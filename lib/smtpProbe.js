const net  = require('net');
const tls  = require('tls');
const dns  = require('dns');
const { promisify } = require('util');
const dnsLookup = promisify(dns.lookup);

// ── SSRF guard helpers ────────────────────────────────────────────────────────
function isPrivateIp(ip) {
    if (!ip || typeof ip !== 'string') return true;
    const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    const v = m ? m[1] : ip;
    if (v === '::1' || v.startsWith('fd') || v.startsWith('fc') || v.startsWith('fe80:')) return true;
    if (v === '127.0.0.1' || v === '0.0.0.0' || v.startsWith('10.') || v.startsWith('192.168.') || v.startsWith('169.254.')) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(v)) return true;
    return false;
}

const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|::1$|fd[0-9a-f]{2}:|169\.254\.)/i;
function isSsrfTarget(host) {
    if (!host || typeof host !== 'string') return true;
    const h = host.trim().toLowerCase();
    return (
        h === 'localhost' ||
        h.endsWith('.internal') ||
        h.endsWith('.local') ||
        h.endsWith('.localhost') ||
        PRIVATE_IP_RE.test(h)
    );
}

/**
 * Parse enhanced SMTP status code from response text.
 * e.g. "550 5.1.1 The email account does not exist" → { class: 5, subject: 1, detail: 1 }
 */
function parseEnhancedCode(responseText) {
    const match = responseText.match(/(\d)\.(\d+)\.(\d+)/);
    if (match) {
        return {
            class: parseInt(match[1], 10),
            subject: parseInt(match[2], 10),
            detail: parseInt(match[3], 10),
            raw: match[0],
        };
    }
    return null;
}

/**
 * Classify an SMTP rejection: returns one of:
 * 'mailbox_not_found' | 'mailbox_disabled' | 'mailbox_full' |
 * 'sender_blocked' | 'policy_rejection' | 'ambiguous_550' | 'unknown_rejection'
 */
function classifyRejection(code, responseText) {
    const lower = (responseText || '').toLowerCase();
    const enhanced = parseEnhancedCode(responseText || '');

    // ── TIER 0: Sender-IP / reputation blocks ─────────────────────────────────
    const senderBlockPatterns = [
        'blocked using spamhaus', 'blocked using barracuda', 'blocked using sorbs',
        'blocked using spamcop', 'blocked using', 'listed by xbl', 'listed by css',
        'listed by pbl', 'listed by sbl', 'listed on', 'client host', 'ip blocked',
        'ip is blocked', 'sender ip', 'bad sender', 'sender blocked',
        'zen.mimecast.org', 'bl.spamcop.net', '.rbl.', '.dnsbl.', 'blacklist',
        'reputation', 'sender verify failed',
    ];
    for (const pattern of senderBlockPatterns) {
        if (lower.includes(pattern)) return 'sender_blocked';
    }

    // ── TIER 1: RFC 3463 enhanced status codes ────────────────────────────────
    if (enhanced) {
        if (enhanced.subject === 1 && enhanced.detail === 1) return 'mailbox_not_found'; // 5.1.1
        if (enhanced.subject === 1 && enhanced.detail === 2) return 'mailbox_not_found'; // 5.1.2
        if (enhanced.subject === 2) {
            if (enhanced.detail === 1) return 'mailbox_disabled'; // 5.2.1 exists but off
            if (enhanced.detail === 2) return 'mailbox_full';     // 5.2.2 exists but full
            return 'policy_rejection';                             // other 5.2.x
        }
        if (enhanced.subject === 7) return 'policy_rejection';    // 5.7.x security/policy
    }

    // ── TIER 2: Keyword detection ─────────────────────────────────────────────
    const disabledPatterns = [
        'account disabled', 'account has been disabled', 'user disabled',
        'mailbox disabled', 'inbox is disabled', 'account is disabled',
        'this mailbox is disabled', 'mailbox is not accepting',
        'account deactivated', 'user account is disabled',
    ];
    for (const pattern of disabledPatterns) {
        if (lower.includes(pattern)) return 'mailbox_disabled';
    }

    const notFoundPatterns = [
        'does not exist', "doesn't exist", 'user unknown', 'user not found',
        'unknown user', 'no such user', 'no such mailbox', 'mailbox not found',
        'mailbox unavailable', 'unknown recipient', 'invalid recipient',
        'undeliverable', 'no mailbox here', 'addressee unknown',
        'recipient not found', 'recipient unknown', 'address rejected',
        'recipient address rejected',
    ];
    for (const pattern of notFoundPatterns) {
        if (lower.includes(pattern)) return 'mailbox_not_found';
    }

    const policyPatterns = [
        'recipient rejected', 'invalid address', 'policy', 'blocked',
        'blacklisted', 'spam', 'not allowed', 'access denied', 'relay denied',
        'relay not permitted', 'try again later', 'rate limit', 'too many',
        'temporarily', 'service unavailable', 'connection not allowed',
        'sender verify failed', 'spf', 'dmarc', 'dkim', 'reputation',
        'listed on', 'rbl', 'rejected by',
    ];
    for (const pattern of policyPatterns) {
        if (lower.includes(pattern)) return 'policy_rejection';
    }

    // ── TIER 3: Fallback by numeric code ─────────────────────────────────────
    if (code === 550) return 'ambiguous_550';
    if (code >= 500 && code < 600) return 'unknown_rejection';

    return 'unknown_rejection';
}

// ── Low-level: resolve + SSRF-check a hostname ────────────────────────────────
async function resolveHost(mxHost) {
    if (isSsrfTarget(mxHost)) return { ok: false, reason: 'ssrf_blocked' };
    try {
        const found = await dnsLookup(mxHost, { all: true });
        if (!found || !found.length) return { ok: false, reason: 'dns_failed' };
        if (found.some(a => isPrivateIp(a.address))) return { ok: false, reason: 'ssrf_blocked' };
        return { ok: true, ip: found[0].address };
    } catch {
        return { ok: false, reason: 'dns_failed' };
    }
}

/**
 * Core SMTP conversation on a raw TCP socket (port 25 or 587 without TLS).
 * Returns the RCPT TO result.
 */
function smtpConversationRaw(ip, port, heloDomain, mailFrom, rcptTo, timeoutMs) {
    return new Promise(resolve => {
        const socket = net.createConnection({ host: ip, port });
        let stage = 'connect';
        let buffer = '';
        let settled = false;

        const finish = payload => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try { socket.end(); } catch (_) {}
            try { socket.destroy(); } catch (_) {}
            resolve(payload);
        };

        const timer = setTimeout(() => {
            finish({ result: 'connection_failed', reason: 'timeout' });
        }, timeoutMs);

        socket.on('connect', () => {
            if (!settled && isPrivateIp(socket.remoteAddress)) {
                settled = true;
                clearTimeout(timer);
                try { socket.destroy(); } catch (_) {}
                resolve({ result: 'connection_failed', reason: 'ssrf_blocked' });
            }
        });
        socket.on('error', err => {
            finish({ result: 'connection_failed', reason: err.code || 'socket_error' });
        });

        socket.on('data', chunk => {
            buffer += chunk.toString('utf8');
            const lines = buffer.split('\r\n');
            let finalLine = null;
            for (let i = lines.length - 1; i >= 0; i--) {
                const line = lines[i].trim();
                if (!line.length) continue;
                if (/^\d{3} /.test(line)) { finalLine = line; break; }
                if (/^\d{3}-/.test(line)) return; // continuation — wait
                break;
            }
            if (!finalLine) return;

            const code = parseInt(finalLine.substring(0, 3), 10);
            const fullResponse = buffer;
            buffer = '';

            if (stage === 'connect') {
                if (code >= 200 && code < 400) {
                    stage = 'helo';
                    socket.write(`EHLO ${heloDomain}\r\n`);
                } else {
                    finish({ result: 'connection_failed', reason: 'bad_banner', code, responseText: fullResponse });
                }
                return;
            }

            if (stage === 'helo') {
                if (code >= 200 && code < 400) {
                    stage = 'mailfrom';
                    socket.write(`MAIL FROM:<${mailFrom}>\r\n`);
                } else {
                    finish({ result: 'connection_failed', reason: 'helo_rejected', code, responseText: fullResponse });
                }
                return;
            }

            if (stage === 'mailfrom') {
                if (code >= 200 && code < 300) {
                    stage = 'rcptto';
                    socket.write(`RCPT TO:<${rcptTo}>\r\n`);
                } else {
                    finish({
                        result: 'sender_rejected',
                        reason: 'mailfrom_rejected',
                        code,
                        responseText: fullResponse,
                        rejectionType: classifyRejection(code, fullResponse),
                    });
                }
                return;
            }

            if (stage === 'rcptto') {
                socket.write('QUIT\r\n');
                if (code >= 200 && code < 300) {
                    finish({ result: 'accepted', code, responseText: fullResponse });
                } else if (code >= 400 && code < 500) {
                    finish({
                        result: 'temp_fail',
                        code,
                        responseText: fullResponse,
                        rejectionType: classifyRejection(code, fullResponse),
                    });
                } else {
                    finish({
                        result: 'rejected',
                        code,
                        responseText: fullResponse,
                        rejectionType: classifyRejection(code, fullResponse),
                    });
                }
                return;
            }
        });
    });
}

/**
 * Probe a single MX host — tries port 25 first, then 587, then 465.
 * Returns the first non-connection-failed result, or connection_failed
 * if all ports are unreachable.
 */
async function probeRcptTo(mxHost, mailFromAddress, rcptToAddress, heloDomain, timeoutMs) {
    const resolved = await resolveHost(mxHost);
    if (!resolved.ok) return { result: 'connection_failed', reason: resolved.reason };

    const ip = resolved.ip;
    const ports = [25, 587, 465];

    for (const port of ports) {
        let outcome;
        if (port === 465) {
            // Port 465 uses implicit TLS — attempt a TLS connect, send EHLO/MAIL/RCPT
            outcome = await smtpConversationTls(ip, port, heloDomain, mailFromAddress, rcptToAddress, timeoutMs);
        } else {
            outcome = await smtpConversationRaw(ip, port, heloDomain, mailFromAddress, rcptToAddress, timeoutMs);
        }
        if (outcome.result !== 'connection_failed') {
            return { ...outcome, port };
        }
    }

    return { result: 'connection_failed', reason: 'all_ports_unreachable' };
}

/**
 * SMTP conversation over implicit TLS (port 465).
 */
function smtpConversationTls(ip, port, heloDomain, mailFrom, rcptTo, timeoutMs) {
    return new Promise(resolve => {
        let socket;
        try {
            socket = tls.connect({ host: ip, port, rejectUnauthorized: false });
        } catch {
            return resolve({ result: 'connection_failed', reason: 'tls_connect_error' });
        }

        let stage = 'connect';
        let buffer = '';
        let settled = false;

        const finish = payload => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try { socket.end(); } catch (_) {}
            try { socket.destroy(); } catch (_) {}
            resolve(payload);
        };

        const timer = setTimeout(() => {
            finish({ result: 'connection_failed', reason: 'timeout' });
        }, timeoutMs);

        socket.on('error', err => {
            finish({ result: 'connection_failed', reason: err.code || 'tls_error' });
        });

        socket.on('data', chunk => {
            buffer += chunk.toString('utf8');
            const lines = buffer.split('\r\n');
            let finalLine = null;
            for (let i = lines.length - 1; i >= 0; i--) {
                const line = lines[i].trim();
                if (!line.length) continue;
                if (/^\d{3} /.test(line)) { finalLine = line; break; }
                if (/^\d{3}-/.test(line)) return;
                break;
            }
            if (!finalLine) return;

            const code = parseInt(finalLine.substring(0, 3), 10);
            const fullResponse = buffer;
            buffer = '';

            if (stage === 'connect') {
                if (code >= 200 && code < 400) {
                    stage = 'helo';
                    socket.write(`EHLO ${heloDomain}\r\n`);
                } else {
                    finish({ result: 'connection_failed', reason: 'bad_banner', code, responseText: fullResponse });
                }
                return;
            }
            if (stage === 'helo') {
                if (code >= 200 && code < 400) {
                    stage = 'mailfrom';
                    socket.write(`MAIL FROM:<${mailFrom}>\r\n`);
                } else {
                    finish({ result: 'connection_failed', reason: 'helo_rejected', code, responseText: fullResponse });
                }
                return;
            }
            if (stage === 'mailfrom') {
                if (code >= 200 && code < 300) {
                    stage = 'rcptto';
                    socket.write(`RCPT TO:<${rcptTo}>\r\n`);
                } else {
                    finish({
                        result: 'sender_rejected',
                        reason: 'mailfrom_rejected',
                        code,
                        responseText: fullResponse,
                        rejectionType: classifyRejection(code, fullResponse),
                    });
                }
                return;
            }
            if (stage === 'rcptto') {
                socket.write('QUIT\r\n');
                if (code >= 200 && code < 300) {
                    finish({ result: 'accepted', code, responseText: fullResponse });
                } else if (code >= 400 && code < 500) {
                    finish({ result: 'temp_fail', code, responseText: fullResponse, rejectionType: classifyRejection(code, fullResponse) });
                } else {
                    finish({ result: 'rejected', code, responseText: fullResponse, rejectionType: classifyRejection(code, fullResponse) });
                }
                return;
            }
        });
    });
}

/**
 * Try each MX host in priority order. Return the first real (non-connection-failed) result.
 */
async function probeAcrossMxHosts(mxHosts, mailFrom, rcptTo, heloDomain, timeoutMs) {
    for (const host of mxHosts) {
        const outcome = await probeRcptTo(host, mailFrom, rcptTo, heloDomain, timeoutMs);
        if (outcome.result !== 'connection_failed') {
            return outcome;
        }
    }
    return { result: 'connection_failed', reason: 'all_mx_hosts_unreachable' };
}

function buildRandomProbeAddress(domain) {
    const rand = Math.random().toString(36).slice(2, 14);
    return `nonexistent-probe-${rand}@${domain}`;
}

/**
 * Full mailbox check:
 * 1. Probe the real address using NULL sender (MAIL FROM:<>) — the RFC-compliant
 *    approach used by NeverBounce, ZeroBounce, and Reon. The null/empty sender has
 *    no domain reputation, so Microsoft 365 and other anti-spam providers cannot
 *    reject us at the MAIL FROM stage based on sender IP blacklists.
 * 2. If null sender is also rejected at MAIL FROM, retry with a fallback domain address.
 * 3. If accepted, probe a random address to detect catch-all domains.
 * 4. If blocked (connection_failed/sender_rejected), probe a fake address to infer catch-all.
 */
async function checkMailbox(mxHosts, domain, fullEmail) {
    const heloDomain  = 'verify.truesendy.com';
    const timeoutMs   = 7000;

    // Strategy 1: RFC-standard null sender — avoids all sender-reputation blocks
    // Per RFC 5321, MAIL FROM:<> is used for DSN/bounce messages and is a valid
    // probe sender that cannot be blocked by sender reputation systems.
    const nullSender  = '';
    let realOutcome   = await probeAcrossMxHosts(mxHosts, nullSender, fullEmail, heloDomain, timeoutMs);

    // Strategy 2: If null sender failed at MAIL FROM (some servers require a valid sender),
    // fall back to a domain address. This helps with strict servers that reject empty sender.
    if (realOutcome.result === 'sender_rejected') {
        const domainSender = 'verify@truesendy.com';
        realOutcome = await probeAcrossMxHosts(mxHosts, domainSender, fullEmail, heloDomain, timeoutMs);
    }

    let isCatchAll = false;

    if (realOutcome.result === 'accepted') {
        // Standard catch-all detection: if a fake address is also accepted → catch-all
        const fakeAddress = buildRandomProbeAddress(domain);
        const fakeOutcome = await probeAcrossMxHosts(mxHosts, nullSender, fakeAddress, heloDomain, timeoutMs);
        isCatchAll = fakeOutcome.result === 'accepted';

    } else if (realOutcome.result === 'rejected') {
        // Real address was rejected — check catch-all by probing a fake.
        // If the fake is accepted, the real rejection was something else (e.g. policy),
        // and the domain is actually catch-all.
        if (realOutcome.rejectionType !== 'mailbox_not_found' &&
            realOutcome.rejectionType !== 'mailbox_disabled') {
            const fakeAddress = buildRandomProbeAddress(domain);
            const fakeOutcome = await probeAcrossMxHosts(mxHosts, nullSender, fakeAddress, heloDomain, timeoutMs);
            isCatchAll = fakeOutcome.result === 'accepted';
        }

    } else if (realOutcome.result === 'connection_failed' || realOutcome.result === 'sender_rejected') {
        // All ports + both sender strategies blocked. Try catch-all probe as last resort.
        const fake1 = buildRandomProbeAddress(domain);
        const fake1Outcome = await probeAcrossMxHosts(mxHosts, nullSender, fake1, heloDomain, timeoutMs);
        if (fake1Outcome.result === 'accepted') {
            isCatchAll = true;
            return { smtpResult: { result: 'accepted', code: 250, responseText: 'catch-all inferred' }, isCatchAll: true };
        }
    }

    return { smtpResult: realOutcome, isCatchAll };
}

module.exports = { checkMailbox };
