const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const dnsLookup = promisify(dns.lookup);

// Load SMTP config
let SMTP_CONFIG = {};
try {
    SMTP_CONFIG = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config', 'smtp.json'), 'utf8'));
} catch (_) {
    SMTP_CONFIG = { heloDomain: 'truesendy.com', mailFrom: 'verify@truesendy.com', catchAllProbes: 3 };
}

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
 * Classify an SMTP rejection.
 */
function classifyRejection(code, responseText) {
    const lower = (responseText || '').toLowerCase();
    const enhanced = parseEnhancedCode(responseText || '');

    // TIER 0: Sender-IP / reputation blocks
    const senderBlockPatterns = [
        'blocked using spamhaus', 'blocked using barracuda', 'blocked using sorbs',
        'blocked using spamcop', 'blocked using', 'listed by xbl', 'listed by css',
        'listed by pbl', 'listed by sbl', 'listed on', 'client host', 'ip blocked',
        'ip is blocked', 'sender ip', 'bad sender', 'sender blocked',
        'zen.mimecast.org', 'bl.spamcop.net', '.rbl.', '.dnsbl.', 'blacklist',
        'reputation', 'sender verify failed',
    ];
    for (const p of senderBlockPatterns) { if (lower.includes(p)) return 'sender_blocked'; }

    // TIER 1: RFC 3463 enhanced status codes
    if (enhanced) {
        if (enhanced.subject === 1 && enhanced.detail === 1) return 'mailbox_not_found';
        if (enhanced.subject === 1 && enhanced.detail === 2) return 'mailbox_not_found';
        if (enhanced.subject === 2) {
            if (enhanced.detail === 1) return 'mailbox_disabled';
            if (enhanced.detail === 2) return 'mailbox_full';
            return 'policy_rejection';
        }
        if (enhanced.subject === 7) return 'policy_rejection';
    }

    // TIER 2: Keyword detection
    const disabledPatterns = [
        'account disabled', 'account has been disabled', 'user disabled',
        'mailbox disabled', 'inbox is disabled', 'account is disabled',
        'this mailbox is disabled', 'mailbox is not accepting',
        'account deactivated', 'user account is disabled',
    ];
    for (const p of disabledPatterns) { if (lower.includes(p)) return 'mailbox_disabled'; }

    const notFoundPatterns = [
        'does not exist', "doesn't exist", 'user unknown', 'user not found',
        'unknown user', 'no such user', 'no such mailbox', 'mailbox not found',
        'mailbox unavailable', 'unknown recipient', 'invalid recipient',
        'undeliverable', 'no mailbox here', 'addressee unknown',
        'recipient not found', 'recipient unknown', 'address rejected',
        'recipient address rejected',
    ];
    for (const p of notFoundPatterns) { if (lower.includes(p)) return 'mailbox_not_found'; }

    const policyPatterns = [
        'recipient rejected', 'invalid address', 'policy', 'blocked',
        'blacklisted', 'spam', 'not allowed', 'access denied', 'relay denied',
        'relay not permitted', 'try again later', 'rate limit', 'too many',
        'temporarily', 'service unavailable', 'connection not allowed',
        'sender verify failed', 'spf', 'dmarc', 'dkim',
        'listed on', 'rbl', 'rejected by',
    ];
    for (const p of policyPatterns) { if (lower.includes(p)) return 'policy_rejection'; }

    if (code === 550) return 'ambiguous_550';
    if (code >= 500 && code < 600) return 'unknown_rejection';
    return 'unknown_rejection';
}

// ── DNS resolution + SSRF check ───────────────────────────────────────────────
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
 * SMTP conversation on port 25 — the only port that reliably works for
 * unauthenticated RCPT TO probes. Ports 587/465 require AUTH and almost
 * never return useful RCPT TO results from cloud VPS IPs.
 *
 * Uses NULL sender (MAIL FROM:<>) per RFC 5321 — this bypasses sender
 * reputation blocks since there's no domain to blacklist.
 */
function smtpConversation(ip, heloDomain, mailFrom, rcptTo, timeoutMs) {
    return new Promise(resolve => {
        const socket = net.createConnection({ host: ip, port: 25 });
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
                settled = true; clearTimeout(timer);
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
                        result: 'sender_rejected', reason: 'mailfrom_rejected',
                        code, responseText: fullResponse,
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
 * Probe a single MX host on port 25.
 */
async function probeRcptTo(mxHost, mailFrom, rcptTo, heloDomain, timeoutMs) {
    const resolved = await resolveHost(mxHost);
    if (!resolved.ok) return { result: 'connection_failed', reason: resolved.reason };
    return smtpConversation(resolved.ip, heloDomain, mailFrom, rcptTo, timeoutMs);
}

/**
 * Try each MX host. Return first real result.
 */
async function probeAcrossMxHosts(mxHosts, mailFrom, rcptTo, heloDomain, timeoutMs) {
    for (const host of mxHosts) {
        const outcome = await probeRcptTo(host, mailFrom, rcptTo, heloDomain, timeoutMs);
        if (outcome.result !== 'connection_failed') return outcome;
    }
    return { result: 'connection_failed', reason: 'all_mx_hosts_unreachable' };
}

function buildRandomProbeAddress(domain) {
    return `nonexistent-probe-${Math.random().toString(36).slice(2, 14)}@${domain}`;
}

/**
 * Probe a random fake address to detect catch-all behaviour.
 *
 * `prober` (default probeAcrossMxHosts) and `sleep` (default real setTimeout)
 * are injectable so the catch-all resilience policy can be unit-tested without
 * live SMTP connections.
 */
async function probeCatchAll(mxHosts, domain, heloDomain, timeoutMs, prober) {
    const fakeAddr = buildRandomProbeAddress(domain);

    // Attempt 1: null sender (RFC-standard, bypasses reputation blocks)
    let outcome = await prober(mxHosts, '', fakeAddr, heloDomain, timeoutMs);

    // Sender fallback: null sender rejected → retry with domain sender (mirrors real probe)
    if (outcome.result === 'sender_rejected') {
        outcome = await prober(mxHosts, 'verify@truesendy.com', fakeAddr, heloDomain, timeoutMs);
    }

    // NOTE: no greylist retry on the catch-all probe (speed-first). The accuracy
    // gains vs Reoon came from accept-all classification (SMTP_ACCEPT_ALL), not
    // this retry, and the 5s wait per greylisting domain was a major speed cost.
    // Catch-all detection for non-accept-all servers stays correct for the common
    // (non-greylisting) case.
    return outcome;
}

/**
 * Full mailbox check via SMTP:
 * 1. Probe real address with null sender (MAIL FROM:<>)
 * 2. If null sender rejected at MAIL FROM, retry with domain sender
 * 3. If accepted, probe a fake address to detect catch-all
 *
 * `opts.prober` (default probeAcrossMxHosts) and `opts.sleep` (default real
 * setTimeout) are injectable so the catch-all resilience can be unit-tested
 * without real SMTP connections.
 */
async function checkMailbox(mxHosts, domain, fullEmail, opts = {}) {
    const cfg = SMTP_CONFIG;
    const heloDomain = cfg.heloDomain || 'truesendy.com';
    const mailFromAddr = cfg.mailFrom || 'verify@truesendy.com';
    const timeoutMs  = opts.shortTimeout ? 3000 : (cfg.timeoutMs || 8000);
    const catchAllTimeout = opts.shortTimeout ? 2000 : (cfg.catchAllTimeoutMs || 5000);
    const catchAllProbes = cfg.catchAllProbes || 3;
    const prober = opts.prober || probeAcrossMxHosts;
    const sleep  = opts.sleep  || (ms => new Promise(r => setTimeout(r, ms)));

    // Strategy 1: Real MAIL FROM (domain sender with SPF alignment)
    let realOutcome = await prober(mxHosts, mailFromAddr, fullEmail, heloDomain, timeoutMs);

    // Strategy 2: Fall back to null sender if domain sender rejected
    if (realOutcome.result === 'sender_rejected') {
        realOutcome = await prober(mxHosts, '', fullEmail, heloDomain, timeoutMs);
    }

    // Strategy 3: Greylisting retry — wait and retry once inline
    // (Full persistent greylist queue handled by greylistQueue.js in verifier.js)
    if (realOutcome.result === 'temp_fail') {
        await sleep(5000);
        const retryOutcome = await prober(mxHosts, '', fullEmail, heloDomain, timeoutMs);
        if (retryOutcome.result === 'accepted' || retryOutcome.result === 'rejected') {
            realOutcome = retryOutcome;
        }
    }

    if (opts.skipCatchAll) {
        return { smtpResult: realOutcome, isCatchAll: false };
    }

    let isCatchAll = false;

    if (realOutcome.result === 'accepted') {
        isCatchAll = await multiProbeCatchAll(mxHosts, domain, heloDomain, catchAllTimeout, prober, catchAllProbes);
    } else if (realOutcome.result === 'rejected') {
        if (realOutcome.rejectionType !== 'mailbox_not_found' &&
            realOutcome.rejectionType !== 'mailbox_disabled') {
            isCatchAll = await multiProbeCatchAll(mxHosts, domain, heloDomain, catchAllTimeout, prober, catchAllProbes);
        }
    } else if (realOutcome.result === 'sender_rejected' || realOutcome.result === 'temp_fail') {
        const fakeOutcome = await multiProbeCatchAll(mxHosts, domain, heloDomain, catchAllTimeout, prober, catchAllProbes);
        if (fakeOutcome) {
            isCatchAll = true;
            return { smtpResult: { result: 'accepted', code: 250, responseText: 'catch-all inferred' }, isCatchAll: true };
        }
    }

    return { smtpResult: realOutcome, isCatchAll };
}

/**
 * Multi-probe catch-all detection — test N random addresses.
 * If ALL are accepted, the domain is catch-all.
 * Returns boolean (true = catch-all confirmed).
 */
async function multiProbeCatchAll(mxHosts, domain, heloDomain, timeoutMs, prober, numProbes) {
    const cfg = SMTP_CONFIG;
    const mailFromAddr = cfg.mailFrom || 'verify@truesendy.com';
    for (let i = 0; i < numProbes; i++) {
        const fakeAddr = buildRandomProbeAddress(domain);
        let outcome = await prober(mxHosts, '', fakeAddr, heloDomain, timeoutMs);
        if (outcome.result === 'sender_rejected') {
            outcome = await prober(mxHosts, mailFromAddr, fakeAddr, heloDomain, timeoutMs);
        }
        if (outcome.result !== 'accepted') {
            return false; // At least one random address was NOT accepted → not catch-all
        }
    }
    return true; // All random addresses accepted → catch-all confirmed
}

module.exports = { checkMailbox };
