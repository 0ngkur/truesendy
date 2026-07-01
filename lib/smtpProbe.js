const net = require('net');
const dns = require('dns');
const { promisify } = require('util');
const dnsLookup = promisify(dns.lookup);

// True if an IP literal is private/loopback/link-local/cloud-metadata.
// SSRF defense: an attacker's MX record can point a normal-looking hostname at
// an internal IP, so we must check the RESOLVED address, not just the hostname.
function isPrivateIp(ip) {
    if (!ip || typeof ip !== 'string') return true;
    const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);   // IPv6-mapped IPv4
    const v = m ? m[1] : ip;
    if (v === '::1' || v.startsWith('fd') || v.startsWith('fc') || v.startsWith('fe80:')) return true; // v6 loopback/ULA/link-local
    if (v === '127.0.0.1' || v === '0.0.0.0' || v.startsWith('10.') || v.startsWith('192.168.') || v.startsWith('169.254.')) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(v)) return true;
    return false;
}

/**
 * Parse enhanced SMTP status code from response text.
 * e.g. "550 5.1.1 The email account does not exist" → { class: 5, subject: 1, detail: 1 }
 * e.g. "550 5.7.1 Policy rejection" → { class: 5, subject: 7, detail: 1 }
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
 * Analyze the SMTP rejection to determine if it's a real "mailbox doesn't exist"
 * or just anti-spam / policy rejection.
 *
 * Returns: 'mailbox_not_found' | 'policy_rejection' | 'unknown_rejection'
 */
function classifyRejection(code, responseText) {
  const lower = (responseText || '').toLowerCase();
  const enhanced = parseEnhancedCode(responseText || '');

  // ── TIER 1: Enhanced status codes (RFC 3463) — checked FIRST for precision ──

  // 5.1.1 = mailbox does not exist
  if (enhanced && enhanced.subject === 1 && enhanced.detail === 1) {
    return 'mailbox_not_found';
  }
  // 5.1.2 = bad destination system address
  if (enhanced && enhanced.subject === 1 && enhanced.detail === 2) {
    return 'mailbox_not_found';
  }

  // 5.2.x = mailbox status
  if (enhanced && enhanced.subject === 2) {
    if (enhanced.detail === 1) return 'mailbox_not_found';  // 5.2.1 = mailbox disabled — CANNOT receive
    if (enhanced.detail === 2) return 'mailbox_full';        // 5.2.2 = mailbox full — EXISTS but full
    return 'policy_rejection';                                // other 5.2.x = policy/admin
  }

  // 5.7.x = security/policy status (anti-spam, DMARC, SPF, RBL, etc.)
  if (enhanced && enhanced.subject === 7) {
    return 'policy_rejection';
  }

  // ── TIER 2: Keyword-based detection for servers without enhanced codes ──

  // DEFINITIVE "mailbox doesn't exist" signals
  const notFoundPatterns = [
    'does not exist',
    'doesn\'t exist',
    'user unknown',
    'user not found',
    'unknown user',
    'no such user',
    'no such mailbox',
    'mailbox not found',
    'mailbox unavailable',
    'unknown recipient',
    'invalid recipient',
    'undeliverable',
    'account disabled',
    'account has been disabled',
    'user disabled',
    'mailbox disabled',
    'inbox is disabled',
    'no mailbox here',
    'addressee unknown',
  ];

  for (const pattern of notFoundPatterns) {
    if (lower.includes(pattern)) {
      return 'mailbox_not_found';
    }
  }

  // DEFINITIVE "policy rejection" signals
  const policyPatterns = [
    'recipient rejected',
    'address rejected',
    'invalid address',
    'policy',
    'blocked',
    'blacklisted',
    'spam',
    'not allowed',
    'access denied',
    'relay denied',
    'relay not permitted',
    'try again later',
    'rate limit',
    'too many',
    'temporarily',
    'service unavailable',
    'connection not allowed',
    'sender verify failed',
    'spf',
    'dmarc',
    'dkim',
    'reputation',
    'listed on',
    'rbl',
    'rejected by',
  ];

  for (const pattern of policyPatterns) {
    if (lower.includes(pattern)) {
      return 'policy_rejection';
    }
  }

  // ── TIER 3: Ambiguous fallbacks ──
  if (code === 550) {
    return 'ambiguous_550';
  }
  if (code >= 500 && code < 600) {
    return 'unknown_rejection';
  }

  return 'unknown_rejection';
}

// SSRF guard — block private/internal IPs from being probed
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
 * Probe a single MX host with RCPT TO to check if the mailbox exists.
 */
async function probeRcptTo(mxHost, mailFromAddress, rcptToAddress, heloDomain, timeoutMs) {
    // SSRF: never connect to private/internal hostnames
    if (isSsrfTarget(mxHost)) {
        return { result: 'connection_failed', reason: 'ssrf_blocked' };
    }
    // SSRF: resolve the hostname and block if it points at a private/internal IP.
    // An attacker's MX record can point a normal-looking hostname inward — the
    // hostname check alone is not enough.
    let resolvedIp;
    try {
        const found = await dnsLookup(mxHost, { all: true });
        if (!found || !found.length) return { result: 'connection_failed', reason: 'dns_failed' };
        if (found.some(a => isPrivateIp(a.address))) return { result: 'connection_failed', reason: 'ssrf_blocked' };
        resolvedIp = found[0].address;
    } catch (e) {
        return { result: 'connection_failed', reason: 'dns_failed' };
    }

  return new Promise((resolve) => {
    const socket = net.createConnection({ host: resolvedIp, port: 25 });
    let stage = 'connect';
    let buffer = '';
    let settled = false;

    const finish = (payload) => {
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

    // DNS-rebinding defense: verify the ACTUAL address we connected to.
    socket.on('connect', () => {
        if (!settled && isPrivateIp(socket.remoteAddress)) {
            settled = true;
            clearTimeout(timer);
            try { socket.destroy(); } catch (_) {}
            resolve({ result: 'connection_failed', reason: 'ssrf_blocked' });
        }
    });
    socket.on('error', (err) => {
      finish({ result: 'connection_failed', reason: err.code || 'socket_error' });
    });

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');

      // SMTP responses can be multi-line (code-space for final, code-dash for continuation)
      const lines = buffer.split('\r\n');
      let finalLine = null;
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim();
        if (line.length === 0) continue;
        if (/^\d{3} /.test(line)) {
          finalLine = line;
        } else if (/^\d{3}-/.test(line)) {
          return; // Still a continuation line — wait for more data
        }
        break;
      }

      if (!finalLine) return;

      const code = parseInt(finalLine.substring(0, 3), 10);
      const fullResponse = buffer; // Capture FULL response text before clearing
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
          socket.write(`MAIL FROM:<${mailFromAddress}>\r\n`);
        } else {
          finish({ result: 'connection_failed', reason: 'helo_rejected', code, responseText: fullResponse });
        }
        return;
      }

      if (stage === 'mailfrom') {
        if (code >= 200 && code < 300) {
          stage = 'rcptto';
          socket.write(`RCPT TO:<${rcptToAddress}>\r\n`);
        } else {
          // MAIL FROM rejected — this is ALWAYS a policy rejection, not mailbox-related
          finish({
            result: 'sender_rejected',
            reason: 'mailfrom_rejected',
            code,
            responseText: fullResponse,
            rejectionType: 'policy_rejection',
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
          const rejectionType = classifyRejection(code, fullResponse);
          finish({
            result: 'rejected',
            code,
            responseText: fullResponse,
            rejectionType,
          });
        }
        return;
      }
    });
  });
}

/**
 * Try each MX host in priority order. Return the first real result.
 * Now distinguishes between connection failures and sender rejections.
 */
async function probeAcrossMxHosts(mxHosts, mailFrom, rcptTo, heloDomain, timeoutMs) {
  for (const host of mxHosts) {
    const outcome = await probeRcptTo(host, mailFrom, rcptTo, heloDomain, timeoutMs);
    // Only skip to next host if we couldn't connect at all
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
 * Full mailbox check: probe the real address, then probe a random
 * address to detect catch-all domains.
 */
async function checkMailbox(mxHosts, domain, fullEmail) {
  const heloDomain = 'mail.verifier-check.com';
  const mailFrom = 'check@verifier-check.com';
  const timeoutMs = 7000;

  const realOutcome = await probeAcrossMxHosts(mxHosts, mailFrom, fullEmail, heloDomain, timeoutMs);

  let isCatchAll = false;
  if (realOutcome.result === 'accepted') {
    const fakeAddress = buildRandomProbeAddress(domain);
    const fakeOutcome = await probeAcrossMxHosts(mxHosts, mailFrom, fakeAddress, heloDomain, timeoutMs);
    isCatchAll = fakeOutcome.result === 'accepted';
  }

  return { smtpResult: realOutcome, isCatchAll };
}

module.exports = { checkMailbox };
