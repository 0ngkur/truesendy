const net = require('net');

/**
 * Probe a single MX host with RCPT TO to check if the mailbox exists.
 * Uses a proper 7-second timeout so real servers have time to respond.
 */
function probeRcptTo(mxHost, mailFromAddress, rcptToAddress, heloDomain, timeoutMs) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: mxHost, port: 25 });
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

    socket.on('error', (err) => {
      finish({ result: 'connection_failed', reason: err.code || 'socket_error' });
    });

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');

      // SMTP responses can be multi-line (code-space for final, code-dash for continuation)
      // We need to wait until we get a final line (code followed by space)
      const lines = buffer.split('\r\n');
      // Check if the last non-empty line is a final response
      let finalLine = null;
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim();
        if (line.length === 0) continue;
        if (/^\d{3} /.test(line)) {
          finalLine = line;
        } else if (/^\d{3}-/.test(line)) {
          // Still a continuation line — wait for more data
          return;
        }
        break;
      }

      if (!finalLine) return;

      const code = parseInt(finalLine.substring(0, 3), 10);
      buffer = '';

      if (stage === 'connect') {
        if (code >= 200 && code < 400) {
          stage = 'helo';
          socket.write(`EHLO ${heloDomain}\r\n`);
        } else {
          finish({ result: 'connection_failed', reason: 'bad_banner', code });
        }
        return;
      }

      if (stage === 'helo') {
        if (code >= 200 && code < 400) {
          stage = 'mailfrom';
          socket.write(`MAIL FROM:<${mailFromAddress}>\r\n`);
        } else {
          finish({ result: 'connection_failed', reason: 'helo_rejected', code });
        }
        return;
      }

      if (stage === 'mailfrom') {
        if (code >= 200 && code < 300) {
          stage = 'rcptto';
          socket.write(`RCPT TO:<${rcptToAddress}>\r\n`);
        } else {
          finish({ result: 'connection_failed', reason: 'mailfrom_rejected', code });
        }
        return;
      }

      if (stage === 'rcptto') {
        socket.write('QUIT\r\n');
        if (code >= 200 && code < 300) {
          finish({ result: 'accepted', code });
        } else if (code >= 400 && code < 500) {
          finish({ result: 'temp_fail', code });
        } else {
          finish({ result: 'rejected', code });
        }
        return;
      }
    });
  });
}

/**
 * Try each MX host in priority order. Return the first real result.
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
 * Full mailbox check: probe the real address, then probe a random
 * address to detect catch-all domains.
 */
async function checkMailbox(mxHosts, domain, fullEmail) {
  const heloDomain = 'verify.example.com';
  const mailFrom = 'probe@example.com';
  const timeoutMs = 7000; // 7 seconds — real SMTP servers need time

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
