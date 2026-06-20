const dns = require('dns').promises;

/**
 * Resolves MX records for a domain, sorted by priority.
 * 
 * Strategy:
 *   1. Try native DNS (port 53).
 *   2. If port 53 is blocked (ECONNREFUSED / ETIMEOUT), fall back to
 *      Google DNS-over-HTTPS on port 443 — works through any firewall.
 *   3. If genuinely no MX exists, try A record per RFC 5321 §5.
 *   4. Returns [] only when the domain truly does not exist.
 */
async function resolveMailServers(domain) {
  // --- Attempt 1: Standard DNS ---
  let nativeDnsWorked = false;
  try {
    const records = await dns.resolveMx(domain);
    nativeDnsWorked = true;
    if (records && records.length > 0) {
      records.sort((a, b) => a.priority - b.priority);
      return records.map((r) => r.exchange);
    }
  } catch (err) {
    // ECONNREFUSED / ETIMEOUT = port 53 blocked. Fall through to DoH.
    // ENODATA / ENOTFOUND = domain has no MX. Skip DoH, try A record.
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
      nativeDnsWorked = true; // DNS worked, domain just has no MX
    }
  }

  // --- Attempt 2: DNS-over-HTTPS (only if native DNS was blocked) ---
  if (!nativeDnsWorked) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`, {
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const data = await res.json();
      if (data.Answer && data.Answer.length > 0) {
        const records = data.Answer
          .filter((ans) => ans.type === 15) // MX record type
          .map((ans) => {
            const parts = ans.data.split(' ');
            return {
              priority: parseInt(parts[0], 10),
              exchange: parts[1].replace(/\.$/, ''),
            };
          });
        if (records.length > 0) {
          records.sort((a, b) => a.priority - b.priority);
          return records.map((r) => r.exchange);
        }
      }
      // DoH worked but domain has no MX — fall through to A record check
      if (data.Status === 3) {
        // NXDOMAIN — domain does not exist at all
        return [];
      }
    } catch (dohErr) {
      // DoH also failed — network is completely dead
    }
  }

  // --- Attempt 3: A record fallback (RFC 5321 §5) ---
  // Only try if the domain exists but simply has no MX
  try {
    if (nativeDnsWorked) {
      await dns.resolve4(domain);
      return [domain];
    } else {
      // Try DoH for A record
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(`https://dns.google/resolve?name=${domain}&type=A`, {
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const data = await res.json();
      if (data.Answer && data.Answer.length > 0) {
        return [domain];
      }
    }
  } catch (err) {
    // Domain doesn't exist
  }

  return [];
}

module.exports = { resolveMailServers };
