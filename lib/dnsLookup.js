const dns = require('dns').promises;

// Use node-fetch for DNS-over-HTTPS fallback (works on Node 14+)
let _fetch;
try {
    if (typeof globalThis.fetch === 'function') {
        _fetch = globalThis.fetch;
    } else {
        _fetch = require('node-fetch');
    }
} catch {
    _fetch = null;
}

// ── MX record cache ──────────────────────────────────────────────────────────
const MX_CACHE_TTL_POS = 30 * 60 * 1000;
const MX_CACHE_TTL_NEG = 5 * 60 * 1000;
const MX_CACHE_MAX = 20000;
const _mxCache = new Map();

function _cacheGet(domain) {
  const entry = _mxCache.get(domain);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    _mxCache.delete(domain);
    return null;
  }
  return entry;
}

function _cacheSet(domain, hosts, isNegative) {
  if (_mxCache.size >= MX_CACHE_MAX) {
    const firstKey = _mxCache.keys().next().value;
    _mxCache.delete(firstKey);
  }
  _mxCache.set(domain, {
    hosts,
    expiresAt: Date.now() + (isNegative ? MX_CACHE_TTL_NEG : MX_CACHE_TTL_POS),
    neg: !!isNegative,
  });
}

/**
 * Resolves MX records for a domain, sorted by priority.
 */
async function resolveMailServers(domain) {
  const cached = _cacheGet(domain);
  if (cached) return cached.hosts;

  const hosts = await _resolveMailServersUncached(domain);
  _cacheSet(domain, hosts, hosts.length === 0);
  return hosts;
}

async function _resolveMailServersUncached(domain) {
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
    if (err.code === 'ENODATA' || err.code === 'ENOTFOUND') {
      nativeDnsWorked = true;
    }
  }

  // --- Attempt 2: DNS-over-HTTPS (only if native DNS was blocked) ---
  if (!nativeDnsWorked && _fetch) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await _fetch(`https://dns.google/resolve?name=${domain}&type=MX`, {
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const data = await res.json();
      if (data.Answer && data.Answer.length > 0) {
        const records = data.Answer
          .filter((ans) => ans.type === 15)
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
      if (data.Status === 3) {
        return [];
      }
    } catch (dohErr) {
      // DoH also failed
    }
  }

  // --- Attempt 3: A record fallback (RFC 5321 §5) ---
  try {
    if (nativeDnsWorked) {
      await dns.resolve4(domain);
      return [domain];
    } else if (_fetch) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await _fetch(`https://dns.google/resolve?name=${domain}&type=A`, {
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
