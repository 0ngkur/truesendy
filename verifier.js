const { checkSyntax } = require('./lib/syntaxCheck');
const { resolveMailServers } = require('./lib/dnsLookup');
const { checkMailbox } = require('./lib/smtpProbe');
const { buildResult } = require('./lib/classify');

// ── Global SMTP concurrency cap ──────────────────────────────────────────────
// Each SMTP probe holds a socket for up to 7s. Without a process-wide cap, a
// flood of verifications would open thousands of sockets, exhaust the OS port
// range, and trip provider rate limits (Gmail allows ~15-50 concurrent/source).
// Excess callers QUEUE (backpressure) instead of piling on connections.
const SMTP_MAX_CONCURRENCY = 50;
let _smtpActive = 0;
const _smtpQueue = [];
const SMTP_MAX_QUEUE = 200;   // cap waiters — reject (backpressure) instead of unbounded memory growth
function _smtpAcquire() {
    if (_smtpActive < SMTP_MAX_CONCURRENCY) { _smtpActive++; return Promise.resolve(); }
    if (_smtpQueue.length >= SMTP_MAX_QUEUE) return Promise.reject(new Error('smtp_overloaded'));
    return new Promise(resolve => _smtpQueue.push(resolve));
}
function _smtpRelease() {
    _smtpActive = Math.max(0, _smtpActive - 1);
    while (_smtpQueue.length && _smtpActive < SMTP_MAX_CONCURRENCY) {
        _smtpActive++; _smtpQueue.shift()();
    }
}

async function verifyEmail(rawEmail) {
  const syntax = checkSyntax(rawEmail);

  if (!syntax.valid) {
    return {
      email: rawEmail,
      domain: null,
      providerType: null,
      mxProvider: null,
      emailCategory: null,
      status: 'invalid',
      reasonCode: syntax.reason,
      flags: { disposable: false, roleBased: false, catchAll: false },
    };
  }

  const { email, localPart, domain } = syntax;

  // Step 1: DNS resolution (with DoH fallback built in)
  const mxHosts = await resolveMailServers(domain);
  const hadMx = mxHosts.length > 0;

  if (!hadMx) {
    return buildResult({
      email, localPart, domain,
      smtpOutcome: { result: 'rejected' },
      isCatchAllDomain: false,
      hadMx: false,
      mxHosts: [],
    });
  }

  // Step 2: SMTP probe (real connection, no faking) — globally capped.
  await _smtpAcquire();
  try {
    const { smtpResult, isCatchAll } = await checkMailbox(mxHosts, domain, email);
    return buildResult({
      email,
      localPart,
      domain,
      smtpOutcome: smtpResult,
      isCatchAllDomain: isCatchAll,
      hadMx: true,
      mxHosts,
    });
  } finally {
    _smtpRelease();
  }
}

module.exports = { verifyEmail };
