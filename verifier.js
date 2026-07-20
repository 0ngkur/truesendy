const { checkSyntax } = require('./lib/syntaxCheck');
const { resolveMailServers } = require('./lib/dnsLookup');
const { checkMailbox } = require('./lib/smtpProbe');
const { buildResult } = require('./lib/classify');
const { identifyMxProvider } = require('./data/domainData');

// Use node-fetch (works on Node 14+)
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

// ── Global SMTP concurrency cap ──────────────────────────────────────────────
// Lower concurrency prevents burst-triggering rate limits on enterprise gateways.
// 8 concurrent SMTP connections is the sweet spot: fast enough, not triggering.
const SMTP_MAX_CONCURRENCY = 8;
let _smtpActive = 0;
const _smtpQueue = [];
const SMTP_MAX_QUEUE = 200;
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

// ═══════════════════════════════════════════════════════════════════════════════
//  MICROSOFT 365 API — GetCredentialType
// ═══════════════════════════════════════════════════════════════════════════════
const MSFT_API_URL = 'https://login.microsoftonline.com/common/GetCredentialType';

// ── Concurrent rate limiter for M365 API ─────────────────────────────────────
// Allow up to 3 concurrent API calls with 200ms minimum between each call.
// This gives ~15 calls/sec max burst, ~5/sec sustained — well within limits.
// Previous serial 600ms queue caused 60+ second backlogs for bulk lists.
const MSFT_MAX_CONCURRENT = 3;
const MSFT_MIN_INTERVAL   = 200; // ms minimum between any two calls
let _msftActive   = 0;
let _msftLastCall = 0;
const _msftWaiters = [];

function _msftRelease() {
    _msftActive = Math.max(0, _msftActive - 1);
    if (_msftWaiters.length) {
        const next = _msftWaiters.shift();
        setTimeout(next, 0);
    }
}

function _msftRateAcquire() {
    return new Promise(resolve => {
        function tryAcquire() {
            const now  = Date.now();
            const wait = Math.max(0, MSFT_MIN_INTERVAL - (now - _msftLastCall));
            if (_msftActive < MSFT_MAX_CONCURRENT && wait === 0) {
                _msftActive++;
                _msftLastCall = now;
                resolve();
            } else {
                setTimeout(() => {
                    // Try from queue when slot/time is available
                    const n2   = Date.now();
                    const wait2 = Math.max(0, MSFT_MIN_INTERVAL - (n2 - _msftLastCall));
                    if (_msftActive < MSFT_MAX_CONCURRENT && wait2 === 0) {
                        _msftActive++;
                        _msftLastCall = n2;
                        resolve();
                    } else {
                        _msftWaiters.push(tryAcquire);
                    }
                }, Math.max(50, wait));
            }
        }
        tryAcquire();
    });
}

// Per-domain cache for catch-all status.
const _msftCatchAllCache = new Map();

/**
 * Single M365 API call (no retry). Rate-limited through concurrent semaphore.
 */
async function _checkMicrosoftMailboxOnce(email) {
    if (!_fetch) return { result: 'api_error', reason: 'no_fetch' };

    await _msftRateAcquire();
    try {
        const body = JSON.stringify({
            username: email,
            isOtherIdpSupported: true,
            checkPhones: false,
            isRemoteNGCSupported: false,
            isCookieBannerShown: false,
            isFidoSupported: false,
            originalRequest: '',
            country: 'US',
            forceotclogin: false,
            isExternalFederationDisallowed: false,
            isRemoteConnectSupported: false,
            federationFlags: 0,
            isSignup: false,
            flowToken: '',
        });

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);

        const res = await _fetch(MSFT_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            },
            body,
            signal: controller.signal,
        });
        clearTimeout(timer);

        if (!res.ok) return { result: 'api_error', reason: `http_${res.status}` };

        const data = await res.json();
        const ifExists  = data.IfExistsResult;
        const throttled = data.ThrottleStatus === 1;
        const credentials = data.Credentials || {};

        // ── Check FEDERATION first — always reliable even when throttled ──
        // Federated domains use external IdP; IfExistsResult=0 is meaningless.
        const isFederated = !!(credentials.FederationRedirectUrl || credentials.FederationProvider);
        if (isFederated || ifExists === 6) return { result: 'federated' };

        // ── Check IfExistsResult — trust it even when throttled ──
        // Data shows IfExistsResult is generally accurate even with ThrottleStatus=1.
        // Treating it as unreliable causes too many false "unknown" results.
        if (ifExists === 0 || ifExists === 5) return { result: 'exists' };
        if (ifExists === 1) return { result: 'not_found' };

        // Only treat as throttled if IfExistsResult was truly ambiguous
        if (throttled) return { result: 'throttled' };

        return { result: 'unknown', ifExists };
    } catch (e) {
        if (e.name === 'AbortError') return { result: 'api_error', reason: 'timeout' };
        return { result: 'api_error', reason: e.message };
    } finally {
        _msftRelease();
    }
}

/**
 * Check Microsoft mailbox with retry + exponential backoff.
 * Longer backoffs (5s, 10s, 15s) to let throttle clear.
 */
async function checkMicrosoftMailbox(email) {
    const MAX_RETRIES = 3;
    const BACKOFF_MS = [5000, 10000, 15000];

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const result = await _checkMicrosoftMailboxOnce(email);

        if (result.result === 'exists' || result.result === 'not_found' || result.result === 'federated') {
            return result;
        }

        if ((result.result === 'throttled' || result.result === 'api_error') && attempt < MAX_RETRIES) {
            await new Promise(r => setTimeout(r, BACKOFF_MS[attempt] || 15000));
            continue;
        }

        return result;
    }
    return { result: 'api_error', reason: 'max_retries' };
}

/**
 * Check M365 catch-all — hybrid API + SMTP approach.
 * Strategy 1: API probe (fast, detects Azure AD catch-all)
 * Strategy 2: SMTP probe fallback (detects Exchange transport-rule catch-all)
 * Result is cached per domain.
 */
async function isMsftDomainCatchAll(domain, mxHosts) {
    if (_msftCatchAllCache.has(domain)) return _msftCatchAllCache.get(domain);

    // Strategy 1: API probe
    const fakeEmail = `nonexistent-probe-${Math.random().toString(36).slice(2, 10)}@${domain}`;
    const fakeCheck = await checkMicrosoftMailbox(fakeEmail);

    if (fakeCheck.result === 'exists') {
        _msftCatchAllCache.set(domain, true);
        return true;
    }

    // Strategy 2: SMTP probe for transport-rule catch-all
    if (mxHosts && mxHosts.length > 0) {
        try {
            await _smtpAcquire();
            try {
                const { smtpResult } = await checkMailbox(mxHosts, domain, fakeEmail);
                if (smtpResult && smtpResult.result === 'accepted') {
                    _msftCatchAllCache.set(domain, true);
                    return true;
                }
            } finally {
                _smtpRelease();
            }
        } catch (e) { /* SMTP failed — not catch-all */ }
    }

    _msftCatchAllCache.set(domain, false);
    if (_msftCatchAllCache.size > 5000) {
        const firstKey = _msftCatchAllCache.keys().next().value;
        _msftCatchAllCache.delete(firstKey);
    }
    return false;
}

// ── Providers whose SMTP acceptance is UNRELIABLE ────────────────────────────
// These are security GATEWAYS that sit in front of the real mail server.
// They accept ALL inbound SMTP (even fakes), then filter internally.
// For these, a single SMTP 250 does NOT prove the mailbox exists.
// However, if catch-all IS detected via fake probe, classify as catch_all.
// If SMTP explicitly rejects (5xx mailbox_not_found), that IS reliable.
const SMTP_UNRELIABLE_PROVIDERS = new Set([
    'Mimecast',    // Mimecast gateway accepts all, filters internally
    'Barracuda',   // Barracuda ESG accepts all at SMTP level
    'Proofpoint',  // Proofpoint gateway — RCPT TO is unreliable
    'MessageLabs', // Broadcom/Symantec gateway — same behavior
    'SpamExperts', // SpamExperts relay — accepts all
]);


// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN VERIFICATION PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════
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

    // Step 1: DNS resolution
    const mxHosts = await resolveMailServers(domain);
    const hadMx = mxHosts.length > 0;

    if (!hadMx) {
        return buildResult({
            email, localPart, domain,
            smtpOutcome: { result: 'rejected', rejectionType: 'mailbox_not_found' },
            isCatchAllDomain: false,
            hadMx: false,
            mxHosts: [],
        });
    }

    const mxProvider = identifyMxProvider(mxHosts);
    const isM365 = mxProvider === 'Microsoft 365';

    // ────────────────────────────────────────────────────────────────────────
    // FAST PATH: Microsoft 365 domains → API is authoritative
    // ────────────────────────────────────────────────────────────────────────
    if (isM365) {
        const msftCheck = await checkMicrosoftMailbox(email);

        if (msftCheck.result === 'exists') {
            // User EXISTS in Azure AD → safe
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'accepted', code: 250, responseText: 'msft_api_exists' },
                isCatchAllDomain: false,
                hadMx: true,
                mxHosts,
            });
        }

        if (msftCheck.result === 'not_found') {
            const catchAll = await isMsftDomainCatchAll(domain, mxHosts);
            if (catchAll) {
                return buildResult({
                    email, localPart, domain,
                    smtpOutcome: { result: 'accepted', code: 250, responseText: 'msft_catchall' },
                    isCatchAllDomain: true,
                    hadMx: true,
                    mxHosts,
                });
            }
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'rejected', code: 550, responseText: 'msft_api_not_found', rejectionType: 'mailbox_not_found' },
                isCatchAllDomain: false,
                hadMx: true,
                mxHosts,
            });
        }

        if (msftCheck.result === 'federated') {
            // Fall through to SMTP
        } else {
            // API failed after all retries → unknown
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'connection_failed' },
                isCatchAllDomain: false,
                hadMx: true,
                mxHosts,
            });
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // STANDARD PATH: SMTP probe for non-M365 providers
    // ────────────────────────────────────────────────────────────────────────
    await _smtpAcquire();
    let smtpResult, isCatchAll;
    try {
        ({ smtpResult, isCatchAll } = await checkMailbox(mxHosts, domain, email));
    } finally {
        _smtpRelease();
    }

    // ── SMTP-unreliable providers (Mimecast etc.) ───────────────────────────
    if (SMTP_UNRELIABLE_PROVIDERS.has(mxProvider)) {
        if (smtpResult && smtpResult.result === 'accepted') {
            if (isCatchAll) {
                // Catch-all detected → classify as catch_all
                return buildResult({
                    email, localPart, domain,
                    smtpOutcome: smtpResult,
                    isCatchAllDomain: true,
                    hadMx: true,
                    mxHosts,
                });
            }
            // Not catch-all but accepted → unknown (can't trust)
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'temp_fail' },
                isCatchAllDomain: false,
                hadMx: true,
                mxHosts,
            });
        }
    }

    return buildResult({
        email,
        localPart,
        domain,
        smtpOutcome: smtpResult,
        isCatchAllDomain: isCatchAll,
        hadMx: true,
        mxHosts,
    });
}

module.exports = { verifyEmail };
