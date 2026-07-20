const { checkSyntax } = require('./lib/syntaxCheck');
const { resolveMailServers } = require('./lib/dnsLookup');
const { checkMailbox } = require('./lib/smtpProbe');
const { buildResult } = require('./lib/classify');
const { identifyMxProvider } = require('./data/domainData');

// Use node-fetch (works on Node 14+, already in package.json)
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
const SMTP_MAX_CONCURRENCY = 20;
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

// ── Rate limiter: max 3 requests/second (token bucket) ──────────────────────
// Microsoft throttles based on requests-per-second, not concurrent connections.
// A token bucket smooths out burst requests that cause throttling.
const MSFT_RATE_LIMIT = 3;        // max requests per second
let _msftTokens = MSFT_RATE_LIMIT;
let _msftLastRefill = Date.now();
const _msftRateQueue = [];

function _refillTokens() {
    const now = Date.now();
    const elapsed = now - _msftLastRefill;
    if (elapsed >= 1000) {
        const refill = Math.floor(elapsed / 1000) * MSFT_RATE_LIMIT;
        _msftTokens = Math.min(MSFT_RATE_LIMIT, _msftTokens + refill);
        _msftLastRefill = now;
    }
}

function _msftRateAcquire() {
    _refillTokens();
    if (_msftTokens > 0) {
        _msftTokens--;
        return Promise.resolve();
    }
    return new Promise(resolve => {
        _msftRateQueue.push(resolve);
    });
}

// Drain the rate queue every 333ms (1000/3 = one token every 333ms)
setInterval(() => {
    _refillTokens();
    while (_msftRateQueue.length > 0 && _msftTokens > 0) {
        _msftTokens--;
        _msftRateQueue.shift()();
    }
}, 333).unref();

// Per-domain cache for catch-all status detected via Microsoft API.
const _msftCatchAllCache = new Map();

/**
 * Single M365 API call (no retry).
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

        if (throttled) return { result: 'throttled' };

        if (ifExists === 0) return { result: 'exists' };
        if (ifExists === 5) return { result: 'exists' };
        if (ifExists === 1) return { result: 'not_found' };
        if (ifExists === 6) return { result: 'federated' };

        return { result: 'unknown', ifExists };
    } catch (e) {
        if (e.name === 'AbortError') return { result: 'api_error', reason: 'timeout' };
        return { result: 'api_error', reason: e.message };
    }
}

/**
 * Check Microsoft mailbox with aggressive retry + exponential backoff.
 * 5 retries with 2s, 4s, 6s, 8s, 10s delays — M365 API is the ONLY reliable
 * source for M365 domains. SMTP gives unreliable results for these domains.
 */
async function checkMicrosoftMailbox(email) {
    const MAX_RETRIES = 5;
    const BACKOFF_MS = [2000, 4000, 6000, 8000, 10000];

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const result = await _checkMicrosoftMailboxOnce(email);

        // Definitive answer — return immediately
        if (result.result === 'exists' || result.result === 'not_found' || result.result === 'federated') {
            return result;
        }

        // Throttled or transient error — retry with backoff
        if ((result.result === 'throttled' || result.result === 'api_error') && attempt < MAX_RETRIES) {
            await new Promise(r => setTimeout(r, BACKOFF_MS[attempt] || 10000));
            continue;
        }

        // Final attempt failed
        return result;
    }
    return { result: 'api_error', reason: 'max_retries' };
}

/**
 * Check M365 catch-all status for a domain (cached).
 * Probes a random fake address — if the API says "exists", it's catch-all.
 */
async function isMsftDomainCatchAll(domain) {
    if (_msftCatchAllCache.has(domain)) return _msftCatchAllCache.get(domain);

    const fakeEmail = `nonexistent-probe-${Math.random().toString(36).slice(2, 10)}@${domain}`;
    const fakeCheck = await checkMicrosoftMailbox(fakeEmail);
    const isCatchAll = fakeCheck.result === 'exists';
    _msftCatchAllCache.set(domain, isCatchAll);

    if (_msftCatchAllCache.size > 5000) {
        const firstKey = _msftCatchAllCache.keys().next().value;
        _msftCatchAllCache.delete(firstKey);
    }

    return isCatchAll;
}


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

    // Step 1: DNS resolution (with DoH fallback built in)
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

    // Identify the mail provider from MX records
    const mxProvider = identifyMxProvider(mxHosts);
    const isM365 = mxProvider === 'Microsoft 365';

    // ────────────────────────────────────────────────────────────────────────
    // FAST PATH: Microsoft 365 domains → use API EXCLUSIVELY
    // ────────────────────────────────────────────────────────────────────────
    // CRITICAL: M365 blocks SMTP probes from most IPs, making SMTP results
    // unreliable. The GetCredentialType API is the ONLY reliable source.
    // We NEVER fall through to SMTP for M365 — if the API fails after all
    // retries, we classify based on what we know (anti-probe unknown).
    if (isM365) {
        const msftCheck = await checkMicrosoftMailbox(email);

        if (msftCheck.result === 'exists') {
            const catchAll = await isMsftDomainCatchAll(domain);
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'accepted', code: 250, responseText: 'msft_api_exists' },
                isCatchAllDomain: catchAll,
                hadMx: true,
                mxHosts,
            });
        }

        if (msftCheck.result === 'not_found') {
            const catchAll = await isMsftDomainCatchAll(domain);
            if (catchAll) {
                return buildResult({
                    email, localPart, domain,
                    smtpOutcome: { result: 'accepted', code: 250, responseText: 'msft_catchall_inferred' },
                    isCatchAllDomain: true,
                    hadMx: true,
                    mxHosts,
                });
            }
            // Not catch-all — mailbox genuinely does not exist
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'rejected', code: 550, responseText: 'msft_api_not_found', rejectionType: 'mailbox_not_found' },
                isCatchAllDomain: false,
                hadMx: true,
                mxHosts,
            });
        }

        if (msftCheck.result === 'federated') {
            // Federated domain — Azure AD doesn't manage mailboxes directly.
            // Fall through to SMTP probe as the only option.
        } else {
            // API failed after all retries (throttled/error).
            // For M365, SMTP is unreliable — classify as unknown anti-probe.
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
