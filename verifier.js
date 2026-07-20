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
const MSFT_RATE_LIMIT = 3;
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

// Drain the rate queue every 333ms
setInterval(() => {
    _refillTokens();
    while (_msftRateQueue.length > 0 && _msftTokens > 0) {
        _msftTokens--;
        _msftRateQueue.shift()();
    }
}, 333).unref();

// Per-domain cache for catch-all status.
const _msftCatchAllCache = new Map();

/**
 * Single M365 API call (no retry).
 * CRITICAL: Check IfExistsResult BEFORE ThrottleStatus.
 * Microsoft returns valid IfExistsResult even when ThrottleStatus=1.
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

        // Check definitive IfExistsResult FIRST — throttle is just "slow down"
        if (ifExists === 0 || ifExists === 5) return { result: 'exists' };
        if (ifExists === 1) return { result: 'not_found' };
        if (ifExists === 6) return { result: 'federated' };

        // Only treat as throttled if IfExistsResult was ambiguous
        if (throttled) return { result: 'throttled' };

        return { result: 'unknown', ifExists };
    } catch (e) {
        if (e.name === 'AbortError') return { result: 'api_error', reason: 'timeout' };
        return { result: 'api_error', reason: e.message };
    }
}

/**
 * Check Microsoft mailbox with retry + exponential backoff.
 */
async function checkMicrosoftMailbox(email) {
    const MAX_RETRIES = 5;
    const BACKOFF_MS = [2000, 3000, 5000, 8000, 12000];

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const result = await _checkMicrosoftMailboxOnce(email);

        if (result.result === 'exists' || result.result === 'not_found' || result.result === 'federated') {
            return result;
        }

        if ((result.result === 'throttled' || result.result === 'api_error') && attempt < MAX_RETRIES) {
            await new Promise(r => setTimeout(r, BACKOFF_MS[attempt] || 12000));
            continue;
        }

        return result;
    }
    return { result: 'api_error', reason: 'max_retries' };
}

/**
 * Check M365 catch-all status — hybrid API + SMTP approach.
 * Strategy 1: API probe (fast, detects Azure AD catch-all)
 * Strategy 2: SMTP probe fallback (detects Exchange transport-rule catch-all)
 * Result is cached per domain.
 */
async function isMsftDomainCatchAll(domain, mxHosts) {
    if (_msftCatchAllCache.has(domain)) return _msftCatchAllCache.get(domain);

    // Strategy 1: M365 API probe for Azure AD catch-all
    const fakeEmail = `nonexistent-probe-${Math.random().toString(36).slice(2, 10)}@${domain}`;
    const fakeCheck = await checkMicrosoftMailbox(fakeEmail);

    if (fakeCheck.result === 'exists') {
        // API says fake address exists → definite Azure AD catch-all
        _msftCatchAllCache.set(domain, true);
        return true;
    }

    // Strategy 2: SMTP probe for transport-rule catch-all
    // Some M365 domains have Exchange transport rules that route ALL inbound
    // mail, even for addresses not in Azure AD. Only SMTP can detect this.
    if (mxHosts && mxHosts.length > 0) {
        try {
            await _smtpAcquire();
            try {
                const { smtpResult, isCatchAll } = await checkMailbox(mxHosts, domain, fakeEmail);
                if (smtpResult && smtpResult.result === 'accepted') {
                    _msftCatchAllCache.set(domain, true);
                    return true;
                }
            } finally {
                _smtpRelease();
            }
        } catch (e) {
            // SMTP failed — not catch-all
        }
    }

    _msftCatchAllCache.set(domain, false);
    if (_msftCatchAllCache.size > 5000) {
        const firstKey = _msftCatchAllCache.keys().next().value;
        _msftCatchAllCache.delete(firstKey);
    }
    return false;
}

// ── Providers whose SMTP acceptance is UNRELIABLE ────────────────────────────
// These providers accept ALL inbound mail at SMTP level and filter AFTER.
// An SMTP 250 from these providers does NOT mean the mailbox exists.
// Reon/ZeroBounce classify these as "unknown" regardless of SMTP result.
const SMTP_UNRELIABLE_PROVIDERS = new Set([
    'Mimecast',
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

    // Identify the mail provider from MX records
    const mxProvider = identifyMxProvider(mxHosts);
    const isM365 = mxProvider === 'Microsoft 365';

    // ────────────────────────────────────────────────────────────────────────
    // FAST PATH: Microsoft 365 domains → API is authoritative
    // ────────────────────────────────────────────────────────────────────────
    if (isM365) {
        const msftCheck = await checkMicrosoftMailbox(email);

        if (msftCheck.result === 'exists') {
            // ── User EXISTS in Azure AD ──
            // API says account exists, but the mailbox may be disabled/deprovisioned.
            // Do SMTP probe to confirm: if SMTP explicitly rejects (550) → invalid.
            // SMTP rejection is always reliable; acceptance may not be.
            try {
                await _smtpAcquire();
                try {
                    const { smtpResult } = await checkMailbox(mxHosts, domain, email);
                    if (smtpResult && smtpResult.result === 'rejected' &&
                        (smtpResult.rejectionType === 'mailbox_not_found' || smtpResult.rejectionType === 'mailbox_disabled')) {
                        // SMTP explicitly says mailbox doesn't exist → invalid
                        return buildResult({
                            email, localPart, domain,
                            smtpOutcome: smtpResult,
                            isCatchAllDomain: false,
                            hadMx: true,
                            mxHosts,
                        });
                    }
                } finally {
                    _smtpRelease();
                }
            } catch (e) {
                // SMTP failed — trust API, classify as safe
            }
            // SMTP accepted or failed → trust API, user is real
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'accepted', code: 250, responseText: 'msft_api_exists' },
                isCatchAllDomain: false,
                hadMx: true,
                mxHosts,
            });
        }

        if (msftCheck.result === 'not_found') {
            // ── User NOT in Azure AD ──
            // Check if domain has Azure AD catch-all (API only, not SMTP).
            // SMTP gives false positives due to transport rules/greylisting.
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
            // Federated domain — fall through to SMTP
        } else {
            // API failed after all retries — classify as unknown anti-probe
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
    // These providers accept ALL mail at SMTP level then filter after.
    // An SMTP 250 from these providers is meaningless — classify as unknown.
    if (SMTP_UNRELIABLE_PROVIDERS.has(mxProvider)) {
        if (smtpResult && smtpResult.result === 'accepted') {
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'temp_fail' },  // treat acceptance as temp_fail → unknown
                isCatchAllDomain: false,
                hadMx: true,
                mxHosts,
            });
        }
        // If SMTP explicitly rejects (mailbox_not_found), that IS reliable
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
