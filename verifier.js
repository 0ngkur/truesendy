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
// 10 concurrent SMTP connections: each of 5 server workers can run
// real probe + catch-all probe simultaneously without queueing.
const SMTP_MAX_CONCURRENCY = 10;
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

// ── Simple rate limiter: 2 concurrent API calls, 300ms between each ──────────
const MSFT_MAX_CONCURRENT = 2;
const MSFT_MIN_INTERVAL   = 300;
let _msftActive   = 0;
let _msftLastCall = 0;
const _msftQueue  = [];

function _msftAcquire() {
    return new Promise(resolve => {
        const tryRun = () => {
            const now  = Date.now();
            const wait = Math.max(0, MSFT_MIN_INTERVAL - (now - _msftLastCall));
            if (_msftActive < MSFT_MAX_CONCURRENT && wait === 0) {
                _msftActive++;
                _msftLastCall = Date.now();
                resolve();
            } else {
                setTimeout(tryRun, Math.max(50, wait || 50));
            }
        };
        if (_msftActive < MSFT_MAX_CONCURRENT) {
            tryRun();
        } else {
            _msftQueue.push(tryRun);
        }
    });
}
function _msftRelease() {
    _msftActive = Math.max(0, _msftActive - 1);
    if (_msftQueue.length) {
        const next = _msftQueue.shift();
        setTimeout(next, MSFT_MIN_INTERVAL);
    }
}

// Per-domain cache for catch-all status.
const _msftCatchAllCache = new Map();

/**
 * Single M365 API call with rate limiting.
 */
async function _checkMicrosoftMailboxOnce(email) {
    if (!_fetch) return { result: 'api_error', reason: 'no_fetch' };

    await _msftAcquire();
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
        const isFederated = !!(credentials.FederationRedirectUrl || credentials.FederationProvider);
        if (isFederated || ifExists === 6) return { result: 'federated' };

        // ── Trust IfExistsResult even when throttled ──
        // Data shows IfExistsResult is generally accurate with ThrottleStatus=1.
        // Treating as unreliable causes too many false "unknown" results (60% → 55%).
        if (ifExists === 0 || ifExists === 5) return { result: 'exists' };
        if (ifExists === 1) return { result: 'not_found' };

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
 */
async function checkMicrosoftMailbox(email) {
    const MAX_RETRIES = 3;
    const BACKOFF_MS = [2000, 4000, 8000];

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const result = await _checkMicrosoftMailboxOnce(email);

        if (result.result === 'exists' || result.result === 'not_found' || result.result === 'federated') {
            return result;
        }

        if ((result.result === 'throttled' || result.result === 'api_error') && attempt < MAX_RETRIES) {
            await new Promise(r => setTimeout(r, BACKOFF_MS[attempt] || 10000));
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
// Mimecast accepts ALL inbound mail at SMTP level, then filters internally.
// An SMTP 250 from Mimecast does NOT mean the mailbox exists.
// But if catch-all IS detected, still classify as catch_all.
// IMPORTANT: Only Mimecast here. Barracuda/Proofpoint SMTP rejections ARE
// reliable — adding them caused false unknowns in testing.
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

        // ── SMTP RETRY on connection_failed ──────────────────────────────────
        // Transient failures are common under load. One retry handles most.
        if (smtpResult && smtpResult.result === 'connection_failed') {
            await new Promise(r => setTimeout(r, 1000)); // 1s cooldown
            ({ smtpResult, isCatchAll } = await checkMailbox(mxHosts, domain, email));
        }
    } finally {
        _smtpRelease();
    }

    // ── SMTP-unreliable providers (Mimecast only) ───────────────────────────
    if (SMTP_UNRELIABLE_PROVIDERS.has(mxProvider)) {
        if (smtpResult && smtpResult.result === 'accepted') {
            if (isCatchAll) {
                return buildResult({
                    email, localPart, domain,
                    smtpOutcome: smtpResult,
                    isCatchAllDomain: true,
                    hadMx: true,
                    mxHosts,
                });
            }
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
