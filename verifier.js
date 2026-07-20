const { checkSyntax } = require('./lib/syntaxCheck');
const { resolveMailServers } = require('./lib/dnsLookup');
const { checkMailbox } = require('./lib/smtpProbe');
const { buildResult } = require('./lib/classify');
const { identifyMxProvider } = require('./data/domainData');

// Use node-fetch (works on Node 14+, already in package.json)
// Native fetch() only exists in Node 18+ and the VPS may have an older version.
let _fetch;
try {
    // Prefer native fetch if available (Node 18+)
    if (typeof globalThis.fetch === 'function') {
        _fetch = globalThis.fetch;
    } else {
        _fetch = require('node-fetch');
    }
} catch {
    // Last resort — this will cause Microsoft API to gracefully degrade
    _fetch = null;
}

// ── Global SMTP concurrency cap ──────────────────────────────────────────────
const SMTP_MAX_CONCURRENCY = 50;
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
// When SMTP is blocked (common on M365), this public Microsoft API tells us
// definitively whether a mailbox exists in Azure AD. This is the same technique
// used by NeverBounce, Hunter.io, ZeroBounce, and Reon for Microsoft domains.
//
// IfExistsResult values:
//   0 = account EXISTS in this tenant → safe
//   1 = account does NOT exist → invalid
//   5 = personal Microsoft account (MSA) → safe
//   6 = domain is federated (external IdP) → unknown (can't determine)
//  -1 = throttled
const MSFT_API_URL = 'https://login.microsoftonline.com/common/GetCredentialType';

// Concurrency cap — Microsoft throttles aggressive parallel requests.
// 5 simultaneous is the sweet spot: fast enough for bulk, under the rate limit.
const MSFT_API_MAX_CONCURRENT = 5;
let _msftActive = 0;
const _msftQueue = [];
function _msftAcquire() {
    if (_msftActive < MSFT_API_MAX_CONCURRENT) { _msftActive++; return Promise.resolve(); }
    return new Promise(resolve => _msftQueue.push(resolve));
}
function _msftRelease() {
    _msftActive = Math.max(0, _msftActive - 1);
    if (_msftQueue.length) { _msftActive++; _msftQueue.shift()(); }
}

// Per-domain cache for catch-all status detected via Microsoft API.
// Avoids redundant fake-address probes when many emails share a domain.
const _msftCatchAllCache = new Map();

async function checkMicrosoftMailbox(email) {
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
        const timer = setTimeout(() => controller.abort(), 8000);

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
    } finally {
        _msftRelease();
    }
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

    // Evict old entries to prevent memory leak in long-running process
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
            smtpOutcome: { result: 'rejected' },
            isCatchAllDomain: false,
            hadMx: false,
            mxHosts: [],
        });
    }

    // Identify the mail provider from MX records
    const mxProvider = identifyMxProvider(mxHosts);
    const isM365 = mxProvider === 'Microsoft 365';

    // ────────────────────────────────────────────────────────────────────────
    // FAST PATH: Microsoft 365 domains → use API instead of SMTP
    // ────────────────────────────────────────────────────────────────────────
    // This is the #1 accuracy improvement. M365 blocks SMTP probes from most
    // IPs, but the GetCredentialType API works perfectly from anywhere.
    // 84+ of 246 test emails are M365 — this single optimization fixes the
    // majority of mismatches.
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
                // Domain has a transport-rule catch-all — mail is accepted for
                // ALL addresses even though the user doesn't exist in Azure AD.
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
            // Fall through to SMTP probe as a secondary check.
        }

        // For throttled / api_error — fall through to SMTP probe
    }

    // ────────────────────────────────────────────────────────────────────────
    // STANDARD PATH: SMTP probe for all other providers
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
