const { checkSyntax } = require('./lib/syntaxCheck');
const { resolveMailServers } = require('./lib/dnsLookup');
const { checkMailbox } = require('./lib/smtpProbe');
const { buildResult } = require('./lib/classify');
const { identifyMxProvider, isAntiProbeProvider } = require('./data/domainData');
const greylist = require('./lib/greylistQueue');
const historyDB = require('./lib/historyDB');

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

// ══════════════════════════════════════════════════════════════════════════════
//  CONCURRENCY CONTROLS — tuned for speed + accuracy
// ══════════════════════════════════════════════════════════════════════════════

// SMTP: 15 concurrent connections. High enough for speed, each probe is
// independent (different target servers). Enterprise gateways don't correlate
// connections from the same IP to different domains.
const SMTP_MAX_CONCURRENCY = 25;
let _smtpActive = 0;
const _smtpQueue = [];
function _smtpAcquire() {
    if (_smtpActive < SMTP_MAX_CONCURRENCY) { _smtpActive++; return Promise.resolve(); }
    return new Promise(resolve => _smtpQueue.push(resolve));
}
function _smtpRelease() {
    _smtpActive = Math.max(0, _smtpActive - 1);
    if (_smtpQueue.length && _smtpActive < SMTP_MAX_CONCURRENCY) {
        _smtpActive++; _smtpQueue.shift()();
    }
}

// M365 API: 5 concurrent, no artificial delays. HTTP round-trip (~300ms)
// provides natural spacing. 5 concurrent = ~15 req/sec max burst.
// If throttled, ONE fast retry after 1.5s. No long backoff chains.
const MSFT_MAX_CONCURRENT = 3;
let _msftActive = 0;
const _msftQueue = [];
function _msftAcquire() {
    if (_msftActive < MSFT_MAX_CONCURRENT) { _msftActive++; return Promise.resolve(); }
    return new Promise(resolve => _msftQueue.push(resolve));
}
function _msftRelease() {
    _msftActive = Math.max(0, _msftActive - 1);
    if (_msftQueue.length && _msftActive < MSFT_MAX_CONCURRENT) {
        _msftActive++; _msftQueue.shift()();
    }
}

// ══════════════════════════════════════════════════════════════════════════════
//  MICROSOFT 365 API — GetCredentialType
// ══════════════════════════════════════════════════════════════════════════════
const MSFT_API_URL = 'https://login.microsoftonline.com/common/GetCredentialType';

/**
 * Single M365 API call. Fast: 8s timeout, no retry here.
 */
async function _msftApiCall(email) {
    if (!_fetch) return { result: 'api_error', reason: 'no_fetch' };

    await _msftAcquire();
    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 8000);

        const res = await _fetch(MSFT_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            },
            body: JSON.stringify({
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
            }),
            signal: controller.signal,
        });
        clearTimeout(timer);

        if (!res.ok) return { result: 'api_error', reason: `http_${res.status}` };

        const data = await res.json();
        const ifExists  = data.IfExistsResult;
        const throttled = data.ThrottleStatus === 1;
        const creds     = data.Credentials || {};

        // Federation check — always reliable
        if (!!(creds.FederationRedirectUrl || creds.FederationProvider) || ifExists === 6) {
            return { result: 'federated' };
        }

        // Definitive results
        if (ifExists === 0 || ifExists === 4 || ifExists === 5) return { result: 'exists' };
        if (ifExists === 1) return { result: 'not_found' };

        // Throttled or ambiguous
        if (ifExists === 2 || throttled) return { result: 'throttled' };

        return { result: 'unknown', ifExists };
    } catch (e) {
        return { result: 'api_error', reason: e.name === 'AbortError' ? 'timeout' : e.message };
    } finally {
        _msftRelease();
    }
}

/**
 * Check M365 mailbox: 1 call + 3 retries with exponential backoff.
 * Delays: 3s, 8s, 15s. Total max wait ~26s for throttled emails.
 */
async function checkMicrosoftMailbox(email) {
    const r1 = await _msftApiCall(email);
    if (r1.result === 'exists' || r1.result === 'not_found' || r1.result === 'federated') return r1;

    // 3 retries with exponential backoff on throttle/error
    const retryDelays = [3000, 8000, 15000];
    for (let i = 0; i < retryDelays.length; i++) {
        if (r1.result !== 'throttled' && r1.result !== 'api_error') break;
        await new Promise(r => setTimeout(r, retryDelays[i]));
        const retry = await _msftApiCall(email);
        if (retry.result === 'exists' || retry.result === 'not_found' || retry.result === 'federated') return retry;
        if (i === retryDelays.length - 1) return retry;
    }

    return r1;
}

// Per-domain catch-all cache
const _catchAllCache = new Map();

/**
 * M365 catch-all detection — API with 2 retries.
 * Probes a fake address. If exists → catch-all domain.
 */
async function isMsftCatchAll(domain) {
    if (_catchAllCache.has(domain)) return _catchAllCache.get(domain);

    let result = false;
    let resolved = false;

    // Try up to 3 times to get a definitive answer
    for (let attempt = 0; attempt < 3; attempt++) {
        const fake = `nonexist-probe-${Math.random().toString(36).slice(2, 10)}@${domain}`;
        const check = await _msftApiCall(fake);
        if (check.result === 'exists') { result = true; resolved = true; break; }
        if (check.result === 'not_found') { result = false; resolved = true; break; }
        // throttled/error — wait and retry
        if (attempt < 2) await new Promise(r => setTimeout(r, 3000 + attempt * 5000));
    }

    // Only cache if we got a definitive answer
    if (resolved) {
        _catchAllCache.set(domain, result);
        if (_catchAllCache.size > 5000) {
            _catchAllCache.delete(_catchAllCache.keys().next().value);
        }
    }
    return resolved ? result : null; // null = couldn't determine
}

// Per-domain SMTP catch-all cache (mirror of the M365 API cache above).
// Catch-all is a DOMAIN property: once determined, every email on the domain
// shares the verdict. Lets us short-circuit repeat domains — one fake probe per
// domain per run, not one per email — improving both consistency and speed.
const _smtpCatchAllCache = new Map();
const SMTP_CATCHALL_CACHE_MAX = 5000;

// Accept-all gateways: accept EVERY SMTP recipient then filter internally, so
// SMTP acceptance can't confirm a specific mailbox → classify as catch_all.
// (Mimecast + Barracuda confirmed accept-all from real per-email data vs Reoon.)
const SMTP_ACCEPT_ALL = new Set(['Mimecast', 'Barracuda']);


// ══════════════════════════════════════════════════════════════════════════════
//  MAIN VERIFICATION PIPELINE — "Fail Fast, Classify Smart"
// ══════════════════════════════════════════════════════════════════════════════
async function verifyEmail(rawEmail) {
    const syntax = checkSyntax(rawEmail);

    if (!syntax.valid) {
        return {
            email: rawEmail, domain: null, providerType: null,
            mxProvider: null, mxRecords: '', emailCategory: null,
            status: 'invalid', reasonCode: syntax.reason,
            safeToSend: false, overallScore: 0,
            flags: { disposable: false, spamtrap: false, roleBased: false, catchAll: false, freeEmail: false },
        };
    }

    const { email, localPart, domain } = syntax;

    // Phase 2: Historical cache — if we verified this email < 7 days ago, return cached result
    const cached = historyDB.getEmailHistory(email);
    if (cached && (Date.now() - cached.timestamp < 7 * 24 * 60 * 60 * 1000)) {
        // Return cached result with cached flag
        const result = buildResult({
            email, localPart, domain,
            smtpOutcome: { result: 'accepted', code: 250, responseText: 'historical_cache' },
            isCatchAllDomain: false, hadMx: true, mxHosts: [],
        });
        // Override with cached status if it was invalid (don't re-probe known invalids)
        if (cached.status === 'invalid') {
            return { ...result, status: 'invalid', reasonCode: cached.reasonCode, safeToSend: false, overallScore: cached.score };
        }
        // For valid/cached results, return quickly
        return { ...result, status: cached.status, reasonCode: 'historical_cache', overallScore: cached.score };
    }

    // Step 1: DNS — fast, cached by OS resolver
    const mxHosts = await resolveMailServers(domain);
    if (!mxHosts.length) {
        return buildResult({
            email, localPart, domain,
            smtpOutcome: { result: 'rejected', rejectionType: 'mailbox_not_found' },
            isCatchAllDomain: false, hadMx: false, mxHosts: [],
        });
    }

    const mxProvider = identifyMxProvider(mxHosts);
    const isM365 = mxProvider === 'Microsoft 365';

    // ──────────────────────────────────────────────────────────────────────
    // M365 FAST PATH: API is authoritative, no SMTP needed
    // ──────────────────────────────────────────────────────────────────────
    if (isM365) {
        const api = await checkMicrosoftMailbox(email);

        if (api.result === 'exists') {
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'accepted', code: 250, responseText: 'msft_api_exists' },
                isCatchAllDomain: false, hadMx: true, mxHosts,
            });
        }

        if (api.result === 'not_found') {
            const catchAll = await isMsftCatchAll(domain);
            if (catchAll === true) {
                return buildResult({
                    email, localPart, domain,
                    smtpOutcome: { result: 'accepted', code: 250, responseText: 'msft_catchall' },
                    isCatchAllDomain: true, hadMx: true, mxHosts,
                });
            }
            if (catchAll === null) {
                // Catch-all check failed (throttled) — fall through to SMTP
                // instead of marking invalid (fixes nationals.com false invalids)
            } else {
                // API definitively says user doesn't exist → invalid
                return buildResult({
                    email, localPart, domain,
                    smtpOutcome: { result: 'rejected', code: 550, responseText: 'msft_api_not_found', rejectionType: 'mailbox_not_found' },
                    isCatchAllDomain: false, hadMx: true, mxHosts,
                });
            }
        }

        // Federated → fall through to SMTP (API can't check federated mailboxes)
        // Throttled/error → also fall through to SMTP as backup
    }

    // ──────────────────────────────────────────────────────────────────────
    // GMAIL / GOOGLE WORKSPACE / YAHOO / AOL — SMTP probes ALWAYS fail from
    // datacenter IPs. These providers are catch-all (accept all syntactically
    // valid addresses). Skip SMTP entirely — saves 8s per email and matches
    // Reoon's approach for these providers.
    // ──────────────────────────────────────────────────────────────────────
    const SKIP_SMTP_PROVIDERS = new Set(['Google Workspace', 'Yahoo']);
    const SKIP_SMTP_DOMAINS = new Set([
        'gmail.com', 'googlemail.com',
        'yahoo.com', 'yahoo.co.uk', 'ymail.com', 'rocketmail.com',
        'aol.com', 'aim.com',
    ]);
    if (SKIP_SMTP_PROVIDERS.has(mxProvider) || SKIP_SMTP_DOMAINS.has(domain.toLowerCase())) {
        return buildResult({
            email, localPart, domain,
            smtpOutcome: { result: 'connection_failed', reason: 'provider_blocks_smtp' },
            isCatchAllDomain: true, hadMx: true, mxHosts,
        });
    }

    // ──────────────────────────────────────────────────────────────────────
    // SMTP PATH: for non-M365, federated M365, or M365 API failure
    // ──────────────────────────────────────────────────────────────────────
    // Per-domain catch-all cache: short-circuit known catch-all domains, and skip
    // the redundant fake probe for known non-catch-all domains (one probe/domain).
    if (_smtpCatchAllCache.get(domain) === true) {
        return buildResult({
            email, localPart, domain,
            smtpOutcome: { result: 'accepted', code: 250, responseText: 'smtp_catchall_cached' },
            isCatchAllDomain: true, hadMx: true, mxHosts,
        });
    }
    const skipCatchAll = _smtpCatchAllCache.get(domain) === false;

    await _smtpAcquire();
    let smtpResult, isCatchAll;
    // Anti-probe providers (Proofpoint, Mimecast, Cisco, etc.) — use 3s timeout
    // instead of 8s. These connections fail fast anyway, saves 5s per failed probe.
    const smtpOpts = { skipCatchAll };
    if (isAntiProbeProvider(mxProvider)) {
        smtpOpts.shortTimeout = true;
    }
    try {
        ({ smtpResult, isCatchAll } = await checkMailbox(mxHosts, domain, email, smtpOpts));
    } finally {
        _smtpRelease();
    }
    // Cache the freshly-determined domain status. Only when we actually ran the
    // fake probe — skipped probes must not overwrite a prior determination.
    if (!skipCatchAll) {
        _smtpCatchAllCache.set(domain, !!isCatchAll);
        if (_smtpCatchAllCache.size > SMTP_CATCHALL_CACHE_MAX) {
            _smtpCatchAllCache.delete(_smtpCatchAllCache.keys().next().value);
        }
    }

    // Accept-all gateways (Mimecast): accept every SMTP recipient then filter
    // internally, so acceptance cannot confirm a specific mailbox. Classify as
    // catch_all — sending never SMTP-bounces, matching Reoon. Previously forced to
    // "unknown", which manufactured ~53 false unknowns on Mimecast-heavy lists.
    // Cache the domain so other emails on it short-circuit to catch_all.
    if (SMTP_ACCEPT_ALL.has(mxProvider)) {
        if (smtpResult && smtpResult.result === 'accepted') {
            _smtpCatchAllCache.set(domain, true);
            return buildResult({
                email, localPart, domain,
                smtpOutcome: smtpResult, isCatchAllDomain: true, hadMx: true, mxHosts,
            });
        }
    }

    return buildResult({
        email, localPart, domain,
        smtpOutcome: smtpResult, isCatchAllDomain: isCatchAll, hadMx: true, mxHosts,
    });
}

// Start greylist worker — retries temp_fail emails in the background
function startGreylistWorker() {
    greylist.startWorker(async (email) => {
        return verifyEmail(email);
    }, 60000);
    console.log('[TrueSendy] Greylist retry worker started');
}

module.exports = { verifyEmail, startGreylistWorker };
