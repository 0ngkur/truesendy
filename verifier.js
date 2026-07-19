const { checkSyntax } = require('./lib/syntaxCheck');
const { resolveMailServers } = require('./lib/dnsLookup');
const { checkMailbox } = require('./lib/smtpProbe');
const { buildResult } = require('./lib/classify');
const { identifyMxProvider } = require('./data/domainData');

// ── Global SMTP concurrency cap ──────────────────────────────────────────────
// Each SMTP probe holds a socket for up to 7s. Without a process-wide cap, a
// flood of verifications would open thousands of sockets, exhaust the OS port
// range, and trip provider rate limits (Gmail allows ~15-50 concurrent/source).
// Excess callers QUEUE (backpressure) instead of piling on connections.
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

// ── Microsoft GetCredentialType API ─────────────────────────────────────────
// When our SMTP probe is blocked by Microsoft 365 (sender_ip_blocked), we use
// Microsoft's own public API to check if the mailbox exists. This API is used
// by Microsoft's own login page and tells us if an account exists in Azure AD/M365.
//
// IfExistsResult values:
//   0 = account EXISTS in this tenant
//   1 = account does NOT exist
//   5 = personal Microsoft account (MSA) — exists
//   6 = domain is federated (external IdP) — cannot determine mailbox
//  -1 = throttled / unknown
//
// This technique is used by NeverBounce, Hunter.io, and other professional verifiers
// for Microsoft 365 domains where SMTP is blocked.
const MSFT_API_URL = 'https://login.microsoftonline.com/common/GetCredentialType';
const MSFT_API_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Origin': 'https://login.microsoftonline.com',
    'Referer': 'https://login.microsoftonline.com/',
    'Accept-Language': 'en-US,en;q=0.9',
};

// Concurrency cap for M365 API — Microsoft throttles aggressive parallel requests.
// Max 3 simultaneous calls keeps us under the rate limit during bulk verification.
const MSFT_API_MAX_CONCURRENT = 3;
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

async function checkMicrosoftMailbox(email) {
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

        const res = await fetch(MSFT_API_URL, {
            method: 'POST',
            headers: MSFT_API_HEADERS,
            body,
            signal: controller.signal,
        });
        clearTimeout(timer);

        if (!res.ok) return { result: 'api_error', reason: `http_${res.status}` };

        const data = await res.json();
        const ifExists  = data.IfExistsResult;
        const throttled = data.ThrottleStatus === 1;

        if (throttled) return { result: 'throttled' };

        if (ifExists === 0) return { result: 'exists' };     // confirmed in tenant
        if (ifExists === 5) return { result: 'exists' };     // personal MSA account
        if (ifExists === 1) return { result: 'not_found' };  // not in tenant
        if (ifExists === 6) return { result: 'federated' };  // external IdP — can't tell

        return { result: 'unknown', ifExists };
    } catch (e) {
        if (e.name === 'AbortError') return { result: 'api_error', reason: 'timeout' };
        return { result: 'api_error', reason: e.message };
    } finally {
        _msftRelease();
    }
}

// ── Main verification pipeline ───────────────────────────────────────────────
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

    // Step 2: SMTP probe (real connection, globally capped)
    await _smtpAcquire();
    let smtpResult, isCatchAll;
    try {
        ({ smtpResult, isCatchAll } = await checkMailbox(mxHosts, domain, email));
    } finally {
        _smtpRelease();
    }

    // Step 3: Microsoft 365 API fallback
    // When SMTP is blocked by Microsoft (sender_ip_blocked), use the M365
    // GetCredentialType API to definitively determine if the mailbox exists.
    // This gives us safe/invalid/catch_all instead of falling back to unknown.
    const mxProvider = identifyMxProvider(mxHosts);
    const isM365 = mxProvider === 'Microsoft 365';

    if (isM365 && (
        smtpResult.result === 'sender_rejected' ||
        (smtpResult.result === 'rejected' && smtpResult.rejectionType === 'sender_blocked') ||
        smtpResult.result === 'connection_failed'
    )) {
        const msftCheck = await checkMicrosoftMailbox(email);

        if (msftCheck.result === 'exists') {
            // Microsoft confirmed this mailbox exists in the Azure AD tenant.
            // Probe a fake address to detect transport-rule catch-all domains
            // (some M365 tenants route ALL inbound mail regardless of mailbox existence).
            const fakeEmail = `nonexistent-probe-${Math.random().toString(36).slice(2,10)}@${domain}`;
            const fakeCheck = await checkMicrosoftMailbox(fakeEmail);
            // If the fake ALSO 'exists' → catch-all via Azure AD (unlikely but possible)
            const domainIsCatchAll = fakeCheck.result === 'exists';
            return buildResult({
                email, localPart, domain,
                smtpOutcome: { result: 'accepted', code: 250, responseText: 'msft_api_exists' },
                isCatchAllDomain: domainIsCatchAll,
                hadMx: true,
                mxHosts,
            });
        }

        if (msftCheck.result === 'not_found') {
            // User not found in Azure AD tenant.
            // Edge case: domain may have a transport-rule catch-all (routes all mail
            // even for non-existent users). Probe a second fake to check:
            // If fake is ALSO not_found → domain is NOT catch-all, real address is invalid.
            // (If fake returned 'exists', domain is catch-all — but this is extremely rare.)
            const fakeEmail = `nonexistent-probe-${Math.random().toString(36).slice(2,10)}@${domain}`;
            const fakeCheck = await checkMicrosoftMailbox(fakeEmail);
            const domainIsCatchAll = fakeCheck.result === 'exists';

            if (domainIsCatchAll) {
                // Transport-rule catch-all: fake address shows as existing → catch-all
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

        // throttled / federated / api_error — fall through to SMTP-based result
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
