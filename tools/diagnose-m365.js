#!/usr/bin/env node
'use strict';

/**
 * tools/diagnose-m365.js — re-probe M365 "unknown" results via the API to find
 * out WHY each fell through to SMTP during the batch.
 *
 *   node tools/diagnose-m365.js /tmp/truesendy_job_<id>.jsonl
 *
 * For each M365-unknown email, calls GetCredentialType and tallies the verdict:
 *   exists / not_found → RECOVERABLE (API can resolve — original run throttled)
 *   federated          → CEILING (mailbox on a third-party IdP; API can't check)
 *   throttled / api_error → transient (backoff/rerun may help)
 *
 * Run this AFTER the Mimecast fix re-measure, on the latest job file.
 */
const fs = require('fs');

const MSFT_API_URL = 'https://login.microsoftonline.com/common/GetCredentialType';
const CONCURRENCY = 3;
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function probe(email) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
        const res = await fetch(MSFT_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0' },
            body: JSON.stringify({
                username: email, isOtherIdpSupported: true, checkPhones: false,
                isRemoteNGCSupported: false, isCookieBannerShown: false, isFidoSupported: false,
                originalRequest: '', country: 'US', forceotclogin: false,
                isExternalFederationDisallowed: false, isRemoteConnectSupported: false,
                federationFlags: 0, isSignup: false, flowToken: '',
            }),
            signal: controller.signal,
        });
        clearTimeout(timer);
        if (!res.ok) return 'api_error';
        const d = await res.json();
        const c = d.Credentials || {};
        if (!!(c.FederationRedirectUrl || c.FederationProvider) || d.IfExistsResult === 6) return 'federated';
        if (d.IfExistsResult === 0 || d.IfExistsResult === 4 || d.IfExistsResult === 5) return 'exists';
        if (d.IfExistsResult === 1) return 'not_found';
        if (d.IfExistsResult === 2 || d.ThrottleStatus === 1) return 'throttled';
        return 'other(' + d.IfExistsResult + ')';
    } catch (e) {
        clearTimeout(timer);
        return 'api_error';
    }
}

async function main() {
    const file = process.argv[2];
    if (!file) { console.error('Usage: node tools/diagnose-m365.js <job.jsonl>'); process.exit(1); }
    const rows = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)
        .map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    const m365Unknown = rows.filter(r => r.mxProvider === 'Microsoft 365' && r.status === 'unknown');
    console.log(`M365 unknowns to re-probe: ${m365Unknown.length}`);

    const tally = {};
    let i = 0;
    async function worker() {
        while (i < m365Unknown.length) {
            const idx = i++;
            const verdict = await probe(m365Unknown[idx].email);
            tally[verdict] = (tally[verdict] || 0) + 1;
            if ((idx + 1) % 10 === 0) process.stdout.write(`  ...${idx + 1}/${m365Unknown.length}\r`);
            await sleep(300); // gentle spacing to avoid throttling during the diagnostic itself
        }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
    process.stdout.write(' '.repeat(40) + '\r');

    console.log('\n=== M365 unknown re-probe distribution ===');
    const total = Object.values(tally).reduce((a, b) => a + b, 0) || 1;
    for (const [k, v] of Object.entries(tally).sort((a, b) => b[1] - a[1])) {
        console.log(`  ${k.padEnd(16)} ${String(v).padStart(4)}  ${(100 * v / total).toFixed(0)}%`);
    }
    const recoverable = (tally.exists || 0) + (tally.not_found || 0);
    console.log(`\n  RECOVERABLE (exists+not_found): ${recoverable} -> fixable via M365 API reliability`);
    console.log(`  CEILING (federated):            ${tally.federated || 0} -> API can't resolve third-party IdP`);
    console.log(`  THROTTLED/ERROR:                ${(tally.throttled || 0) + (tally.api_error || 0)} -> backoff/rerun may help`);
}

main().catch(e => { console.error('Failed:', e.message); process.exit(1); });
