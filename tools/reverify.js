#!/usr/bin/env node
'use strict';

/**
 * tools/reverify.js — re-run the CURRENT verifier code against every email in an
 * old job file (or a CSV). Bypasses the web upload/browser entirely so you can
 * test a code fix (e.g. HELO change) against the same list in one command.
 *
 *   node tools/reverify.js /tmp/truesendy_job_<id>.jsonl
 *   node tools/reverify.js some_list.csv
 *
 * Uses the deployed verifier.js (whatever code is checked out), concurrency 10.
 */
const fs = require('fs');
const { verifyEmail } = require('../verifier');

function readEmails(file) {
    const text = fs.readFileSync(file, 'utf8');
    if (text.trim().split('\n')[0].startsWith('{')) {
        // jsonl job file
        return text.split('\n').filter(Boolean)
            .map(l => { try { return JSON.parse(l); } catch { return null; } })
            .filter(Boolean).map(r => r.email);
    }
    // CSV — find the email column heuristically
    const lines = text.split(/\r?\n/).filter(l => l.trim());
    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
    const emailColIdx = headers.findIndex(h => /e-?mail/i.test(h));
    const emails = [];
    for (let i = 1; i < lines.length; i++) {
        const cells = lines[i].split(',');
        const v = (cells[emailColIdx] || '').trim().replace(/^"|"$/g, '');
        if (v.includes('@')) emails.push(v);
    }
    return emails;
}

async function main() {
    const file = process.argv[2];
    if (!file) { console.error('Usage: node tools/reverify.js <job.jsonl | emails.csv>'); process.exit(1); }

    const emails = readEmails(file).filter(Boolean);
    console.log(`Re-verifying ${emails.length} emails with the CURRENT verifier code (HELO = truesendy.com)...\n`);

    const CONCURRENCY = 10;
    const results = [];
    let i = 0, done = 0;
    const start = Date.now();

    async function worker() {
        while (i < emails.length) {
            const email = emails[i++];
            try {
                results.push(await verifyEmail(email));
            } catch (e) {
                results.push({ email, status: 'unknown', mxProvider: null, reasonCode: 'reverify_error: ' + e.message });
            }
            done++;
            if (done % 20 === 0) process.stdout.write(`  ${done}/${emails.length}\r`);
        }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    process.stdout.write(' '.repeat(50) + '\r');

    const bucket = {};
    for (const r of results) {
        const p = r.mxProvider || '(none)';
        const s = r.status || 'unknown';
        if (!bucket[p]) bucket[p] = { safe: 0, valid: 0, catch_all: 0, invalid: 0, unknown: 0, _total: 0 };
        if (bucket[p][s] === undefined) bucket[p][s] = 0;
        bucket[p][s]++;
        bucket[p]._total++;
    }
    const providers = Object.keys(bucket).sort((a, b) => bucket[b]._total - bucket[a]._total);

    console.log(`=== Re-verified ${results.length} emails in ${elapsed}s ===\n`);
    console.log('provider                  safe  valid  catchall  invalid  unknown  total');
    for (const p of providers) {
        const b = bucket[p];
        console.log(`${p.slice(0, 24).padEnd(26)}${String(b.safe||0).padStart(4)}${String(b.valid||0).padStart(7)}${String(b.catch_all||0).padStart(10)}${String(b.invalid||0).padStart(9)}${String(b.unknown||0).padStart(9)}${String(b._total).padStart(7)}`);
    }

    console.log('\n=== unknown breakdown by provider (compare to pre-fix: 142 total) ===');
    const sortedByUnknown = providers.sort((a, b) => (bucket[b].unknown || 0) - (bucket[a].unknown || 0));
    let totalUnknown = 0;
    for (const p of sortedByUnknown) totalUnknown += bucket[p].unknown || 0;
    for (const p of sortedByUnknown) {
        const u = bucket[p].unknown || 0;
        if (!u) continue;
        console.log(`  ${p.slice(0, 24).padEnd(26)} ${String(u).padStart(4)}  ${(100 * u / (totalUnknown || 1)).toFixed(0)}%`);
    }
    console.log(`  TOTAL UNKNOWN: ${totalUnknown}`);
    const totals = { safe: 0, valid: 0, catch_all: 0, invalid: 0, unknown: 0 };
    for (const r of results) totals[r.status] = (totals[r.status] || 0) + 1;
    console.log(`\nOVERALL: safe=${totals.safe} valid=${totals.valid} catch_all=${totals.catch_all} invalid=${totals.invalid} unknown=${totals.unknown}`);
    console.log(`(Reoon target: valid≈23 catch_all≈57 invalid≈108 unknown≈58)`);
}

main().catch(e => { console.error('Failed:', e.message); process.exit(1); });
