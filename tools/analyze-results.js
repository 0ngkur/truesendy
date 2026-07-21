#!/usr/bin/env node
'use strict';

/**
 * tools/analyze-results.js — bucket TrueSendy results by status × MX provider.
 *
 *   node tools/analyze-results.js <truesendy_download.csv>      # downloaded CSV
 *   node tools/analyze-results.js /tmp/truesendy_job_<id>.jsonl # raw job file (VPS)
 *
 * Auto-detects CSV vs JSONL. The JSONL job file (written by appendResult) already
 * carries a `mxProvider` field per row, so no MX parsing is needed there.
 *
 * The "unknown" breakdown at the bottom is the ceiling diagnostic:
 *   Microsoft 365 dominating  -> recoverable via the M365 API path
 *   Google/Proofpoint/Barracuda -> hard SMTP ceiling (Reoon uses a mailbox DB)
 */
const fs = require('fs');
const csv = require('csv-parser');
const { identifyMxProvider } = require('../data/domainData');

const STATUSES = ['safe', 'valid', 'catch_all', 'invalid', 'unknown'];

function readCsv(file) {
    return new Promise((resolve, reject) => {
        const rows = []; let headers = [];
        fs.createReadStream(file).pipe(csv())
            .on('headers', h => { headers = h; })
            .on('data', r => rows.push(r))
            .on('error', reject)
            .on('end', () => resolve({ rows, headers }));
    });
}

function readJsonl(file) {
    const text = fs.readFileSync(file, 'utf8');
    const rows = text.split('\n').filter(Boolean).map(l => {
        try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
    return { rows, headers: rows[0] ? Object.keys(rows[0]) : [], isJsonl: true };
}

async function main() {
    const file = process.argv[2];
    if (!file) {
        console.error('Usage: node tools/analyze-results.js <truesendy.csv | job.jsonl>');
        process.exit(1);
    }

    // Detect format from the first non-empty line.
    const peek = fs.readFileSync(file, 'utf8').trim().split('\n')[0] || '';
    const isJsonl = peek.startsWith('{');
    const { rows, headers } = isJsonl ? readJsonl(file) : await readCsv(file);

    const statusCol = headers.find(h => /^status$/i.test(h)) || headers.find(h => /status/i.test(h)) || 'status';
    const mxProviderCol = headers.find(h => /^mxprovider$/i.test(h));
    const mxCol = headers.find(h => /mx_?records/i.test(h)) || headers.find(h => /^mx$/i.test(h));

    const bucket = {};
    let total = 0;
    for (const row of rows) {
        let status = String(row[statusCol] || 'unknown').toLowerCase().trim();
        if (!STATUSES.includes(status)) status = 'unknown';

        let provider;
        if (isJsonl && mxProviderCol) {
            // JSONL job rows carry mxProvider directly.
            provider = row[mxProviderCol] || '(none)';
        } else if (mxCol && row[mxCol]) {
            const hosts = String(row[mxCol]).split(/[;\n,]/).map(s => s.trim()).filter(Boolean);
            provider = (hosts.length && identifyMxProvider(hosts)) || '(unrecognized)';
        } else {
            provider = '(unknown)';
        }

        if (!bucket[provider]) {
            bucket[provider] = { safe: 0, valid: 0, catch_all: 0, invalid: 0, unknown: 0, _total: 0 };
        }
        bucket[provider][status]++;
        bucket[provider]._total++;
        total++;
    }

    const providers = Object.keys(bucket).sort((a, b) => bucket[b]._total - bucket[a]._total);
    const cols = ['safe', 'valid', 'catch_all', 'invalid', 'unknown', 'total'];

    console.log(`=== ${total} results across ${providers.length} providers (${isJsonl ? 'JSONL' : 'CSV'}) ===`);
    console.log("(rows = MX provider, columns = status)\n");
    console.log(['provider'.padEnd(24), ...cols.map(c => c.padEnd(11))].join(''));
    for (const p of providers) {
        const b = bucket[p];
        console.log([p.slice(0, 23).padEnd(24),
            ...cols.map(c => String(c === 'total' ? b._total : (b[c] || 0)).padStart(11))].join(''));
    }

    console.log('\n=== "unknown" breakdown by provider (the ceiling diagnostic) ===');
    const unknowns = providers
        .map(p => [p, bucket[p].unknown || 0])
        .filter(([, n]) => n > 0)
        .sort((a, b) => b[1] - a[1]);
    const totalUnknown = unknowns.reduce((s, [, n]) => s + n, 0);
    for (const [p, n] of unknowns) {
        const pct = totalUnknown ? (100 * n / totalUnknown).toFixed(0) : 0;
        console.log(`  ${p.slice(0, 30).padEnd(32)} ${String(n).padStart(5)}  ${pct.padStart(3)}%`);
    }
    console.log(`  ${'TOTAL UNKNOWN'.padEnd(32)} ${String(totalUnknown).padStart(5)}`);
    console.log('\nIf "Microsoft 365" dominates -> fixable via the M365 API path.');
    console.log('If "Google Workspace" / "Proofpoint" / "Barracuda" dominate -> hard SMTP ceiling.');
}

main().catch(e => { console.error('Failed:', e.message); process.exit(1); });
