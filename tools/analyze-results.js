#!/usr/bin/env node
'use strict';

/**
 * tools/analyze-results.js — bucket a TrueSendy result CSV by status × MX provider.
 *
 *   node tools/analyze-results.js <truesendy_download.csv>
 *
 * Reveals which mail providers dominate the "unknown" bucket (the SMTP ceiling:
 * Google / federated-M365 / Proofpoint / Barracuda) vs Microsoft 365 (which has
 * an API and is recoverable). The "unknown" breakdown at the bottom is the bit
 * that decides whether the gap is fixable (M365 API) or a hard ceiling.
 */
const fs = require('fs');
const csv = require('csv-parser');
const { identifyMxProvider } = require('../data/domainData');

const STATUSES = ['safe', 'valid', 'catch_all', 'invalid', 'unknown'];

function readCsv(file) {
    return new Promise((resolve, reject) => {
        const rows = [];
        let headers = [];
        fs.createReadStream(file).pipe(csv())
            .on('headers', h => { headers = h; })
            .on('data', r => rows.push(r))
            .on('error', reject)
            .on('end', () => resolve({ rows, headers }));
    });
}

async function main() {
    const file = process.argv[2];
    if (!file) {
        console.error('Usage: node tools/analyze-results.js <truesendy.csv>');
        process.exit(1);
    }
    const { rows, headers } = await readCsv(file);
    const statusCol = headers.find(h => /status/i.test(h)) || 'status';
    const mxCol = headers.find(h => /mx_?records/i.test(h)) ||
                  headers.find(h => /^mx$/i.test(h)) || null;

    const bucket = {};
    let total = 0;
    for (const row of rows) {
        let status = (row[statusCol] || 'unknown').toString().toLowerCase().trim();
        if (!STATUSES.includes(status)) status = 'unknown';
        let provider = '(no mx)';
        if (mxCol && row[mxCol]) {
            const hosts = String(row[mxCol]).split(/[;\n,]/).map(s => s.trim()).filter(Boolean);
            if (hosts.length) provider = identifyMxProvider(hosts) || '(unrecognized)';
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

    console.log(`=== ${total} results across ${providers.length} providers ===`);
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
