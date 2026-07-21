#!/usr/bin/env node
'use strict';

/**
 * tools/diff-vs-reoon.js — compare TrueSendy verification output against Reoon's
 * for the SAME input list, email by email.
 *
 *   node tools/diff-vs-reoon.js <truesendy.csv> <reoon.csv> [--full]
 *   node tools/diff-vs-reoon.js --selftest
 *
 * Prints: detected columns, row/intersection counts, per-bucket distribution
 * (the key metric for "does TrueSendy match Reoon now"), agreement %, a
 * confusion matrix, and the list of disagreeing emails with both raw statuses.
 *
 * Statuses from both vocabularies are canonicalized to:
 *   valid | catch_all | invalid | unknown
 * ("spamtrap" is Reoon-only and excluded from agreement — TrueSendy has no
 *  equivalent. Disposable/Inbox Full are treated as deliverable → valid.)
 */
const fs = require('fs');
const csv = require('csv-parser');

const CANON_BUCKETS = ['valid', 'catch_all', 'invalid', 'unknown'];

/**
 * Canonicalize a verification status (TrueSendy or Reoon vocabulary) into one of:
 * 'valid' | 'catch_all' | 'invalid' | 'unknown' | 'spamtrap'.
 */
function canon(status) {
    const s = String(status || '').toLowerCase().trim();
    if (!s) return 'unknown';
    if (s.includes('catch') || s.includes('accept-all') || s.includes('accept all') || s === 'catchall') return 'catch_all';
    if (s.includes('spam') && s.includes('trap')) return 'spamtrap';
    if (s.includes('invalid') || s.includes('undeliver') || s.includes('disable') ||
        s.includes('not found') || s.includes('no mailbox')) return 'invalid';
    if (s === 'safe' || s === 'valid' || s === 'role' ||
        s.includes('valid') || s.includes('safe') || s.includes('deliverab') ||
        s.includes('disposable') || s.includes('inbox') || s.includes('full')) return 'valid';
    if (s.includes('unknown') || s.includes('risky') || s.includes('unverif') || s.includes('temporary')) return 'unknown';
    return 'unknown';
}

/**
 * Detect the email and status columns from CSV headers. Tries a strict email
 * match first, then a looser fallback. Status prefers "verification status",
 * then "status", then "result", then anything "verif*".
 */
function detectColumns(headers) {
    const emailCol =
        headers.find(h => /(^|_)e-?mail($|_)/i.test(h)) ||
        headers.find(h => /e-?mail/i.test(h)) ||
        headers.find(h => /mail/i.test(h)) ||
        null;
    const statusCol =
        headers.find(h => /verif/i.test(h) && /status/i.test(h)) ||
        headers.find(h => /status/i.test(h)) ||
        headers.find(h => /^result$|results/i.test(h)) ||
        headers.find(h => /verif/i.test(h)) ||
        null;
    return { emailCol, statusCol };
}

function readCsv(file) {
    return new Promise((resolve, reject) => {
        const rows = [];
        let headers = [];
        fs.createReadStream(file)
            .pipe(csv())
            .on('headers', h => { headers = h; })
            .on('data', row => rows.push(row))
            .on('error', reject)
            .on('end', () => resolve({ rows, headers }));
    });
}

function normEmail(e) {
    return String(e || '').trim().toLowerCase();
}

function buildMap(rows, emailCol, statusCol) {
    const m = new Map();
    for (const row of rows) {
        const e = normEmail(row[emailCol]);
        if (!e || !e.includes('@')) continue;
        m.set(e, (row[statusCol] || '').toString());
    }
    return m;
}

function distribution(map) {
    const d = { valid: 0, catch_all: 0, invalid: 0, unknown: 0, spamtrap: 0 };
    for (const raw of map.values()) d[canon(raw)]++;
    return d;
}

async function compare(tsFile, reoonFile, { full = false } = {}) {
    const ts = await readCsv(tsFile);
    const reoon = await readCsv(reoonFile);
    const tsCols = detectColumns(ts.headers);
    const reoonCols = detectColumns(reoon.headers);

    const lines = [];
    const log = (...a) => { lines.push(a.join(' ')); };

    log('=== TrueSendy vs Reoon — per-email diff ===\n');
    log(`TrueSendy: ${ts.rows.length} rows | columns: ${tsCols.emailCol || '<no email col>'} / ${tsCols.statusCol || '<no status col>'}`);
    log(`Reoon:     ${reoon.rows.length} rows | columns: ${reoonCols.emailCol || '<no email col>'} / ${reoonCols.statusCol || '<no status col>'}\n`);

    if (!tsCols.emailCol || !tsCols.statusCol || !reoonCols.emailCol || !reoonCols.statusCol) {
        log('ERROR: could not auto-detect email/status columns. Edit detectColumns or rename columns.');
        log(`TrueSendy headers: ${ts.headers.join(', ')}`);
        log(`Reoon headers:     ${reoon.headers.join(', ')}`);
        return lines.join('\n');
    }

    const tsMap = buildMap(ts.rows, tsCols.emailCol, tsCols.statusCol);
    const reoonMap = buildMap(reoon.rows, reoonCols.emailCol, reoonCols.statusCol);

    const onlyTs = [...tsMap.keys()].filter(e => !reoonMap.has(e)).length;
    const onlyReoon = [...reoonMap.keys()].filter(e => !tsMap.has(e)).length;
    const common = [...tsMap.keys()].filter(e => reoonMap.has(e));
    log(`Emails: ${tsMap.size} in TrueSendy, ${reoonMap.size} in Reoon, ${common.length} in common.`);
    log(`Only in TrueSendy: ${onlyTs} | Only in Reoon: ${onlyReoon}\n`);

    // Distribution over the COMMON set (apples-to-apples).
    const tsCommon = new Map(common.map(e => [e, tsMap.get(e)]));
    const reoonCommon = new Map(common.map(e => [e, reoonMap.get(e)]));
    const tsDist = distribution(tsCommon);
    const reoonDist = distribution(reoonCommon);

    log('--- Distribution (over common emails) ---');
    log('bucket       TrueSendy  Reoon    Δ');
    for (const b of CANON_BUCKETS) {
        const dt = tsDist[b], dr = reoonDist[b];
        log(`${b.padEnd(12)} ${String(dt).padStart(6)}     ${String(dr).padStart(5)}  ${String(dr - dt).padStart(5)}`);
    }
    if (tsDist.spamtrap || reoonDist.spamtrap) log(`spamtrap*     ${String(tsDist.spamtrap).padStart(6)}     ${String(reoonDist.spamtrap).padStart(5)}  (* excluded from agreement)`);
    log('');

    // Confusion matrix + agreement (exclude Reoon spamtrap).
    const matrix = {};
    for (const t of CANON_BUCKETS) { matrix[t] = {}; for (const r of CANON_BUCKETS) matrix[t][r] = 0; }
    let compared = 0, agree = 0, excluded = 0;
    const disagrees = [];
    for (const e of common) {
        const tc = canon(tsMap.get(e));
        const rc = canon(reoonMap.get(e));
        if (rc === 'spamtrap' || tc === 'spamtrap') { excluded++; continue; }
        compared++;
        if (CANON_BUCKETS.includes(tc)) matrix[tc][rc]++;
        if (tc === rc) agree++;
        else disagrees.push({ email: e, ts: tsMap.get(e), tsCanon: tc, reoon: reoonMap.get(e), reoonCanon: rc });
    }
    const pct = compared ? (100 * agree / compared) : 0;
    log(`--- Agreement: ${agree}/${compared} = ${pct.toFixed(1)}%${excluded ? ` (${excluded} spamtrap excluded)` : ''} ---\n`);

    log('--- Confusion matrix (rows=TrueSendy, cols=Reoon) ---');
    log(`${' '.repeat(11)}${CANON_BUCKETS.map(b => b.padStart(11)).join('')}`);
    for (const t of CANON_BUCKETS) {
        log(`${t.padEnd(11)}${CANON_BUCKETS.map(r => String(matrix[t][r]).padStart(11)).join('')}`);
    }
    log('');

    log(`--- Disagreements: ${disagrees.length} (showing ${full ? 'all' : Math.min(disagrees.length, 40)}) ---`);
    log('TrueSendy→bucket   Reoon→bucket        email');
    const shown = full ? disagrees : disagrees.slice(0, 40);
    // Sort by disagreement type to make tuning classify.js easier.
    shown.sort((a, b) => (a.tsCanon + '>' + a.reoonCanon).localeCompare(b.tsCanon + '>' + b.reoonCanon));
    for (const d of shown) {
        log(`${(d.tsCanon.padEnd(7) + '(' + (d.ts || '').slice(0, 14) + ')').padEnd(25)}${(d.reoonCanon.padEnd(7) + '(' + (d.reoon || '').slice(0, 14) + ')').padEnd(20)} ${d.email}`);
    }
    return lines.join('\n');
}

async function main() {
    const argv = process.argv.slice(2);
    if (argv[0] === '--selftest') return selftest();
    const full = argv.includes('--full');
    const files = argv.filter(a => !a.startsWith('--'));
    if (files.length < 2) {
        console.error('Usage: node tools/diff-vs-reoon.js <truesendy.csv> <reoon.csv> [--full]');
        console.error('       node tools/diff-vs-reoon.js --selftest');
        process.exit(1);
    }
    try {
        console.log(await compare(files[0], files[1], { full }));
    } catch (e) {
        console.error('Failed:', e.message);
        process.exit(1);
    }
}

function selftest() {
    const assert = require('node:assert');
    const cases = [
        ['Valid', 'valid'], ['Safe', 'valid'], ['Role', 'valid'],
        ['safe', 'valid'], ['valid', 'valid'],
        ['Catch All', 'catch_all'], ['catch_all', 'catch_all'], ['accept-all', 'catch_all'],
        ['Invalid', 'invalid'], ['invalid', 'invalid'], ['Disabled', 'invalid'],
        ['Unknown', 'unknown'], ['unknown', 'unknown'], ['', 'unknown'],
        ['Disposable', 'valid'], ['Inbox Full', 'valid'],
        ['Spam Trap', 'spamtrap'],
    ];
    for (const [inp, exp] of cases) {
        assert.equal(canon(inp), exp, `canon(${JSON.stringify(inp)})`);
    }
    assert.ok(detectColumns(['email', 'status']).emailCol);
    assert.equal(detectColumns(['Email', 'Verification_Status']).statusCol, 'Verification_Status');
    console.log('selftest OK');
}

module.exports = { canon, detectColumns, compare };
if (require.main === module) main();
