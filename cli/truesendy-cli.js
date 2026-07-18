#!/usr/bin/env node
/**
 * TrueSendy CLI — Agency Email Verifier Tool v2.0
 * Owner  : Shakil
 * Dev    : Ikhtheir Jaman Ongkur
 * Web    : https://truesendy.com
 *
 * 1 token = 1 email verification. Tool REQUIRES a valid API key with tokens.
 * Buy API key: https://truesendy.com/key
 *
 * Supports: .csv  .txt  .xlsx  .xls
 * Output  : valid_emails.csv  (ONLY valid emails — clean list, ready to send)
 */

const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const readline = require('readline');

// ── CONFIG ──────────────────────────────────────────────────────────────────
const CONFIG_FILE = path.join(os.homedir(), '.truesendy.json');
const API_BASE    = process.env.TRUESENDY_HOST || 'https://truesendy.com';
const VERSION     = '2.0.0';

// ── COLORS ──────────────────────────────────────────────────────────────────
const C = {
    reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m',
    green:'\x1b[32m', red:'\x1b[31m', yellow:'\x1b[33m',
    blue:'\x1b[34m', cyan:'\x1b[36m', white:'\x1b[97m',
};
const c = (col, txt) => C[col] + txt + C.reset;

// ── BANNER ──────────────────────────────────────────────────────────────────
function printBanner() {
    console.log('');
    console.log(c('bold',c('cyan','  ████████╗██████╗ ██╗   ██╗███████╗███████╗███╗   ██╗██████╗ ██╗   ██╗')));
    console.log(c('bold',c('blue','  ╚══██╔══╝██╔══██╗██║   ██║██╔════╝██╔════╝████╗  ██║██╔══██╗╚██╗ ██╔╝')));
    console.log(c('bold',c('cyan','     ██║   ██████╔╝██║   ██║█████╗  ███████╗██╔██╗ ██║██║  ██║ ╚████╔╝')));
    console.log(c('bold',c('blue','     ██║   ██╔══██╗██║   ██║██╔══╝  ╚════██║██║╚██╗██║██║  ██║  ╚██╔╝')));
    console.log(c('bold',c('cyan','     ██║   ██║  ██║╚██████╔╝███████╗███████║██║ ╚████║██████╔╝   ██║')));
    console.log(c('bold',c('blue','     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝    ╚═╝')));
    console.log('');
    console.log(c('dim',`  Agency Email Verifier  v${VERSION}  |  1 token = 1 email`));
    console.log(c('dim','  Owner   : ') + c('white','Shakil'));
    console.log(c('dim','  Dev     : ') + c('white','Ikhtheir Jaman Ongkur'));
    console.log(c('dim','  Buy API : ') + c('cyan','truesendy.com/key'));
    console.log('');
}

// ── HTTP HELPER ──────────────────────────────────────────────────────────────
function apiRequest(method, endpoint, data, apiKey, timeoutMs) {
    // NEW-5: bulk verification can run for minutes; default to a long timeout for it.
    if (!timeoutMs) timeoutMs = endpoint === '/api/v1/verify-bulk' ? 300000 : 30000;
    return new Promise((resolve, reject) => {
        const host = getHost();
        const url  = new URL(host + endpoint);
        const isHttps = url.protocol === 'https:';
        const lib    = isHttps ? https : http;
        const body   = data ? JSON.stringify(data) : '';

        const opts = {
            hostname : url.hostname,
            port     : url.port || (isHttps ? 443 : 80),
            path     : url.pathname + url.search,
            method,
            headers  : {
                'Content-Type'  : 'application/json',
                'Content-Length': Buffer.byteLength(body),
                'X-API-Key'     : apiKey || '',
                'User-Agent'    : `TrueSendy-CLI/${VERSION}`,
            },
        };

        const req = lib.request(opts, res => {
            let raw = '';
            res.on('data', d => raw += d);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(raw) });
                } catch {
                    // Not JSON — usually a parked/wrong domain serving HTML.
                    const looksHtml = /<\s*(html|!doctype|script)/i.test(raw);
                    resolve({ status: res.statusCode, data: { error: looksHtml
                        ? `The server at ${host} did NOT return a TrueSendy response — wrong server URL. Run: TrueSendy set-host <url>  (local testing: http://localhost:3000)`
                        : ('Unexpected server response: ' + raw.slice(0, 120)) } });
                }
            });
        });

        req.on('error', () => reject(new Error(`Could not reach the TrueSendy server at ${host}. If testing locally, run:  TrueSendy set-host http://localhost:3000`)));
        req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error(`Connection timed out reaching ${host}. Wrong server URL? Run:  TrueSendy set-host <url>`)); });
        if (body) req.write(body);
        req.end();
    });
}

// ── CONFIG ───────────────────────────────────────────────────────────────────
function loadConfig() {
    try { if (fs.existsSync(CONFIG_FILE)) return JSON.parse(fs.readFileSync(CONFIG_FILE,'utf8')); } catch {}
    return {};
}
function saveConfig(cfg) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2)); }

// Resolve the server host: --host flag > saved config > production default.
function getHost() {
    return process.env.TRUESENDY_HOST || loadConfig().host || API_BASE;
}

// Interactive prompt helper. Returns trimmed answer (or defaultValue if empty).
function ask(question, defaultValue) {
    return new Promise(resolve => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        const suffix = defaultValue ? c('dim', ` [${defaultValue}]`) : '';
        rl.question(question + suffix + ' ', ans => { rl.close(); resolve((ans || '').trim()); });
    });
}

// ── EMAIL PARSER — CSV / TXT / XLSX / XLS ────────────────────────────────────
function parseEmailsFromFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();

    // ── Excel files ──────────────────────────────────────────────────────────
    if (ext === '.xlsx' || ext === '.xls') {
        let XLSX;
        try { XLSX = require('./node_modules/xlsx'); }
        catch { die('Excel support requires xlsx package. Run: npm install xlsx inside the cli folder.'); }

        const wb    = XLSX.readFile(filePath);
        const emails = [];

        for (const sheetName of wb.SheetNames) {
            const rows = XLSX.utils.sheet_to_json(wb.Sheets[sheetName], { header:1, defval:'' });
            for (const row of rows) {
                for (const cell of row) {
                    const val = String(cell || '').trim();
                    if (looksLikeEmail(val)) emails.push(val.toLowerCase());
                }
            }
        }
        return [...new Set(emails)];
    }

    // ── CSV / TXT — split on common delimiters ───────────────────────────────
    const raw = fs.readFileSync(filePath, 'utf8');
    const tokens = raw.split(/[\r\n,;\t|]+/);
    const emails = tokens
        .map(t => t.trim().replace(/^["']|["']$/g,'').trim())
        .filter(looksLikeEmail)
        .map(e => e.toLowerCase());

    return [...new Set(emails)];
}

function looksLikeEmail(str) {
    // Solid basic RFC-ish check
    return typeof str === 'string'
        && str.length >= 6
        && str.length <= 254
        && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(str);
}

function die(msg) {
    console.log('\n' + c('red','  ✗ ' + msg));
    console.log(c('yellow','  → Buy API: truesendy.com/key\n'));
    process.exit(1);
}

// ── TOKEN GUARD — hard block if tokens = 0 ───────────────────────────────────
async function requireTokens(apiKey, need) {
    process.stdout.write(c('dim','  Checking API key... '));
    const res = await apiRequest('GET','/api/v1/balance',null,apiKey)
        .catch(e => ({ data:{ error: e.message } }));

    if (res.data.error) {
        console.log('');
        die(res.data.error);
    }

    const { tokens, daysRemaining, expiresAt } = res.data;

    if (tokens === 0) {
        console.log('');
        console.log(c('red','\n  ✗ Your API key has 0 tokens remaining.'));
        console.log(c('yellow','  → This tool will NOT work without tokens.'));
        console.log(c('cyan','  → Purchase a new API key: truesendy.com/key\n'));
        process.exit(1);
    }

    if (need && tokens < need) {
        console.log('');
        console.log(c('red',`\n  ✗ Not enough tokens. Need ${need.toLocaleString()}, have ${tokens.toLocaleString()}.`));
        console.log(c('yellow','  → Purchase a new API key to top up.'));
        console.log(c('cyan','  → truesendy.com/key\n'));
        process.exit(1);
    }

    console.log(c('green','OK'));
    console.log(c('dim',`  Tokens: ${c('cyan',tokens.toLocaleString())} remaining | Expires in ${daysRemaining} days`));
    if (daysRemaining <= 5) {
        console.log(c('yellow',`  ⚠️  Key expires soon! Renew at truesendy.com/key`));
    }
    console.log('');
    return tokens;
}

// ── COMMANDS ──────────────────────────────────────────────────────────────────

async function cmdSetKey(key) {
    if (!key || !key.startsWith('ts_')) die('Invalid API key. Keys start with ts_');

    const cfg = loadConfig();
    cfg.apiKey = key;
    saveConfig(cfg);
    console.log(c('green','  ✓ API key saved locally. Testing connection...'));

    const res = await apiRequest('GET','/api/v1/balance',null,key).catch(() => null);
    if (!res || res.data.error) {
        console.log(c('red','  ✗ ' + (res?.data?.error || 'Could not connect to truesendy.com')));
        console.log(c('yellow','  → Make sure you have internet access and a valid Agency key.\n'));
        process.exit(1);
    }

    const { tokens, tokensUsed, daysRemaining } = res.data;
    if (tokens === 0) {
        console.log(c('yellow','  ⚠️  Key saved BUT has 0 tokens. Purchase tokens at truesendy.com/key'));
    } else {
        console.log(c('green','  ✓ Connected!'));
    }

    console.log(c('bold','\n  📊 Key Status'));
    console.log('  ' + '─'.repeat(36));
    console.log('  Tokens    : ' + c('cyan', tokens.toLocaleString()));
    console.log('  Used      : ' + c('dim',  tokensUsed.toLocaleString()));
    console.log('  Expires   : ' + c('dim',  daysRemaining + ' days remaining'));
    console.log('');
}

async function cmdBalance(apiKey) {
    const res = await apiRequest('GET','/api/v1/balance',null,apiKey)
        .catch(e => ({ data:{ error: e.message } }));

    if (res.data.error) die(res.data.error);

    const { tokens, tokensUsed, expiresAt, daysRemaining } = res.data;

    console.log(c('bold','  📊 API Key Balance'));
    console.log('  ' + '─'.repeat(40));
    console.log('  Tokens remaining : ' + c('bold',c('cyan', tokens.toLocaleString())));
    console.log('  Tokens used      : ' + c('yellow', tokensUsed.toLocaleString()));
    console.log('  Expires          : ' + c('dim', expiresAt));
    console.log('  Days remaining   : ' + (daysRemaining <= 3
        ? c('red', daysRemaining + ' days ⚠️  RENEW NOW')
        : c('green', daysRemaining + ' days')));

    if (tokens === 0) {
        console.log('');
        console.log(c('red','  ✗ ZERO TOKENS — tool is locked until you buy a new key.'));
        console.log(c('cyan','  → truesendy.com/key'));
    }
    console.log('');
}

async function cmdVerify(email, apiKey) {
    if (!looksLikeEmail(email)) die('Invalid email address: ' + email);

    // Token guard
    await requireTokens(apiKey, 1);

    process.stdout.write(c('dim','  Verifying ' + email + '... '));
    const res = await apiRequest('POST','/api/v1/verify',{ email },apiKey)
        .catch(e => ({ data:{ error: e.message } }));

    if (res.data.error) die(res.data.error);

    const r = res.data;
    const isValid = r.status === 'valid';
    console.log(isValid ? c('green','✓ VALID') : c('red','✗ INVALID'));
    console.log('');
    console.log(c('bold','  📧 Result'));
    console.log('  ' + '─'.repeat(36));
    console.log('  Email    : ' + c('white', r.email));
    console.log('  Status   : ' + (isValid ? c('green','VALID') : c('red', r.status.toUpperCase())));
    console.log('  Reason   : ' + c('dim', r.reason || '—'));
    console.log('  Provider : ' + c('cyan', r.provider || '—'));
    console.log('  Category : ' + c('dim', r.category || '—'));
    if (r.flags) {
        const f = Object.entries(r.flags).filter(([,v])=>v).map(([k])=>k);
        if (f.length) console.log('  Flags    : ' + c('yellow', f.join(', ')));
    }
    console.log('  Tokens ← : ' + c('dim', (r.tokensRemaining||0).toLocaleString() + ' left'));
    console.log('');
}

async function cmdVerifyBulk(filePath, apiKey, outPath, outInvalidPath) {
    // ── Parse file ───────────────────────────────────────────────────────────
    if (!filePath) die('No file specified. Example: TrueSendy verify-bulk emails.csv');
    if (!fs.existsSync(filePath)) die('File not found: ' + filePath);

    const ext = path.extname(filePath).toLowerCase();
    const supported = ['.csv','.txt','.xlsx','.xls'];
    if (!supported.includes(ext)) die('Unsupported file type: ' + ext + '. Use: ' + supported.join(' '));

    console.log(c('dim','  Reading ' + path.basename(filePath) + '...'));
    let emails;
    try { emails = parseEmailsFromFile(filePath); }
    catch (e) { die('Could not read file: ' + e.message); }

    if (!emails.length) die('No valid email addresses found in the file.');

    console.log(c('green','  ✓ ') + c('bold', emails.length.toLocaleString()) + ' unique emails loaded');
    console.log('');

    // ── Token guard ──────────────────────────────────────────────────────────
    await requireTokens(apiKey, emails.length);

    // ── Verify in batches of 100 ─────────────────────────────────────────────
    const BATCH = 100;
    const allResults = [];
    let done = 0;

    const startTime = Date.now();

    for (let i = 0; i < emails.length; i += BATCH) {
        const batch = emails.slice(i, i + BATCH);
        const pct   = Math.round((done / emails.length) * 100);

        process.stdout.write(
            `\r  ${c('cyan','▶')} Verifying... ${c('bold', pct + '%')}  ` +
            `(${done}/${emails.length})  ${c('dim', estimateTime(startTime, done, emails.length))}`
        );

        const res = await apiRequest('POST','/api/v1/verify-bulk',{ emails: batch },apiKey)
            .catch(e => ({ data:{ error: e.message } }));

        if (res.data.error) {
            console.log('');
            // Check if it's a token exhaustion mid-run
            if (res.data.error.includes('token')) {
                console.log(c('red','\n  ✗ Ran out of tokens mid-run!'));
                console.log(c('yellow','  → Partial results saved. Buy more tokens: truesendy.com/key'));
                // Save partial
                if (allResults.length) saveResults(allResults, filePath, outPath, outInvalidPath);
                process.exit(1);
            }
            die(res.data.error);
        }

        allResults.push(...(res.data.results || []));
        done += batch.length;
    }

    process.stdout.write(`\r  ${c('green','✓')} Done!  (${done}/${emails.length})                               \n\n`);

    // ── Stats (3-category: valid / invalid / unknown) ────────────────────────
    const valid   = allResults.filter(r => r.status === 'valid');
    const invalid = allResults.filter(r => r.status === 'invalid');
    const unknown = allResults.filter(r => r.status === 'unknown');
    const pct     = ((valid.length / allResults.length) * 100).toFixed(1);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const tokLeft = allResults[allResults.length-1]?.tokensRemaining ?? '?';

    console.log(c('bold','  📊 Verification Results'));
    console.log('  ' + '─'.repeat(44));
    console.log('  Total checked  : ' + c('white', allResults.length.toLocaleString()));
    console.log('  ✓ Valid        : ' + c('green', valid.length.toLocaleString() + '  (' + pct + '%)'));
    console.log('  ✗ Invalid      : ' + c('red',   invalid.length.toLocaleString()));
    console.log('  ? Unknown      : ' + c('yellow', unknown.length.toLocaleString()));
    console.log('  ⏱ Time         : ' + c('dim', elapsed + 's'));
    console.log('  Tokens left    : ' + (tokLeft === 0
        ? c('red','0  ← Buy a new key at truesendy.com/key')
        : c('cyan', String(tokLeft).toLocaleString())));
    console.log('');

    // ── Save files ───────────────────────────────────────────────────────────
    saveResults(allResults, filePath, outPath, outInvalidPath);

    if (tokLeft === 0) {
        console.log(c('red','  ✗ Token balance is now ZERO.'));
        console.log(c('yellow','  → Purchase a new API key to continue: truesendy.com/key\n'));
    }
}

function saveResults(allResults, filePath, outPath, outInvalidPath) {
    const base    = filePath.replace(/\.[^.]+$/,'');
    const stamp   = Date.now();

    const valid   = allResults.filter(r => r.status === 'valid');
    const invalid = allResults.filter(r => r.status === 'invalid');
    const unknown = allResults.filter(r => r.status === 'unknown');

    // ── VALID-ONLY clean list (primary output) ───────────────────────────────
    const validFile = outPath || (base + '_VALID_' + stamp + '.csv');
    const validLines = [
        'Email,Provider,Reason',
        ...valid.map(r =>
            `"${r.email}","${r.provider||''}","${r.reason||''}"`
        )
    ];
    fs.writeFileSync(validFile, validLines.join('\n'), 'utf8');
    console.log(c('green','  ✓ VALID emails saved  : ') + c('bold', validFile));
    console.log(c('dim',  '    ' + valid.length.toLocaleString() + ' emails — ready to send ✈️'));

    // ── INVALID list (confirmed non-existent) ────────────────────────────────
    const invalidFile = outInvalidPath || (base + '_INVALID_' + stamp + '.csv');
    const invalidLines = [
        'Email,Status,Reason',
        ...invalid.map(r =>
            `"${r.email}","${r.status}","${r.reason||''}"`
        )
    ];
    fs.writeFileSync(invalidFile, invalidLines.join('\n'), 'utf8');
    console.log(c('red','  ✗ INVALID emails saved : ') + c('dim', invalidFile));
    console.log(c('dim','    ' + invalid.length.toLocaleString() + ' confirmed non-existent'));

    // ── UNKNOWN list (unverifiable — couldn't confirm either way) ─────────────
    if (unknown.length) {
        const unknownFile = base + '_UNKNOWN_' + stamp + '.csv';
        const unknownLines = [
            'Email,Status,Reason',
            ...unknown.map(r =>
                `"${r.email}","${r.status}","${r.reason||''}"`
            )
        ];
        fs.writeFileSync(unknownFile, unknownLines.join('\n'), 'utf8');
        console.log(c('yellow','  ? UNKNOWN emails saved : ') + c('dim', unknownFile));
        console.log(c('dim','    ' + unknown.length.toLocaleString() + ' unverifiable — review manually'));
    }
    console.log('');
}

function estimateTime(startTime, done, total) {
    if (done === 0) return '';
    const elapsed = (Date.now() - startTime) / 1000;
    const rate    = done / elapsed;
    const left    = Math.ceil((total - done) / rate);
    if (left < 60) return `~${left}s left`;
    return `~${Math.ceil(left/60)}m left`;
}

// ── HELP ──────────────────────────────────────────────────────────────────────
function printHelp() {
    console.log(c('bold','  Commands'));
    console.log('  ' + '─'.repeat(36));
    console.log('  ' + c('cyan','set-key') + ' <ts_xxx...>      Save API key (run once)');
    console.log('  ' + c('cyan','balance') + '                  Check token balance');
    console.log('  ' + c('cyan','verify') + ' <email>           Verify one email (1 token)');
    console.log('  ' + c('cyan','verify-bulk') + ' <file>       Verify emails from file');
    console.log('');
    console.log(c('bold','  Supported File Types'));
    console.log('  ' + '─'.repeat(36));
    console.log('  .csv   Comma-separated, one column or many');
    console.log('  .txt   One email per line');
    console.log('  .xlsx  Excel spreadsheet — all sheets scanned');
    console.log('  .xls   Legacy Excel — all sheets scanned');
    console.log('');
    console.log(c('bold','  Output Files'));
    console.log('  ' + '─'.repeat(36));
    console.log('  <file>_VALID_<ts>.csv    ← ONLY valid emails (clean list)');
    console.log('  <file>_INVALID_<ts>.csv  ← removed/bad emails');
    console.log('');
    console.log(c('bold','  Options'));
    console.log('  --key <ts_xxx>    Use key just for this command');
    console.log('  --host <url>      Override API server (default: truesendy.com)');
    console.log('  --out <file>      Custom output file for valid emails');
    console.log('');
    console.log(c('bold','  Examples'));
    console.log(c('dim','  TrueSendy set-key ts_abc123def456...'));
    console.log(c('dim','  TrueSendy balance'));
    console.log(c('dim','  TrueSendy verify hello@gmail.com'));
    console.log(c('dim','  TrueSendy verify-bulk mylist.csv'));
    console.log(c('dim','  TrueSendy verify-bulk mylist.xlsx'));
    console.log(c('dim','  TrueSendy verify-bulk mylist.txt --out clean.csv'));
    console.log('');
    console.log(c('bold','  Token Rules'));
    console.log('  1 token = 1 email checked');
    console.log('  Tool is LOCKED when tokens = 0');
    console.log('  Keys expire after 30 days');
    console.log('  Buy / renew: ' + c('cyan','truesendy.com/key'));
    console.log('');
}

// ── SET-HOST ─────────────────────────────────────────────────────────────────
// Point the bot at a specific TrueSendy server (local testing or custom deploy).
// Usage: TrueSendy set-host http://localhost:3000
async function cmdSetHost(url) {
    if (!url) die('Usage: TrueSendy set-host <url>   (e.g. http://localhost:3000)');
    url = url.replace(/\/+$/, '');
    const cfg = loadConfig(); cfg.host = url; saveConfig(cfg);
    console.log(c('green', `  ✓ Server URL set to ${url}\n`));
}

// ── FIRST-RUN ONBOARDING ─────────────────────────────────────────────────────
// When no key is saved, interactively prompt for one, validate it against the
// server, and save it. Delivers the "install → asks for key → paste → unlock"
// flow. Returns the validated key so the calling command can proceed immediately.
async function onboardKey() {
    if (!process.stdin.isTTY) {
        console.log(c('red','  ✗ No API key set up yet.'));
        console.log(c('cyan','  → Run:  TrueSendy set-key <your-key>     (and  TrueSendy set-host <url>  if testing locally)\n'));
        process.exit(1);
    }
    console.log(c('yellow','  👋 Welcome — let\'s connect TrueSendy.\n'));

    // 1) Server URL — works for local testing (http://localhost:3000) OR production.
    const savedHost = loadConfig().host || API_BASE;
    const hostIn    = await ask(c('bold','  1) TrueSendy server URL'), savedHost);
    const host      = (hostIn || savedHost).replace(/\/+$/, '');
    process.env.TRUESENDY_HOST = host;   // so the validation call below hits the right server

    // 2) API key (buy at truesendy.com/key)
    for (let attempt = 0; attempt < 3; attempt++) {
        const key = await ask(c('bold','  2) Your TrueSendy key (ts_...)'));
        if (!key.startsWith('ts_')) {
            console.log(c('red','  ✗ Keys start with "ts_" — buy one at truesendy.com/key.\n'));
            continue;
        }
        process.stdout.write(c('dim','  Connecting... '));
        const res = await apiRequest('GET','/api/v1/balance',null,key).catch(e => ({ data:{ error: e.message } }));
        if (!res || res.data.error) {
            console.log(c('red','✗ ' + (res?.data?.error || 'Could not reach the server.')));
            console.log(c('yellow','  → Check the Server URL + key, then retry.\n'));
            continue;
        }
        const cfg = loadConfig(); cfg.host = host; cfg.apiKey = key; saveConfig(cfg);
        console.log(c('green','✓ Connected!') + c('dim', `  ${Number(res.data.tokens).toLocaleString()} tokens available.`));
        console.log(c('green','\n  ✅ All set. Verify emails with:'));
        console.log(c('cyan','     TrueSendy verify-bulk your_emails.csv\n'));
        return key;
    }
    console.log(c('red','  ✗ Setup incomplete. Re-run, or: TrueSendy set-key <key>\n'));
    process.exit(1);
}

// ── MAIN ──────────────────────────────────────────────────────────────────────
async function main() {
    const args       = process.argv.slice(2);
    const flags      = {};
    const positional = [];

    for (let i = 0; i < args.length; i++) {
        if (args[i].startsWith('--')) {
            const k    = args[i].slice(2);
            flags[k]   = (args[i+1] && !args[i+1].startsWith('--')) ? args[++i] : true;
        } else {
            positional.push(args[i]);
        }
    }

    if (flags.host) process.env.TRUESENDY_HOST = flags.host;

    const cmd = positional[0];
    printBanner();

    if (!cmd || cmd === 'help' || flags.help || flags.h) { printHelp(); return; }

    // set-key / set-host don't need a stored key
    if (cmd === 'set-host') { await cmdSetHost(positional[1] || flags.host); return; }
    if (cmd === 'set-key') { await cmdSetKey(positional[1] || flags.key); return; }

    // Every other command REQUIRES a valid key with tokens. If none is saved,
    // interactively onboard the user (prompt → validate → save → unlock).
    const cfg    = loadConfig();
    let apiKey   = flags.key || cfg.apiKey;
    if (!apiKey) {
        apiKey = await onboardKey();
    }

    switch (cmd) {
        case 'balance':
            await cmdBalance(apiKey);
            break;

        case 'verify':
            await cmdVerify(positional[1], apiKey);
            break;

        case 'verify-bulk':
            await cmdVerifyBulk(positional[1], apiKey, flags.out, flags['out-invalid']);
            break;

        default:
            console.log(c('red','  ✗ Unknown command: ' + cmd + '\n'));
            printHelp();
            process.exit(1);
    }
}

main().catch(err => {
    console.error(c('red','\n  ✗ Fatal: ' + err.message));
    process.exit(1);
});
