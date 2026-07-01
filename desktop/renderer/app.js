// TrueSendy Desktop — renderer logic. Thin API client over the TrueSendy server.
// Uses the preload bridge (window.ts) for native ops + fetch() for the API.
const $ = (id) => document.getElementById(id);

let auth = { mode: null, token: null, key: null };   // mode: 'token' | 'key'
let cfg   = { host: 'https://truesendy.com' };
let currentEmails = [];
let lastResults   = [];

// ── init ─────────────────────────────────────────────────────────────────────
(async function init() {
    const saved = await window.ts.configGet();
    if (saved.host) cfg.host = saved.host.replace(/\/+$/, '');
    $('host-input').value = cfg.host;

    if (saved.token)      { auth = { mode: 'token', token: saved.token }; showMain(); }
    else if (saved.key)   { auth = { mode: 'key',    key:    saved.key   }; showMain(); }
    else                    showAuth();
})();

async function saveCfg() {
    const out = { host: cfg.host };
    if (auth.mode === 'token') out.token = auth.token;
    if (auth.mode === 'key')   out.key   = auth.key;
    await window.ts.configSet(out);
}

function authHeaders() {
    const h = { 'Content-Type': 'application/json' };
    if (auth.mode === 'key') h['X-API-Key'] = auth.key;
    else                     h['Authorization'] = 'Bearer ' + auth.token;
    return h;
}

function showAuth() {
    $('auth-view').style.display = '';
    $('main-view').style.display = 'none';
}
function showMain() {
    $('auth-view').style.display = 'none';
    $('main-view').style.display = '';
    loadBalance();
}

// ── auth tabs ────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    const tab = t.dataset.tab;
    $('pane-login').style.display = tab === 'login' ? '' : 'none';
    $('pane-key').style.display   = tab === 'key'   ? '' : 'none';
    $('auth-err').textContent = '';
}));

// ── login (email + password) ─────────────────────────────────────────────────
$('li-btn').addEventListener('click', async () => {
    const email = $('li-email').value.trim();
    const password = $('li-pass').value;
    const errEl = $('auth-err'); errEl.textContent = '';
    if (!email || !password) { errEl.textContent = 'Enter your email and password.'; return; }
    $('li-btn').disabled = true;
    try {
        const r = await fetch(cfg.host + '/api/auth/login', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        }).then(r => r.json());
        if (r.error) { errEl.textContent = r.error; return; }
        auth = { mode: 'token', token: r.token };
        await saveCfg();
        showMain();
    } catch (e) {
        errEl.textContent = `Can't reach ${cfg.host}. Open Settings (⚙) and check the server URL.`;
    } finally {
        $('li-btn').disabled = false;
    }
});

// ── activate key ─────────────────────────────────────────────────────────────
$('key-btn').addEventListener('click', async () => {
    const key = $('key-input').value.trim();
    const errEl = $('auth-err'); errEl.textContent = '';
    if (!key.startsWith('ts_')) { errEl.textContent = 'Keys start with "ts_" — buy one at truesendy.com/key.'; return; }
    $('key-btn').disabled = true;
    try {
        const r = await fetch(cfg.host + '/api/v1/balance', { headers: { 'X-API-Key': key } }).then(r => r.json());
        if (r.error) { errEl.textContent = r.error; return; }
        auth = { mode: 'key', key };
        await saveCfg();
        showMain();
    } catch (e) {
        errEl.textContent = `Can't reach ${cfg.host}. Open Settings (⚙) and check the server URL.`;
    } finally {
        $('key-btn').disabled = false;
    }
});

$('buy-key-link').addEventListener('click', () => window.ts.openExternal('https://truesendy.com/key'));
$('auth-settings-link').addEventListener('click', () => $('settings-view').style.display = '');

// ── balance ──────────────────────────────────────────────────────────────────
async function loadBalance() {
    const pill = $('balance-pill');
    try {
        const url = auth.mode === 'key' ? '/api/v1/balance' : '/api/credits';
        const r = await fetch(cfg.host + url, { headers: authHeaders() }).then(r => r.json());
        if (r.error) { pill.textContent = '⚠ ' + r.error; return; }
        const t = auth.mode === 'key' ? r.tokens : r.credits;
        pill.textContent = Number(t).toLocaleString() + ' tokens';
    } catch (e) {
        pill.textContent = '⚠ server unreachable (check ⚙ URL)';
    }
}

// ── logout / settings ────────────────────────────────────────────────────────
$('logout-btn').addEventListener('click', async () => {
    auth = { mode: null, token: null, key: null };
    await window.ts.configSet({ host: cfg.host });   // keep host, drop creds
    currentEmails = []; lastResults = [];
    showAuth();
});
$('settings-btn').addEventListener('click', () => { $('settings-view').style.display = ''; });
$('settings-cancel').addEventListener('click', () => { $('settings-view').style.display = 'none'; });
$('settings-save').addEventListener('click', async () => {
    cfg.host = $('host-input').value.trim().replace(/\/+$/, '') || 'https://truesendy.com';
    await saveCfg();
    $('settings-view').style.display = 'none';
    if (auth.mode) loadBalance();
});

// ── file pick ────────────────────────────────────────────────────────────────
$('pick-btn').addEventListener('click', pickFile);
async function pickFile() {
    const r = await window.ts.pickEmailFile();
    if (r.canceled) return;
    if (r.error) { $('file-info').innerHTML = '<span style="color:var(--red)">✗ ' + r.error + '</span>'; return; }
    currentEmails = r.emails;
    $('file-info').innerHTML = `📄 <strong>${r.emails.length}</strong> email${r.emails.length === 1 ? '' : 's'} found &nbsp;<span style="color:var(--muted)">${shortPath(r.filePath)}</span>`;
    $('verify-btn').disabled = false;
}
// drag & drop onto the dropzone
const dz = $('dropzone');
['dragenter','dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
['dragleave','drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));
dz.addEventListener('drop', e => { /* file dropped — prompt to pick via native dialog (cross-platform reads need main) */ pickFile(); });
function shortPath(p) { return p.length > 48 ? '…' + p.slice(-46) : p; }

// ── verify (batched, live progress) ──────────────────────────────────────────
$('verify-btn').addEventListener('click', runVerify);
async function runVerify() {
    if (!currentEmails.length) return;
    const btn = $('verify-btn'); btn.disabled = true; btn.textContent = 'Verifying…';
    $('export-btn').disabled = true;
    resetStats();
    const BATCH = 500;
    let valid = 0, invalid = 0, skipped = 0;
    lastResults = [];
    try {
        for (let i = 0; i < currentEmails.length; i += BATCH) {
            const slice = currentEmails.slice(i, i + BATCH);
            const endpoint = auth.mode === 'key' ? '/api/v1/verify-bulk' : '/api/verify-bulk';
            const r = await fetch(cfg.host + endpoint, {
                method: 'POST', headers: authHeaders(), body: JSON.stringify({ emails: slice })
            }).then(r => r.json());
            if (r.error) { $('file-info').innerHTML = '<span style="color:var(--red)">✗ ' + r.error + '</span>'; break; }
            lastResults.push(...r.results);
            valid   += r.valid;
            invalid += r.invalid;
            skipped += (r.skipped || 0);
            renderProgress(i + slice.length, currentEmails.length, valid, invalid, skipped);
        }
        $('export-btn').disabled = valid === 0;
        loadBalance();
    } catch (e) {
        $('file-info').innerHTML = '<span style="color:var(--red)">✗ Network error — check the server URL in ⚙ Settings.</span>';
    } finally {
        btn.disabled = false; btn.textContent = 'Verify emails';
    }
}

function resetStats() {
    $('st-total').textContent = currentEmails.length.toLocaleString();
    $('st-valid').textContent = '0'; $('st-invalid').textContent = '0'; $('st-skipped').textContent = '0';
    $('progress').style.width = '0%';
    $('results-table').innerHTML = '<div class="empty">Verifying…</div>';
}
function renderProgress(done, total, valid, invalid, skipped) {
    $('progress').style.width = (done / total * 100) + '%';
    $('st-valid').textContent = valid.toLocaleString();
    $('st-invalid').textContent = invalid.toLocaleString();
    $('st-skipped').textContent = skipped.toLocaleString();
    // render the latest N results into the table
    const recent = lastResults.slice(-200);
    const rows = recent.map(r => `<tr class="${r.status === 'valid' ? 'valid' : 'invalid'}"><td>${esc(r.email)}</td><td><span class="pill ${r.status === 'valid' ? 'valid' : 'invalid'}">${r.status}</span></td><td>${esc(r.reason || r.provider || '')}</td></tr>`).join('');
    $('results-table').innerHTML = `<table><thead><tr><th>Email</th><th>Status</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
}
function esc(s) { return String(s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

// ── export valid emails ──────────────────────────────────────────────────────
$('export-btn').addEventListener('click', async () => {
    const valid = lastResults.filter(r => r.status === 'valid').map(r => r.email);
    if (!valid.length) return;
    const csv = 'Email\n' + valid.map(e => '"' + e + '"').join('\n');
    const r = await window.ts.saveExport('truesendy_valid_emails.csv', csv);
    if (!r.canceled) $('file-info').innerHTML = '<span style="color:var(--green)">✓ Saved ' + valid.length + ' valid emails to ' + shortPath(r.filePath) + '</span>';
});
