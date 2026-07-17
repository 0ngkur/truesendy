// TrueSendy Desktop — renderer logic. Thin API client over the TrueSendy server.
// Uses the preload bridge (window.ts) for native ops + fetch() for the API.
const $ = (id) => document.getElementById(id);

let auth = { mode: null, token: null, key: null };   // mode: 'token' | 'key'
let cfg   = { host: 'https://truesendy.com' };
let currentEmails = [];
let lastResults   = [];
let originalColumns = null;   // preserved file headers (CSV/XLSX)
let originalData    = {};     // { email: { col: val, ... } }
let fileEmails = [];          // file emails (saved for mode-switching)
let fileOriginalColumns = null;
let fileOriginalData = {};
let pendingEmail  = null;   // email of the account being created (for OTP verify)

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
    $('pane-login').style.display    = tab === 'login' ? '' : 'none';
    $('pane-register').style.display = tab === 'register' ? '' : 'none';
    $('pane-key').style.display      = tab === 'key' ? '' : 'none';
    $('pane-otp').style.display      = 'none';
    $('auth-err').textContent = '';
    $('auth-err').style.color = '';
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

// ── create account (register → OTP → unlock) ─────────────────────────────────
$('reg-btn').addEventListener('click', async () => {
    const email    = $('reg-email').value.trim();
    const username = $('reg-username').value.trim();
    const password = $('reg-pass').value;
    const errEl = $('auth-err'); errEl.textContent = ''; errEl.style.color = '';
    if (!email || !username || !password) { errEl.textContent = 'Fill in all fields.'; return; }
    if (password.length < 6)              { errEl.textContent = 'Password must be at least 6 characters.'; return; }
    if (username.length < 3 || username.length > 32) { errEl.textContent = 'Username must be 3-32 characters.'; return; }
    $('reg-btn').disabled = true;
    try {
        const r = await fetch(cfg.host + '/api/auth/register', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, username, password })
        }).then(r => r.json());
        if (r.error) { errEl.textContent = r.error; return; }
        // account created — switch to OTP entry
        pendingEmail = email;
        auth = { mode: 'token', token: r.token };
        $('pane-register').style.display = 'none';
        $('pane-otp').style.display = '';
        if (r.devOTP) {
            errEl.style.color = 'var(--green)';
            errEl.textContent = 'Dev mode — your code: ' + r.devOTP;
        }
    } catch (e) {
        errEl.textContent = `Can't reach ${cfg.host}. Open Settings (⚙) and check the server URL.`;
    } finally {
        $('reg-btn').disabled = false;
    }
});

// ── verify OTP (complete account creation) ───────────────────────────────────
$('otp-btn').addEventListener('click', async () => {
    const code = $('otp-code').value.trim();
    const errEl = $('auth-err');
    if (code.length !== 6) { errEl.style.color = ''; errEl.textContent = 'Enter the 6-digit code.'; return; }
    $('otp-btn').disabled = true;
    try {
        const r = await fetch(cfg.host + '/api/auth/verify-otp', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: pendingEmail, otp: code })
        }).then(r => r.json());
        if (r.error) { errEl.style.color = ''; errEl.textContent = r.error; $('otp-btn').disabled = false; return; }
        auth = { mode: 'token', token: r.token };
        await saveCfg();
        showMain();
    } catch (e) {
        errEl.style.color = '';
        errEl.textContent = `Can't reach ${cfg.host}.`;
        $('otp-btn').disabled = false;
    }
});
$('otp-back').addEventListener('click', () => {
    $('pane-otp').style.display = 'none';
    document.querySelector('.tab[data-tab="login"]').click();
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

// ── mode toggle: file vs typed/paste ────────────────────────────────────────
let verifyModeDesktop = 'file';
$('mode-file').addEventListener('click', () => switchModeDesktop('file'));
$('mode-type').addEventListener('click', () => switchModeDesktop('type'));

function switchModeDesktop(mode) {
    verifyModeDesktop = mode;
    const isFile = mode === 'file';
    $('mode-file').style.background = isFile ? 'var(--blue-600)' : 'var(--surface-2)';
    $('mode-file').style.color = isFile ? '#fff' : 'var(--text-2)';
    $('mode-type').style.background = !isFile ? 'var(--blue-600)' : 'var(--surface-2)';
    $('mode-type').style.color = !isFile ? '#fff' : 'var(--text-2)';
    $('dropzone').style.display = isFile ? '' : 'none';
    $('typezone').style.display = isFile ? 'none' : '';
    if (isFile) {
        // restore file-based state
        currentEmails = fileEmails;
        originalColumns = fileOriginalColumns;
        originalData = fileOriginalData;
        updateVerifyButton();
    } else {
        // switch to typed mode — count whatever is in the textarea
        updateTypedCountDesktop();
    }
}

// Live count + verify-button enable for typed emails
function updateTypedCountDesktop() {
    const text = $('email-textarea') ? $('email-textarea').value : '';
    const matches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
    const unique = [...new Set(matches.map(e => e.toLowerCase().trim()))];
    currentEmails = unique;
    originalColumns = null;  // typed emails have no file structure
    const countEl = $('typed-count');
    if (countEl) countEl.textContent = unique.length + (unique.length === 1 ? ' email' : ' emails') + ' detected';
    updateVerifyButton();
}
if ($('email-textarea')) $('email-textarea').addEventListener('input', updateTypedCountDesktop);

function updateVerifyButton() {
    const btn = $('verify-btn');
    btn.disabled = currentEmails.length === 0;
    btn.textContent = currentEmails.length > 0
        ? 'Verify ' + currentEmails.length + ' emails'
        : (verifyModeDesktop === 'type' ? 'Type emails above' : 'Verify emails');
}
async function pickFile() {
    const r = await window.ts.pickEmailFile();
    if (r.canceled) return;
    if (r.error) { $('file-info').innerHTML = '<span style="color:var(--red)">✗ ' + r.error + '</span>'; return; }
    currentEmails = r.emails;
    fileEmails = r.emails;                          // saved for mode-switching back
    fileOriginalColumns = r.originalColumns || null;
    fileOriginalData = r.originalData || {};
    originalColumns = fileOriginalColumns;
    originalData = fileOriginalData;
    $('file-info').innerHTML = `📄 <strong>${r.emails.length}</strong> email${r.emails.length === 1 ? '' : 's'} found &nbsp;<span style="color:var(--muted)">${shortPath(r.filePath)}</span>`;
    updateVerifyButton();
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
        $('export-btn').disabled = (valid + invalid) === 0;
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
    $('progress-pct').textContent = '0%';
    const ev=$('ec-valid'); if(ev) ev.textContent='0';
    const ei=$('ec-invalid'); if(ei) ei.textContent='0';
    const ea=$('ec-all'); if(ea) ea.textContent='0';
    $('results-table').innerHTML = '<div class="empty">Verifying…</div>';
}
function renderProgress(done, total, valid, invalid, skipped) {
    const pct = Math.round(done / total * 100);
    $('progress').style.width = pct + '%';
    $('progress-pct').textContent = pct + '%';
    $('st-valid').textContent = valid.toLocaleString();
    $('st-invalid').textContent = invalid.toLocaleString();
    $('st-skipped').textContent = skipped.toLocaleString();
    // Update category counts
    const ev = $('ec-valid');   if (ev) ev.textContent = valid;
    const ei = $('ec-invalid'); if (ei) ei.textContent = invalid;
    const ea = $('ec-all');     if (ea) ea.textContent = done;
    // render the latest N results into the table
    const recent = lastResults.slice(-200);
    const rows = recent.map(r => `<tr class="${r.status === 'valid' ? 'valid' : 'invalid'}"><td>${esc(r.email)}</td><td><span class="pill ${r.status === 'valid' ? 'valid' : 'invalid'}">${r.status}</span></td><td>${esc(r.reason || r.provider || '')}</td></tr>`).join('');
    $('results-table').innerHTML = `<table><thead><tr><th>Email</th><th>Status</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
}
function esc(s) { return String(s || '').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

// ── category selector for export ──────────────────────────────────────────────
let exportCategory = 'valid';
function selectCatElec(cat) {
    exportCategory = cat;
    document.querySelectorAll('.cat-btn-electron').forEach(b => b.classList.remove('active'));
    document.querySelector(`.cat-btn-electron[data-cat="${cat}"]`).classList.add('active');
}

// ── export: original file + status column (PREFERRED) ─────────────────────────
// Writes the uploaded file EXACTLY as-is + a Verification_Status column
// inserted RIGHT NEXT TO the email column. Nothing erased.
function buildOriginalWithStatus(results) {
    if (!originalColumns || !originalColumns.length) return null;
    const emailColRe = /^[ \t]*e-?mail[ \t]*(address)?$/i;
    let emailIdx = originalColumns.findIndex(c => emailColRe.test(c));
    if (emailIdx === -1) {
        // Fallback: find the column holding the email for the first result
        const firstEmail = results[0] && results[0].email;
        if (firstEmail && originalData[firstEmail]) {
            emailIdx = originalColumns.findIndex(c =>
                String(originalData[firstEmail][c] || '').toLowerCase().trim() === firstEmail);
        }
    }
    const insertAt = emailIdx === -1 ? originalColumns.length : emailIdx + 1;
    const headers = [...originalColumns];
    headers.splice(insertAt, 0, 'Verification_Status');
    const rows = results.map(r => {
        const orig = originalData[r.email] || {};
        const vals = originalColumns.map(c => orig[c] !== undefined ? String(orig[c]) : '');
        vals.splice(insertAt, 0, r.status || 'unknown');
        return vals;
    });
    return [headers.join(','), ...rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(','))].join('\n');
}

// ── export emails by category ─────────────────────────────────────────────────
$('export-btn').addEventListener('click', async () => {
    let results;
    if (exportCategory === 'all') results = lastResults;
    else if (exportCategory === 'invalid') results = lastResults.filter(r => r.status !== 'valid');
    else results = lastResults.filter(r => r.status === 'valid');
    if (!results.length) return;

    // PREFERRED: if we have the original file structure, export it + status column
    const originalCsv = (exportCategory === 'all') ? buildOriginalWithStatus(results) : null;
    if (originalCsv) {
        const r = await window.ts.saveExport('truesendy_verified_with_status.csv', originalCsv);
        if (!r.canceled) $('file-info').innerHTML = '<span style="color:var(--green)">✓ Saved original file + status for ' + results.length + ' emails → ' + shortPath(r.filePath) + '</span>';
        return;
    }

    // Fallback: rich CSV with verification columns
    const headers = ['Email','Status','Safe_To_Send','Category','Provider','Reason','Domain','Is_Disposable','Is_Role_Based','Is_Catch_All'];
    const rows = results.map(r => [
        r.email || '', r.status || 'unknown',
        r.status === 'valid' ? 'true' : 'false',
        r.category || '', r.provider || '', r.reason || '',
        (r.email||'').split('@')[1] || '',
        r.flags?.disposable ? 'true' : 'false',
        r.flags?.roleBased ? 'true' : 'false',
        r.flags?.catchAll ? 'true' : 'false'
    ]);
    const csv = [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
    const r = await window.ts.saveExport(`truesendy_${exportCategory}.csv`, csv);
    if (!r.canceled) $('file-info').innerHTML = '<span style="color:var(--green)">✓ Saved ' + results.length + ' ' + exportCategory + ' emails to ' + shortPath(r.filePath) + '</span>';
});
