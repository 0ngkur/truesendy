// TrueSendy Desktop — Electron main process.
// Secure: contextIsolation on, nodeIntegration off, sandbox on.
const fs   = require('fs');
const os   = require('os');
const path = require('path');

// File-based startup log (the packaged app has no console, so this is how we see errors).
const DBG = path.join(os.homedir(), 'truesendy-debug.log');
const dbg = (m) => { try { fs.appendFileSync(DBG, `\n[${new Date().toISOString()}] ${m}`); } catch {} };
dbg('=== main.js loaded ===');

let electronMod;
try { electronMod = require('electron'); dbg(`electron required (app=${typeof electronMod.app})`); }
catch (e) { dbg('REQUIRE electron FAILED: ' + e.message); throw e; }
const { app, BrowserWindow, ipcMain, dialog, shell } = electronMod;

let xlsx;
try { xlsx = require('xlsx'); dbg('xlsx required OK'); }
catch (e) { dbg('REQUIRE xlsx FAILED: ' + e.message); throw e; }

let win;
function createWindow() {
    dbg('createWindow start');
    // Use the logo that IS packaged in the asar (renderer/logo.png) for the window icon.
    const iconPath = path.join(__dirname, 'renderer', 'logo.png');
    win = new BrowserWindow({
        width: 1280, height: 820, minWidth: 960, minHeight: 640,
        icon: fs.existsSync(iconPath) ? iconPath : undefined,
        title: 'TrueSendy',
        backgroundColor: '#f8fafc',
        autoHideMenuBar: true,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
        },
    });
    win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
    win.webContents.on('did-finish-load', () => dbg('renderer did-finish-load'));
    win.webContents.on('console-message', (_e, level, msg) => dbg('renderer console: ' + msg));
    win.on('closed', () => dbg('window closed'));
    dbg('window created');
}

app.whenReady().then(() => { dbg('whenReady fired'); createWindow(); })
   .catch(e => dbg('whenReady REJECTED: ' + e.message));
app.on('window-all-closed', () => { dbg('window-all-closed → quit'); if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on('render-process-gone', (_e, details) => dbg('render-process-gone: ' + details.reason));

// ── Email extraction (CSV / TXT / XLSX) ──────────────────────────────────────
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,63}$/;
function extractEmails(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    let text = '';
    if (ext === '.xlsx' || ext === '.xls') {
        const wb = xlsx.readFile(filePath);
        wb.SheetNames.forEach(s => { text += xlsx.utils.sheet_to_csv(wb.Sheets[s]) + ' '; });
    } else {
        text = fs.readFileSync(filePath, 'utf8');
    }
    const found = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
    const seen = new Set(); const out = [];
    for (const e of found) {
        const lc = e.toLowerCase().trim();
        if (EMAIL_RE.test(lc) && !seen.has(lc)) { seen.add(lc); out.push(lc); }
    }
    return out;
}

ipcMain.handle('pick-email-file', async () => {
    const r = await dialog.showOpenDialog(win, {
        title: 'Choose an email list',
        filters: [{ name: 'Email lists', extensions: ['csv', 'txt', 'xlsx', 'xls'] }],
        properties: ['openFile'],
    });
    if (r.canceled || !r.filePaths.length) return { canceled: true };
    const filePath = r.filePaths[0];
    try {
        const emails = extractEmails(filePath);
        if (!emails.length) return { canceled: false, filePath, error: 'No valid email addresses found in this file.' };
        return { canceled: false, filePath, count: emails.length, emails };
    } catch (e) {
        return { canceled: false, filePath, error: 'Could not read this file: ' + e.message };
    }
});

ipcMain.handle('save-export', async (_e, defaultName, content) => {
    const r = await dialog.showSaveDialog(win, {
        title: 'Export valid emails', defaultPath: defaultName,
        filters: [{ name: 'CSV', extensions: ['csv'] }, { name: 'Text', extensions: ['txt'] }],
    });
    if (r.canceled) return { canceled: true };
    fs.writeFileSync(r.filePath, content);
    return { canceled: false, filePath: r.filePath };
});

ipcMain.handle('open-external', (_e, url) => shell.openExternal(url));

const cfgPath = () => path.join(app.getPath('userData'), 'config.json');
ipcMain.handle('config-get', () => { try { return JSON.parse(fs.readFileSync(cfgPath(), 'utf8')); } catch { return {}; } });
ipcMain.handle('config-set', (_e, cfg) => { try { fs.writeFileSync(cfgPath(), JSON.stringify(cfg)); return true; } catch { return false; } });

ipcMain.handle('app-version', () => app.getVersion());
dbg('main.js end reached — awaiting app.whenReady()');
