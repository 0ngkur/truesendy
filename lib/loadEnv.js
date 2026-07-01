// ── Zero-dependency .env loader ──────────────────────────────────────────────
// Required at the very top of server.js, BEFORE any module that reads
// process.env at load time (e.g. lib/authMiddleware.js reads JWT_SECRET the
// moment it is required, and calls process.exit(1) if it is missing).
//
// Precedence: a value already present in the real environment ALWAYS wins. The
// .env file only fills gaps, so a production deploy (with real env vars set by
// the host) is never silently overridden by a stale or committed .env.
//
// Why hand-rolled instead of the `dotenv` package: TrueSendy runs from a
// constrained Windows environment with no room for global installs, and this
// parser is ~25 lines. It handles comments, blank lines, surrounding quotes,
// and inline trailing comments.

const fs   = require('fs');
const path = require('path');

function loadEnv() {
    const envPath = path.join(__dirname, '..', '.env');
    let raw;
    try {
        raw = fs.readFileSync(envPath, 'utf8');
    } catch (_) {
        return; // No .env present — rely entirely on the real environment.
    }

    for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const eq = trimmed.indexOf('=');
        if (eq === -1) continue;

        const key = trimmed.slice(0, eq).trim();
        let val   = trimmed.slice(eq + 1).trim();
        if (!key) continue;

        // Strip a trailing inline comment that sits outside quotes
        //   KEY=value   # comment     → value
        //   KEY="val # ue"             → val # ue   (preserved)
        if (val.startsWith('"') || val.startsWith("'")) {
            const quote = val[0];
            const close = val.indexOf(quote, 1);
            if (close !== -1) val = val.slice(0, close + 1);
        }
        // Strip one pair of matching surrounding quotes
        if ((val.startsWith('"') && val.endsWith('"')) ||
            (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
        }

        // Never overwrite a value already provided by the real environment
        if (process.env[key] === undefined) {
            process.env[key] = val;
        }
    }
}

loadEnv();
module.exports = {};
