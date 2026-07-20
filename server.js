require('./lib/loadEnv');          // MUST be first: populates process.env before any module reads it
const express     = require('express');
const multer      = require('multer');
const fs          = require('fs');
const path        = require('path');
const os          = require('os');
const crypto      = require('crypto');
const bcrypt      = require('bcryptjs');
const compression = require('compression');
const verifier    = require('./verifier');
const ExcelJS     = require('exceljs');
const pdfParse    = require('pdf-parse');
const mammoth     = require('mammoth');
const store       = require('./db/store');
const settings    = require('./db/settings');
const pricing     = require('./config/pricing');
const { generateOTP, sendOTP, isDevMode, sendApiKeyEmail } = require('./lib/emailService');
const { generateToken, authMiddleware, JWT_SECRET } = require('./lib/authMiddleware');
const {
    helmetMiddleware, corsMiddleware, hppMiddleware, inputSanitizer,
    authLimiter, authSlowDown, otpLimiter, forgotLimiter,
    apiLimiter, generalLimiter, adminLimiter,
    validateUpload, isPrivateHost, timingSafeEqual,
    apiNoCacheHeaders, safeErrorHandler,
} = require('./lib/security');

const app    = express();

// ── Process resilience: never let one async error kill the server ──
// Log unhandled rejections and keep serving (common with SMTP/email ops).
process.on('unhandledRejection', (reason) => {
    console.error('[TrueSendy][FATAL] Unhandled promise rejection:', reason && reason.message ? reason.message : reason);
});
// Uncaught exceptions leave the process in an unknown state — log and exit so
// the supervisor (pm2 / systemd / Render restart policy) brings it back clean.
process.on('uncaughtException', (err) => {
    console.error('[TrueSendy][FATAL] Uncaught exception:', err.message, (err.stack || '').split('\n').slice(0, 3).join(' | '));
    process.exit(1);
});
// Behind a reverse proxy (Render/nginx)? Set TRUST_PROXY=1 so req.ip is the real client.
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);

const upload = multer({
    dest    : 'uploads/',
    limits  : { fileSize: 10 * 1024 * 1024, files: 1 },  // 10MB max, 1 file
});

// ══════════════════════════════════════════════════════════════════
//  SECURITY + PERFORMANCE MIDDLEWARE STACK
// ══════════════════════════════════════════════════════════════════

// [0] Gzip compression — cuts bandwidth ~70%, critical for VPS
app.use(compression({ level: 6, threshold: 1024 }));

// [1] Helmet — strict HTTP security headers
app.use(helmetMiddleware);

// [2] CORS — only allow our own origins
app.use(corsMiddleware);

// [3] Block sensitive files before static middleware
// Sensitive paths that must NEVER be served. Checked against the decoded +
// normalized path so tricks like /./server.js, /../db/users.json, /%2e%2e/.env,
// /SERVER.JS, or trailing dots cannot slip past.
const SENSITIVE_SEGMENTS = new Set(['server.js','verifier.js','package.json','package-lock.json','.env','.git','.gitignore','review.md']);
const SENSITIVE_DIRS = ['db/','lib/','cli/','config/','node_modules/','uploads/','dist/','.remember/','.planning/','.git/'];
app.use((req, res, next) => {
    let p;
    try { p = decodeURIComponent(req.path); } catch { p = req.path; }
    p = p.replace(/\\/g, '/');
    // collapse '.' and '..' segments (path traversal)
    const segs = p.split('/').filter(s => s.length && s !== '.' && s !== '..');
    const clean = '/' + segs.join('/');
    const lower = clean.toLowerCase();
    if (segs.some(s => s.toLowerCase().startsWith('.'))) {                  // any dotfile/dotdir segment
        return res.status(403).json({ error: 'Forbidden' });
    }
    if (segs.some(s => SENSITIVE_SEGMENTS.has(s.toLowerCase()))) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    if (SENSITIVE_DIRS.some(d => lower.includes(d))) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
});

// [4] FAST static file serving — only serve whitelisted public files/dirs
// NEVER serve from __dirname directly (would scan node_modules = 4s+ page load!)
const staticOpts = {
    etag   : true,
    setHeaders(res, filePath) {
        const ext = path.extname(filePath).toLowerCase();
        if (['.woff','.woff2','.ttf','.otf','.png','.jpg','.webp','.svg','.ico'].includes(ext)) {
            res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
        } else if (['.css'].includes(ext)) {
            res.setHeader('Cache-Control', 'public, max-age=3600');
        } else if (['.js'].includes(ext)) {
            res.setHeader('Cache-Control', 'public, max-age=300'); // 5min — app updates
        } else if (['.html'].includes(ext)) {
            res.setHeader('Cache-Control', 'public, max-age=60, must-revalidate');
        }
    },
};

// Serve individual public files explicitly — no directory scanning
const PUBLIC_FILES = ['style.css','app.js','favicon.ico','robots.txt'];
PUBLIC_FILES.forEach(f => {
    const fp = path.join(__dirname, f);
    if (fs.existsSync(fp)) {
        app.get('/' + f, (req, res) => {
            res.setHeader('Cache-Control', f.endsWith('.css') ? 'public, max-age=3600' : 'public, max-age=300');
            res.sendFile(fp);
        });
    }
});

// Serve public directories only (assets, downloads, data)
// NOTE: 'downloads' is intentionally NOT served as a public static dir — the bot
// exe is premium-gated (see serveBotExe below). The /downloads PAGE is still
// served via PAGE_FILES.
const PUBLIC_DIRS = ['assets','data'];
PUBLIC_DIRS.forEach(dir => {
    const dp = path.join(__dirname, dir);
    if (fs.existsSync(dp)) app.use('/' + dir, express.static(dp, staticOpts));
});



// ── Stripe webhook — MUST be registered BEFORE express.json() so the route
// receives the RAW body buffer required for signature verification, and before
// inputSanitizer (which would try to walk the Buffer as an object). This is the
// ONLY endpoint that grants a plan: server-to-server, cryptographically signed
// by Stripe. The browser redirect (/api/payment-success) intentionally does NOT.
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const signature = req.headers['stripe-signature'];
    if (!signature) return res.status(400).json({ error: 'Missing stripe-signature header.' });

    let event;
    try {
        event = pricing.constructEvent(req.body, signature);
    } catch (err) {
        console.error('[TrueSendy] Webhook signature verification failed:', err.message);
        return res.status(400).json({ error: 'Invalid signature.' });
    }

    try {
        // Idempotency — Stripe retries events; never process the same event.id twice
        // (a retried key_purchase would otherwise double-credit tokens).
        if (store.isEventProcessed(event.id)) return res.json({ received: true, duplicate: true });
        store.markEventProcessed(event.id);

        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            const meta    = session.metadata || {};

            if (meta.type === 'key_purchase') {
                // ── Key sale (guest checkout): find-or-create the buyer by email,
                // credit the purchased token allowance (from metadata), mint a key, email it. ──
                const email = meta.email;
                if (!email) {
                    console.warn('[TrueSendy] Webhook key_purchase: no email in metadata');
                } else {
                    const product  = settings.getKeyProduct();
                    const purchased = Number(meta.tokens) || product.tokens; // amount paid for
                    const user   = store.findOrCreateKeyBuyer(email);
                    const result = store.purchaseApiKey(user.id, purchased);
                    if (result.error) {
                        console.error(`[TrueSendy] Webhook key_purchase failed for ${email}: ${result.error}`);
                    } else {
                        await sendApiKeyEmail(email, result.apiKey.key, purchased, product.validityDays);
                        console.log(`[TrueSendy] Webhook: key delivered to ${email} (${purchased} tokens)`);
                    }
                }
            } else if (meta.plan && ['starter', 'pro', 'agency'].includes(meta.plan)) {
                // ── Plan upgrade (subscription) ──
                const plan   = meta.plan;
                const userId = meta.userId;
                const email  = meta.email;
                const user   = (userId && store.findUserById(userId))
                    || (email && store.findUserByEmail(email))
                    || null;

                if (user) {
                    if (user.plan === 'agency' && plan !== 'agency') {
                        store.revokeAllApiKeysForUser(user.id);
                    }
                    store.upgradePlan(user.id, plan);
                    console.log(`[TrueSendy] Webhook: upgraded ${user.email} → ${plan}`);
                } else {
                    console.warn(`[TrueSendy] Webhook: no matching user for plan=${plan} email=${email || '(none)'} userId=${userId || '(none)'}`);
                }
            }
        }
    } catch (err) {
        console.error('[TrueSendy] Webhook handler error:', err.message);
        return res.status(500).json({ error: 'Internal error' });   // Stripe will retry
    }

    // Acknowledge quickly — Stripe retries unless we return 2xx.
    res.json({ received: true });
});

// [5] Body parsers — strict size limits (prevent DoS via large payloads)
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// [6] HTTP Parameter Pollution
app.use(hppMiddleware);

// [7] Input sanitizer (null bytes, prototype pollution, oversized values)
app.use(inputSanitizer);

// [8] No-cache headers for API responses
app.use(apiNoCacheHeaders);

// [9] Rate limiter on API routes only — HTML pages and static assets are exempt
app.use('/api', generalLimiter);

// ── [FIX #2] Pre-cache all HTML file paths at startup — zero disk I/O per request
const PAGE_FILES = {
    '/'              : path.join(__dirname, 'index.html'),
    '/signin'        : path.join(__dirname, 'signin.html'),
    '/signup'        : path.join(__dirname, 'signin.html'),
    '/masterenter'   : path.join(__dirname, 'masterenter.html'),
    '/agency-api'    : path.join(__dirname, 'agency-api.html'),
    '/subscribePlan' : path.join(__dirname, 'subscribePlan.html'),
    '/downloads'     : path.join(__dirname, 'downloads.html'),
    '/emailcheckup'  : path.join(__dirname, 'emailcheckup.html'), // ← Email Checkup tool
    '/key'           : path.join(__dirname, 'key.html'),
    '/checkout'      : path.join(__dirname, 'checkout.html'),
    '/buycredits'    : path.join(__dirname, 'buycredits.html'),
    '/dashboard'     : path.join(__dirname, 'dashboard.html'),
};

// Verify all files exist at boot — fail loud, not silently at runtime
Object.entries(PAGE_FILES).forEach(([route, fp]) => {
    if (!fs.existsSync(fp)) console.warn(`[TrueSendy] WARNING: missing page file for ${route}: ${fp}`);
});

// ── [FIX #1] activeJobs with TTL — completed results auto-delete after 7 days
// (matches competitor behavior; keeps memory bounded on long-running servers).
const activeJobs = {};
const JOB_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
setInterval(() => {
    const cutoff = Date.now() - JOB_TTL_MS;
    for (const [id, job] of Object.entries(activeJobs)) {
        // Delete old jobs (>7 days) or errored/expired jobs.
        // Completed jobs are kept so users can re-download within the 7-day window.
        if (job.createdAt < cutoff || job.status === 'expired') {
            // Clean up the disk-backed result file
            if (job.resultFile) { try { fs.unlinkSync(job.resultFile); } catch {} }
            delete activeJobs[id];
        }
    }
}, 60 * 60 * 1000).unref(); // Run hourly, don't block process exit

// ── 7-day retention: purge old job history + usage logs for ALL users ──
// Runs hourly. Keeps storage bounded — after 7 days, users' Tasks & Results
// and Credits History are cleaned (matches the competitor's 7-day policy).
setInterval(() => {
    try { store.cleanupOldHistory(); } catch (e) { console.warn('[TrueSendy] History cleanup error:', e.message); }
}, 60 * 60 * 1000).unref(); // hourly

// ── [FIX #7] Health check endpoint — for VPS uptime monitors (no rate limit)
app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), ts: Date.now() });
});

// ── Register all HTML page routes from PAGE_FILES (the missing piece!)
// Each route serves its pre-resolved file path — zero fs.existsSync per request
Object.entries(PAGE_FILES).forEach(([route, fp]) => {
    app.get(route, (req, res) => {
        res.setHeader('Cache-Control', 'public, max-age=60, must-revalidate');
        res.setHeader('Vary', 'Accept-Encoding'); // tells proxies gzip varies
        res.sendFile(fp);
    });
});

// ======================== DOWNLOADS ========================

// ── Agency-gated bot download ────────────────────────────────────────────────
// The bot (desktop exe + CLI) is an ULTRA PREMIUM feature. Only Agency plan
// subscribers can download it. Requires ?token=<jwt> of an authenticated
// Agency-plan user. Non-Agency users get redirected to the upgrade page.
function serveBotExe(req, res, filePath, filename) {
    const token = (req.query.token || '').toString();

    // ── Auth required: validate the JWT ──
    if (!token) {
        return res.redirect(302, '/signin?next=' + encodeURIComponent(req.path));
    }

    let userId = null;
    try {
        const jwtLib = require('jsonwebtoken');
        userId = jwtLib.verify(token, JWT_SECRET, { algorithms: ['HS256'] }).id;
    } catch {
        // Invalid / expired token → redirect to sign in
        return res.redirect(302, '/signin?next=' + encodeURIComponent(req.path));
    }

    // ── Plan check: Agency required ──
    const user = store.findUserById(userId);
    if (!user) {
        return res.redirect(302, '/signin?next=' + encodeURIComponent(req.path));
    }
    if (user.plan !== 'agency') {
        // Logged in but not Agency → send to the agency upgrade page
        return res.redirect(302, '/subscribePlan?need=agency');
    }

    // ── Agency user — serve the file ──
    store.markBotDownloaded(userId);
    settings.incBotDownload();

    if (!fs.existsSync(filePath)) {
        // File not cached on this server — redirect to GitHub release (one-time, cached on next boot).
        return res.redirect(302, 'https://github.com/0ngkur/truesendy/releases/download/v1.3.1/TrueSendy-Setup.exe');
    }
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
}

// ── Boot-time exe fetcher: download the installer from GitHub + cache it locally ──
// so the exe is served from truesendy.com, not a redirect. Runs once on first boot.
const EXE_CACHE_PATH = path.join(__dirname, 'downloads', 'TrueSendy-Setup.exe');
const EXE_GITHUB_URL = 'https://github.com/0ngkur/truesendy/releases/download/v1.3.1/TrueSendy-Setup.exe';
function fetchExeOnBoot() {
    if (fs.existsSync(EXE_CACHE_PATH)) {
        console.log('[TrueSendy] Bot exe cached locally — serving from VPS.');
        return;
    }
    console.log('[TrueSendy] Fetching bot exe from GitHub release (one-time, ~80MB)...');
    const https = require('https');
    const dir = path.dirname(EXE_CACHE_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const file = fs.createWriteStream(EXE_CACHE_PATH);
    const handleRedirect = (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
            https.get(response.headers.location, handleRedirect).on('error', () => {
                console.warn('[TrueSendy] Could not fetch bot exe — will redirect to GitHub on download.');
                file.close();
                try { fs.unlinkSync(EXE_CACHE_PATH); } catch {}
            });
        } else {
            response.pipe(file);
            file.on('finish', () => {
                file.close();
                console.log('[TrueSendy] Bot exe cached — future downloads served from VPS.');
            });
        }
    };
    https.get(EXE_GITHUB_URL, handleRedirect).on('error', () => {
        console.warn('[TrueSendy] Could not fetch bot exe — will redirect to GitHub on download.');
        file.close();
        try { fs.unlinkSync(EXE_CACHE_PATH); } catch {}
    });
}
fetchExeOnBoot();

app.get('/downloads/TrueSendy.exe',       (req, res) => serveBotExe(req, res, path.join(__dirname, 'dist',      'TrueSendy.exe'),       'TrueSendy.exe'));
app.get('/downloads/TrueSendy-Setup.exe', (req, res) => serveBotExe(req, res, path.join(__dirname, 'downloads', 'TrueSendy-Setup.exe'), 'TrueSendy-Setup.exe'));

// Check whether the current user can download the bot (Agency plan required).
// Used by downloads.html to decide which UI to show.
app.get('/api/download-eligibility', authMiddleware, (req, res) => {
    const canDownload = req.user.plan === 'agency';
    res.json({
        canDownload,
        plan: req.user.plan || 'free',
        needPlan: canDownload ? null : 'agency',
    });
});

// Legacy download route
app.get('/download/truesendy-cli', (req, res) => res.redirect(301, '/downloads/TrueSendy.exe'));

// ======================== AUTH ROUTES ========================
// All auth routes have rate limiting + slow-down applied

app.post('/api/auth/register', authLimiter, authSlowDown, async (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
        return res.status(400).json({ error: 'Email, username, and password are required.' });
    }
    // Strict email format check
    if (!/^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,63}$/.test(email) || email.length > 254) {
        return res.status(400).json({ error: 'Invalid email address format.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }
    if (username.length < 3 || username.length > 32 || !/^[a-zA-Z0-9_-]+$/.test(username)) {
        return res.status(400).json({ error: 'Username must be 3-32 chars, letters/numbers/_ only.' });
    }

    // If this email belongs to a guest key-buyer, guide them to reset password
    // instead of returning a confusing "already exists" error.
    const existing = store.findUserByEmail(email);
    if (existing && existing.keyBuyer) {
        return res.status(409).json({ error: 'You already bought a key with this email. Use "Forgot password" to set a password and access your account and key.' });
    }

    const result = await store.createUser(email, password, username);
    if (result.error) return res.status(409).json({ error: result.error });

    // Send verification OTP
    const otp = generateOTP();
    store.storeOTP(email, otp, 'verify');
    const token = generateToken(result.user);
    const delivered = await sendOTP(email, otp, 'verify');
    const dev = isDevMode();
    if (!delivered) {
        // SMTP was configured but the code didn't go out — be honest so the user
        // isn't stuck waiting. The OTP was stored; they can hit "resend code".
        return res.status(503).json({ error: 'Your account was created, but we couldn\'t email your verification code right now. Tap "Resend code".', token, needsVerification: true });
    }
    res.json({ message: dev ? `Dev mode — your code is: ${otp}` : 'Account created! Check your email for verification code.', token, needsVerification: true, devOTP: dev ? otp : undefined });
});

app.post('/api/auth/verify-otp', otpLimiter, (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required.' });

    const valid = store.verifyOTP(email, otp, 'verify');
    if (!valid) return res.status(400).json({ error: 'Invalid or expired code.' });

    store.verifyUser(email);
    const user = store.findUserByEmail(email);
    const token = generateToken(user);
    res.json({ message: 'Email verified! You have 5 free credits.', token, user: sanitizeUser(user) });
});

app.post('/api/auth/resend-otp', otpLimiter, (req, res) => {
    const { email, purpose } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required.' });

    const user = store.findUserByEmail(email);
    if (!user) return res.status(404).json({ error: 'No account with that email.' });

    const otp = generateOTP();
    store.storeOTP(email, otp, purpose || 'verify');
    sendOTP(email, otp, purpose || 'verify');
    const dev = isDevMode();
    res.json({ message: dev ? `Dev mode — your code is: ${otp}` : 'New code sent to your email.', devOTP: dev ? otp : undefined });
});

app.post('/api/auth/login', authLimiter, authSlowDown, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
    if (typeof email !== 'string' || email.length > 254) return res.status(400).json({ error: 'Invalid email.' });

    const user = store.findUserByEmail(email);
    // Always run bcrypt even if user not found — prevent timing-based account enumeration
    const dummyHash = '$2a$10$abcdefghijklmnopqrstuvuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu';
    const match = await bcrypt.compare(password, user ? user.password : dummyHash);
    if (!user || !match) {
        if (user && user.keyBuyer) return res.status(403).json({ error: 'You bought a key but haven\'t set a password yet. Use "Forgot password" to create one and access your key.' });
        return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.banned) return res.status(403).json({ error: 'Account suspended. Contact support.' });

    if (!user.verified) {
        const otp = generateOTP();
        store.storeOTP(email, otp, 'verify');
        await sendOTP(email, otp, 'verify');
        const token = generateToken(user);
        return res.json({ message: 'Email not yet verified. New code sent.', token, needsVerification: true });
    }

    const token = generateToken(user);
    res.json({ message: 'Welcome back!', token, user: sanitizeUser(user) });
});

app.post('/api/auth/forgot-password', forgotLimiter, async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required.' });

    const user = store.findUserByEmail(email);
    if (!user) {
        // Don't reveal if account exists
        return res.json({ message: 'If an account exists with that email, a reset code has been sent.' });
    }

    const otp = generateOTP();
    store.storeOTP(email, otp, 'reset');
    await sendOTP(email, otp, 'reset');
    res.json({ message: 'If an account exists with that email, a reset code has been sent.' });
});

app.post('/api/auth/reset-password', otpLimiter, async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) return res.status(400).json({ error: 'All fields required.' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    const valid = store.verifyOTP(email, otp, 'reset');
    if (!valid) return res.status(400).json({ error: 'Invalid or expired code.' });

    await store.updatePassword(email, newPassword);
    res.json({ message: 'Password reset successful! You can now log in.' });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    res.json({ user: sanitizeUser(req.user) });
});

// Logged-in user changes their own password (no OTP needed — already authenticated).
app.post('/api/auth/update-password', authMiddleware, async (req, res) => {
    const { password } = req.body || {};
    if (!password || String(password).length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }
    await store.updatePassword(req.user.email, String(password));
    res.json({ message: 'Password updated successfully.' });
});

function sanitizeUser(user) {
    return {
        id: user.id,
        email: user.email,
        username: user.username,
        verified: user.verified,
        credits: (user.credits || 0) + (user.planCredits || 0) + (user.purchasedTokens || 0),
        purchasedTokens: user.purchasedTokens || 0,
        plan: user.plan,
    };
}

// ======================== SUBSCRIPTION & PAYMENTS ========================

// Get pricing config (public)
app.get('/api/pricing', (req, res) => {
    res.json(pricing.loadPricing());
});

// Create Stripe checkout session
app.post('/api/checkout', authMiddleware, async (req, res) => {
    const { plan, billingCycle } = req.body;
    if (!['starter', 'pro', 'agency'].includes(plan)) {
        return res.status(400).json({ error: 'Invalid plan.' });
    }

    const planConfig = pricing.getPlan(plan);
    if (!planConfig) return res.status(400).json({ error: 'Plan not found.' });

    // Real Stripe checkout — the only way upgrades happen in production.
    if (pricing.isStripeConfigured()) {
        const origin = req.headers.origin || `http://localhost:${PORT}`;
        const result = await pricing.createCheckoutSession(
            plan,
            billingCycle || 'monthly',
            `${origin}/api/payment-success?plan=${plan}&cycle=${billingCycle || 'monthly'}`,
            `${origin}/subscribePlan?canceled=1`,
            req.user.email,
            req.user.id
        );
        if (result.error) return res.status(400).json(result);
        return res.json({ checkoutUrl: result.url, sessionId: result.sessionId });
    }

    // Stripe NOT configured. Only allow a free dev upgrade behind an explicit
    // opt-in flag. Without this gate, anyone could self-serve the Agency plan —
    // and therefore the paid CLI/bot API key — for free. That is exactly the
    // "free bot" leak we are closing.
    if (process.env.ALLOW_DEV_PAYMENTS !== 'true') {
        return res.status(503).json({
            error: 'Payments are not configured on this server. Please contact support to upgrade your plan.',
        });
    }

    const currentUser = store.findUserById(req.user.id);
    if (currentUser && currentUser.plan === 'agency' && plan !== 'agency') {
        store.revokeAllApiKeysForUser(req.user.id);
    }
    store.upgradePlan(req.user.id, plan);
    const user = store.findUserById(req.user.id);
    res.json({ message: `Dev mode — upgraded to ${plan} without payment.`, user: sanitizeUser(user), devMode: true });
});

// Browser landing page after the Stripe redirect. It does NOT require auth (a
// 302 redirect carries no Authorization header) and does NOT grant the plan —
// the signed /api/stripe-webhook does that, server-to-server. Keeping the
// upgrade out of this route closes the bypass where anyone could hit
// /api/payment-success?plan=agency and get a free upgrade.
app.get('/api/payment-success', (req, res) => {
    const { plan } = req.query;
    const valid = ['starter', 'pro', 'agency'].includes(plan);
    res.redirect(valid
        ? `/subscribePlan?success=1&plan=${plan}`
        : '/subscribePlan?error=invalid_plan');
});

// Legacy subscribe endpoint (redirects to checkout)
app.post('/api/subscribe', authMiddleware, async (req, res) => {
    const { plan } = req.body;
    if (!['starter', 'pro', 'agency'].includes(plan)) {
        return res.status(400).json({ error: 'Invalid plan.' });
    }

    if (pricing.isStripeConfigured()) {
        const origin = req.headers.origin || `http://localhost:${PORT}`;
        const result = await pricing.createCheckoutSession(
            plan, 'monthly',
            `${origin}/api/payment-success?plan=${plan}&cycle=monthly`,
            `${origin}/subscribePlan?canceled=1`,
            req.user.email,
            req.user.id
        );
        if (result.error) return res.status(400).json(result);
        return res.json({ checkoutUrl: result.url });
    }

    // Stripe not configured — same explicit dev-payments gate as /api/checkout.
    if (process.env.ALLOW_DEV_PAYMENTS !== 'true') {
        return res.status(503).json({
            error: 'Payments are not configured on this server. Please contact support to upgrade your plan.',
        });
    }

    store.upgradePlan(req.user.id, plan);
    const user = store.findUserById(req.user.id);
    res.json({ message: `Upgraded to ${plan}!`, user: sanitizeUser(user), devMode: true });
});

// ======================== CREDITS ========================

app.get('/api/credits', authMiddleware, (req, res) => {
    const credits = store.getUserCredits(req.user.id);
    res.json({ credits });
});

// Recent credit usage history for the dashboard widget.
app.get('/api/credit-history', authMiddleware, (req, res) => {
    const history = store.getUsageHistory(req.user.id, 20);
    res.json({ history });
});

// Everything the dashboard needs in one call (avoids 5 separate fetches).
app.get('/api/dashboard-stats', authMiddleware, (req, res) => {
    const userId = req.user.id;
    const user = store.findUserById(userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({
        credits:        store.getUserCredits(userId),
        plan:           user.plan || 'free',
        planCredits:    user.planCredits || 0,
        purchasedTokens: user.purchasedTokens || 0,
        freeCredits:    user.credits || 0,
        tokensUsed:     user.tokensUsed || 0,
        email:          user.email,
        username:       user.username,
        createdAt:      user.createdAt,
        jobHistory:     store.getJobHistory(userId),
        usageLog:       store.getUsageHistory(userId, 50),
        agencyRequested: !!user.agencyRequested,
    });
});

// ======================== SINGLE EMAIL CHECK ========================

app.post('/api/verify-single', authMiddleware, async (req, res) => {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
        return res.status(400).json({ error: 'Invalid email provided.' });
    }

    if (!store.deductToken(req.user.id, 1).ok) {
        return res.status(402).json({ error: 'No tokens remaining. Please upgrade your plan or buy a key.' });
    }

    try {
        const data = await verifier.verifyEmail(email);
        res.json(data);
    } catch (e) {
        store.refundToken(req.user.id, 1); // Refund on error
        console.error('[TrueSendy] Single check error:', e.message);
        res.status(500).json({ error: 'Internal server error during verification.' });
    }
});

// Bulk verify for LOGGED-IN (JWT) users — mirrors /api/v1/verify-bulk so the
// desktop app has one clean bulk path for BOTH auth methods (login OR key).
// Dedupe + syntax-validate, then deduct from the shared balance.
app.post('/api/verify-bulk', authMiddleware, async (req, res) => {
    const { emails } = req.body || {};
    if (!Array.isArray(emails) || emails.length === 0) {
        return res.status(400).json({ error: 'Provide an array of emails.' });
    }
    if (emails.length > 500) {
        return res.status(400).json({ error: 'Maximum 500 emails per request.' });
    }
    const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,63}$/;
    const seen = new Set(); const cleanEmails = [];
    for (const e of emails) {
        if (typeof e === 'string' && EMAIL_RE.test(e)) {
            const lc = e.toLowerCase().trim();
            if (!seen.has(lc)) { seen.add(lc); cleanEmails.push(lc); }
        }
    }
    if (cleanEmails.length === 0) return res.status(400).json({ error: 'No valid email addresses in the request.' });
    const skipped = emails.length - cleanEmails.length;

    const have = store.getUserCredits(req.user.id);
    if (have < cleanEmails.length) {
        return res.status(402).json({ error: `Not enough tokens. Need ${cleanEmails.length}, have ${have}.` });
    }
    const d = store.deductToken(req.user.id, cleanEmails.length);
    if (!d.ok) return res.status(402).json({ error: 'Insufficient tokens.' });

    const results = [];
    const batchSize = 20;
    for (let i = 0; i < cleanEmails.length; i += batchSize) {
        const batch = cleanEmails.slice(i, i + batchSize);
        const batchResults = await Promise.all(batch.map(async email => {
            try {
                const r = await verifier.verifyEmail(email);
                return {
                    email,
                    status:        r.status,
                    safe_to_send:  r.safeToSend !== undefined ? r.safeToSend : (r.status === 'safe' || r.status === 'valid'),
                    overall_score: r.overallScore,
                    reason:        r.reasonCode,
                    provider:      r.mxProvider || r.providerType,
                    category:      r.emailCategory || 'Professional',
                    mx_records:    r.mxRecords || '',
                    flags:         r.flags || {},
                };
            } catch {
                return { email, status: 'error', safe_to_send: false, reason: 'verification_failed' };
            }
        }));
        results.push(...batchResults);
    }
    res.json({
        total:           results.length,
        valid:           results.filter(r => r.status === 'safe' || r.status === 'valid').length,
        invalid:         results.filter(r => r.status === 'invalid').length,
        unknown:         results.filter(r => r.status === 'unknown').length,
        catch_all:       results.filter(r => r.status === 'catch_all').length,
        skipped,
        results,
        tokensRemaining: store.getUserCredits(req.user.id),
    });
});

// ======================== BULK UPLOAD ========================

// Shared job-creation helper — used by both file upload and typed-text upload.
// Returns { jobId, total } on success, or { error, status } on failure.
function createVerificationJob(userId, validEmails, filename, originalColumns, originalData) {
    const MAX_EMAILS_PER_UPLOAD = 100000;
    if (validEmails.length > MAX_EMAILS_PER_UPLOAD) {
        return { status: 413, error: `Too many emails (${validEmails.length}). Maximum ${MAX_EMAILS_PER_UPLOAD.toLocaleString()} per upload — split your list.` };
    }
    const userCredits = store.getUserCredits(userId);
    if (userCredits < validEmails.length) {
        return { status: 402, error: `Not enough credits. You have ${userCredits} but need ${validEmails.length}. Please upgrade.` };
    }
    // Per-user concurrent job limit — 1 active job at a time
    const userHasActiveJob = Object.values(activeJobs).some(
        j => j.userId === userId && j.status === 'running'
    );
    if (userHasActiveJob) {
        return { status: 429, error: 'You already have a job running. Wait for it to complete.' };
    }
    // Global concurrent-job cap
    const MAX_CONCURRENT_JOBS = 20;
    const runningJobs = Object.values(activeJobs).filter(j => j.status === 'running').length;
    if (runningJobs >= MAX_CONCURRENT_JOBS) {
        return { status: 503, error: 'Server is at capacity. Please try again in a moment.' };
    }

    const jobId = crypto.randomUUID();
    activeJobs[jobId] = {
        userId, emails: validEmails,
        processed: 0, valid: 0, invalid: 0, unknown: 0, catchAll: 0,
        results: [], recentValid: [], recentInvalid: [],
        status: 'running', createdAt: Date.now(),
        filename: filename || '',
        originalColumns: originalColumns || null,
        originalData: originalData || {},
        resultFile: path.join(os.tmpdir(), `truesendy_job_${jobId}.jsonl`),
    };
    try { fs.writeFileSync(activeJobs[jobId].resultFile, ''); } catch {}
    processJob(jobId).catch(err => {
        console.error('[TrueSendy] processJob unhandled:', err.message);
        if (activeJobs[jobId]) activeJobs[jobId].status = 'error';
    });
    return { jobId, total: validEmails.length };
}

app.post('/api/upload', authMiddleware, upload.single('list'), validateUpload, async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const emails = new Set();
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const ext = path.extname(req.file.originalname).toLowerCase();

    // Preserve original file columns for structured files (CSV / XLSX).
    // originalColumns = ['Company','Name',...], originalData = { 'email': {Company:'..',...} }
    let originalColumns = null;
    let originalData = {};

    try {
        let rawText = '';
        if (ext === '.xlsx' || ext === '.xls') {
            // Use ExcelJS (secure alternative to xlsx)
            const wb = new ExcelJS.Workbook();
            await wb.xlsx.readFile(req.file.path);
            const firstWS = wb.worksheets[0];
            if (firstWS) {
                // Get headers from row 1 (ExcelJS row.values is 1-indexed, index 0 is undefined)
                const headerRow = (firstWS.getRow(1).values || []).slice(1).map(h => String(h || ''));
                if (headerRow.length) {
                    originalColumns = headerRow;
                    firstWS.eachRow((row, rowNum) => {
                        if (rowNum === 1) return; // skip header
                        const obj = {};
                        headerRow.forEach((h, i) => { obj[h] = String(row.getCell(i + 1).text || ''); });
                        const emailVal = Object.values(obj).find(v => emailRegex.test(String(v)));
                        if (emailVal) {
                            const lc = String(emailVal).toLowerCase().trim();
                            emails.add(lc);
                            originalData[lc] = obj;
                        }
                    });
                }
            }
            // Fallback: scan all sheets as raw text (catches emails outside tables)
            wb.worksheets.forEach(ws => {
                ws.eachRow(row => {
                    row.eachCell(cell => { rawText += String(cell.text || '') + ','; });
                    rawText += ' ';
                });
            });
            const found = rawText.match(emailRegex);
            if (found) found.forEach(e => emails.add(e.toLowerCase().trim()));
        } else if (ext === '.csv') {
            const fileText = fs.readFileSync(req.file.path, 'utf8');
            // Parse CSV into rows to preserve columns
            const lines = fileText.split(/\r?\n/).filter(l => l.trim());
            if (lines.length) {
                const parseLine = (line) => {
                    const cells = [];
                    let cur = '', inQ = false;
                    for (let i = 0; i < line.length; i++) {
                        const ch = line[i];
                        if (ch === '"') { inQ = !inQ; continue; }
                        if (ch === ',' && !inQ) { cells.push(cur); cur = ''; continue; }
                        cur += ch;
                    }
                    cells.push(cur);
                    return cells;
                };
                const headerCells = parseLine(lines[0]).map(c => c.trim());
                // Does the header look like a real header row? (contains non-email text)
                const headerLooksReal = headerCells.some(c => c && !emailRegex.test(c) && isNaN(c));
                if (headerLooksReal) {
                    originalColumns = headerCells;
                    const startIdx = 1; // skip header
                    for (let i = startIdx; i < lines.length; i++) {
                        const cells = parseLine(lines[i]);
                        const row = {};
                        headerCells.forEach((h, idx) => { row[h] = (cells[idx] || '').trim(); });
                        const emailVal = cells.find(c => emailRegex.test(c));
                        if (emailVal) {
                            const lc = emailVal.toLowerCase().trim();
                            emails.add(lc);
                            originalData[lc] = row;
                        }
                    }
                }
            }
            rawText = fileText; // also do a catch-all regex scan
            const found = rawText.match(emailRegex);
            if (found) found.forEach(e => emails.add(e.toLowerCase().trim()));
        } else if (ext === '.pdf') {
            const dataBuffer = fs.readFileSync(req.file.path);
            const data = await pdfParse(dataBuffer);
            rawText = data.text;
        } else if (ext === '.docx') {
            const result = await mammoth.extractRawText({ path: req.file.path });
            rawText = result.value;
        } else {
            rawText = fs.readFileSync(req.file.path, 'utf8');
        }
        // Catch-all regex scan for any format
        if (ext !== '.csv' && ext !== '.xlsx' && ext !== '.xls') {
            const found = rawText.match(emailRegex);
            if (found) found.forEach(e => emails.add(e.toLowerCase().trim()));
        }
    } catch (e) {
        console.error('Extraction error:', e);
        try { fs.unlinkSync(req.file.path); } catch (_) {}
        return res.status(500).json({ error: 'Failed to parse the file.' });
    }

    try { fs.unlinkSync(req.file.path); } catch (_) {}

    const validEmails = Array.from(emails);
    if (!validEmails.length) {
        return res.status(400).json({ error: 'No valid email addresses found in this file.' });
    }

    const job = createVerificationJob(req.user.id, validEmails, req.file.originalname, originalColumns, originalData);
    if (job.error) return res.status(job.status).json({ error: job.error });
    res.json({ jobId: job.jobId, total: job.total });

});

// ── Typed/pasted emails upload ───────────────────────────────────────────────
// For users who want to type or paste emails directly instead of uploading a file.
app.post('/api/upload-text', authMiddleware, async (req, res) => {
    const { text } = req.body || {};
    if (!text || typeof text !== 'string') {
        return res.status(400).json({ error: 'No emails provided.' });
    }
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const found = text.match(emailRegex);
    if (!found || !found.length) {
        return res.status(400).json({ error: 'No valid email addresses found in your text.' });
    }
    const emails = new Set();
    found.forEach(e => emails.add(e.toLowerCase().trim()));
    const validEmails = Array.from(emails);

    const job = createVerificationJob(req.user.id, validEmails, 'Typed emails', null, {});
    if (job.error) return res.status(job.status).json({ error: job.error });
    res.json({ jobId: job.jobId, total: job.total });
});

// ── Disk-backed result storage ───────────────────────────────────────────────
// Instead of holding every result in memory (100k results ≈ 100MB / job),
// each verified email is appended as one JSON line to a temp file. The
// download endpoint streams it back. This keeps memory flat regardless of
// list size — 100 emails or 100,000.
function appendResult(job, data) {
    try {
        fs.appendFileSync(job.resultFile, JSON.stringify(data) + '\n');
    } catch (e) {
        // Disk write failed — fall back to memory so the result isn't lost
        job.results.push(data);
    }
    // Keep a small in-memory rolling buffer (live feed preview only)
    job.results.push(data);
    if (job.results.length > 500) job.results.length = 500;
}

// Read all results for a job from disk (fallback to in-memory buffer).
function readJobResults(job) {
    try {
        if (job.resultFile && fs.existsSync(job.resultFile)) {
            const text = fs.readFileSync(job.resultFile, 'utf8');
            return text.trim().split('\n').filter(Boolean).map(l => {
                try { return JSON.parse(l); } catch { return null; }
            }).filter(Boolean);
        }
    } catch (e) {
        console.warn('[TrueSendy] readJobResults fell back to memory:', e.message);
    }
    return job.results || [];
}



app.get('/api/progress/:jobId', authMiddleware, (req, res) => {
    const job = activeJobs[req.params.jobId];
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.userId !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    res.json({
        processed: job.processed,
        total: job.emails.length,
        valid: job.valid,
        invalid: job.invalid,
        unknown: job.unknown || 0,
        catchAll: job.catchAll || 0,
        status: job.status,
        recentValid: job.recentValid,
        recentInvalid: job.recentInvalid,
    });
});

// ======================== BULK PROCESSOR ========================

// ── [FIX #6] Wrap processJob — unhandled crash = Node process dies
async function processJob(jobId) {
    const job = activeJobs[jobId];
    if (!job) return;

    // ── Concurrency: 5 workers.
    // Matches SMTP capacity (5 slots) + M365 API (2 concurrent).
    // Lower concurrency = fewer simultaneous probes = less rate-limiting
    // = more accurate results. Speed trade-off is acceptable (~3-4 min for 246 emails).
    const CONCURRENCY = 5;
    let index = 0;

    // ── [FIX #5] Global 30-minute job timeout — kills runaway jobs
    const jobTimeout = setTimeout(() => {
        if (job.status === 'running') {
            job.status = 'expired';
            console.warn(`[TrueSendy] Job ${jobId} expired after 30min`);
        }
    }, 30 * 60 * 1000);

    async function worker() {
        while (true) {
            const i = index++;
            if (i >= job.emails.length) break;
            if (job.status !== 'running') break;

            if (!store.deductToken(job.userId, 1).ok) {
                job.status = 'out_of_credits';
                break;
            }

            const email = job.emails[i];
            try {
                const data = await verifier.verifyEmail(email);
                // Write to disk (handles 100k+ without memory blowup) + keep a
                // small rolling buffer for the live feed.
                appendResult(job, data);
                // 'safe' and 'valid' (role) are both deliverable → count as valid
                // 'catch_all' is a separate category (like Reon)
                // 'unknown' is unverifiable
                if (data.status === 'safe' || data.status === 'valid') {
                    job.valid++;
                    job.recentValid.unshift(email);
                    if (job.recentValid.length > 5) job.recentValid.pop();
                } else if (data.status === 'catch_all') {
                    job.catchAll = (job.catchAll || 0) + 1;
                    job.recentInvalid.unshift({ email, reason: data.reasonCode });
                    if (job.recentInvalid.length > 5) job.recentInvalid.pop();
                } else if (data.status === 'unknown') {
                    job.unknown = (job.unknown || 0) + 1;
                    job.recentInvalid.unshift({ email, reason: data.reasonCode });
                    if (job.recentInvalid.length > 5) job.recentInvalid.pop();
                } else {
                    job.invalid++;
                    job.recentInvalid.unshift({ email, reason: data.reasonCode });
                    if (job.recentInvalid.length > 5) job.recentInvalid.pop();
                }
            } catch (err) {
                console.error(`[TrueSendy] verify error "${email}":`, err.message);
                // Refund the credit — the verification failed on our end, the user
                // shouldn't lose a paid credit for an internal error. (Matches the
                // single-email /api/verify-single behavior at line 677.)
                try {
                    const refunded = store.refundToken(job.userId, 1);
                    if (!refunded) console.warn(`[TrueSendy] Refund failed for ${email} (user ${job.userId}) — credit may be lost.`);
                } catch (refundErr) {
                    console.warn(`[TrueSendy] Refund error for ${email}:`, refundErr.message);
                }
                const errData = {
                    email, domain: email.split('@')[1] || 'unknown',
                    providerType: 'Unknown', mxProvider: null, emailCategory: 'Unknown',
                    status: 'invalid', reasonCode: 'internal_error',
                    flags: { disposable: false, roleBased: false, catchAll: false },
                };
                appendResult(job, errData);
                job.invalid++;
                job.recentInvalid.unshift({ email, reason: 'internal_error' });
                if (job.recentInvalid.length > 5) job.recentInvalid.pop();
            }
            job.processed++;
        }
    }

    try {
        const workers = Array.from({ length: CONCURRENCY }, () => worker());
        await Promise.all(workers);
        if (job.status === 'running') job.status = 'complete';
    } catch (err) {
        // ── [FIX #6] Never let processJob crash the Node process
        console.error(`[TrueSendy] processJob ${jobId} fatal error:`, err.message);
        job.status = 'error';
    } finally {
        clearTimeout(jobTimeout);
        // Persist a summary to the user's job history (Tasks & Results panel)
        if (job.status === 'complete' || job.status === 'out_of_credits') {
            try {
                store.recordJobSummary(job.userId, {
                    id: jobId,
                    total: job.processed,
                    valid: job.valid,
                    invalid: job.invalid,
                    unknown: job.unknown || 0,
                    catchAll: job.catchAll || 0,
                    filename: job.filename || '',
                    status: job.status,
                });
            } catch (e) {
                console.warn('[TrueSendy] Could not record job summary:', e.message);
            }
        }
    }
}

// ======================== DOWNLOAD ========================

app.get('/api/download/:jobId', authMiddleware, async (req, res) => {
    const job = activeJobs[req.params.jobId];
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.userId !== req.user.id) return res.status(403).json({ error: 'Access denied' });
    if (job.status !== 'complete' && job.status !== 'out_of_credits') {
        return res.status(400).json({ error: 'Job still processing.' });
    }

    const format = req.query.format || 'csv';
    const category = req.query.category || 'valid'; // valid | invalid | all

    // Read results from disk (handles 100k+ without memory blowup)
    const allResults = readJobResults(job);

    // Filter results by category (valid / invalid / unknown / all / catch_all)
    // New status system: safe | valid (role) | catch_all | invalid | unknown
    let results;
    if (category === 'all') {
        results = allResults;
    } else if (category === 'invalid') {
        results = allResults.filter(r => r.status === 'invalid');
    } else if (category === 'unknown') {
        results = allResults.filter(r => r.status === 'unknown');
    } else if (category === 'catch_all') {
        results = allResults.filter(r => r.status === 'catch_all');
    } else {
        // 'valid' download = "safe" (confirmed deliverable) + "valid" (role accounts, also deliverable)
        results = allResults.filter(r => r.status === 'safe' || r.status === 'valid');
    }

    // "Original" format — the uploaded file EXACTLY as-is + a single
    // Verification_Status column (valid/invalid) inserted RIGHT NEXT TO the
    // email column. No other columns added, no original data removed.
    // Only available when original columns exist.
    if (format === 'original' && job.originalColumns && job.originalColumns.length) {
        const origCols = job.originalColumns;
        const origLookup = job.originalData || {};

        // Find the email column index — the column whose header looks like
        // "email" / "e-mail" / "email address", or falls back to the column
        // that contains the verified email value.
        const emailRegexCol = /[ \t]*e-?mail[ \t]*(address)?$/i;
        let emailColIdx = origCols.findIndex(c => emailRegexCol.test(c));
        if (emailColIdx === -1) {
            // Fallback: find the column holding the email for the first result
            const firstEmail = results[0] && results[0].email;
            if (firstEmail) {
                emailColIdx = origCols.findIndex(c => {
                    const sample = origLookup[firstEmail];
                    return sample && String(sample[c] || '').toLowerCase().trim() === firstEmail;
                });
            }
        }
        // If still not found, default to appending at the end
        const insertAt = emailColIdx === -1 ? origCols.length : emailColIdx + 1;

        // Build headers with Verification_Status inserted right after the email
        const headers = [...origCols];
        headers.splice(insertAt, 0, 'Verification_Status');

        const rows = results.map(r => {
            const orig = origLookup[r.email] || {};
            const vals = origCols.map(c => orig[c] !== undefined ? String(orig[c]) : '');
            // Insert "valid"/"invalid" right after the email column
            vals.splice(insertAt, 0, r.status || 'unknown');
            return vals;
        });

        const fname = `truesendy_verified_${req.params.jobId}.csv`;
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
        return res.send([headers.join(','), ...rows.map(r => r.map(c => `"${c.replace(/"/g,'""')}"`).join(','))].join('\n'));
    }

    // TXT format — just email list (like competitor)
    if (format === 'txt') {
        const fname = `truesendy_${category}_${req.params.jobId}.txt`;
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
        return res.send(results.map(r => r.email).join('\n'));
    }

    // CSV / Excel — rich columns with ALL verification data (like competitor)
    // If the uploaded file had structured columns, preserve them FIRST.
    const hasOrig = job.originalColumns && job.originalColumns.length;
    const origCols = hasOrig ? job.originalColumns : [];
    const origLookup = job.originalData || {};

    // Avoid duplicate "Email" column: if the original file already has an email
    // column (case-insensitive), drop it from the verification headers.
    const origHasEmail = origCols.some(c => /^e-?mail$/i.test(c));

    // Helper: derive safe_to_send from the new classifier field or fall back to status
    const isSafe = (r) => {
        // New classifier sets r.safeToSend explicitly
        if (r.safeToSend !== undefined) return r.safeToSend;
        // Fallback for any legacy results still in memory
        return r.status === 'safe' || r.status === 'valid';
    };

    // Helper: was SMTP connection possible?
    const canSmtp = (r) => {
        if (r.reasonCode === 'mx_exists_smtp_blocked') return 'false';
        if (r.status === 'safe' || r.status === 'valid') return 'true';
        if (r.reasonCode === 'smtp_accepted' || r.reasonCode === 'mailbox_full') return 'true';
        if (r.status === 'invalid' && r.reasonCode !== 'no_mx_record') return 'true';
        return 'false';
    };

    // ── Reon-compatible column headers ─────────────────────────────────────
    // Match Reon's exact CSV format: email, username, domain, status, overall_score,
    // is_safe_to_send, is_valid_syntax, is_disposable, is_role_account, mx_accepts_mail,
    // mx_records, can_connect_smtp, has_inbox_full, is_catch_all, is_deliverable,
    // is_disabled, is_spamtrap, is_free_email, is_forwarded
    const verifHeaders = origHasEmail
        ? ['username', 'domain', 'status', 'overall_score',
           'is_safe_to_send', 'is_valid_syntax', 'is_disposable', 'is_role_account',
           'mx_accepts_mail', 'mx_records', 'can_connect_smtp', 'has_inbox_full',
           'is_catch_all', 'is_deliverable', 'is_disabled', 'is_spamtrap',
           'is_free_email', 'is_forwarded']
        : ['email', 'username', 'domain', 'status', 'overall_score',
           'is_safe_to_send', 'is_valid_syntax', 'is_disposable', 'is_role_account',
           'mx_accepts_mail', 'mx_records', 'can_connect_smtp', 'has_inbox_full',
           'is_catch_all', 'is_deliverable', 'is_disabled', 'is_spamtrap',
           'is_free_email', 'is_forwarded'];

    const headers = [...origCols, ...verifHeaders];

    const rows = results.map(r => {
        const orig = origLookup[r.email] || {};
        const origVals = origCols.map(c => orig[c] !== undefined ? String(orig[c]) : '');
        const safeVal = isSafe(r) ? 'true' : 'false';
        const scoreVal = r.overallScore !== undefined ? String(r.overallScore) : (r.status === 'safe' ? '98' : r.status === 'valid' ? '85' : r.status === 'catch_all' ? '75' : r.status === 'invalid' ? '3' : '30');
        const freeEmail = r.flags?.freeEmail ? 'true' : 'false';
        const mxAccepts = (r.status !== 'invalid' || r.reasonCode !== 'no_mx_record') ? 'true' : 'false';
        const canSmtpVal = canSmtp(r);
        const username = (r.email || '').split('@')[0] || '';
        const isDeliverable = (r.status === 'safe' || r.status === 'valid' || r.status === 'catch_all') ? 'true' : 'false';
        const isDisabled = r.reasonCode === 'mailbox_disabled' ? 'true' : 'false';
        const isInboxFull = r.reasonCode === 'mailbox_full' ? 'true' : 'false';
        const mxRecordsVal = r.mxRecords || '';

        const verifVals = origHasEmail
            ? [
                username,
                r.domain || '',
                r.status || 'unknown',
                scoreVal,
                safeVal,
                'true',
                r.flags?.disposable ? 'true' : 'false',
                r.flags?.roleBased ? 'true' : 'false',
                mxAccepts,
                mxRecordsVal,
                canSmtpVal,
                isInboxFull,
                r.flags?.catchAll ? 'true' : 'false',
                isDeliverable,
                isDisabled,
                'false',
                freeEmail,
                'false',
            ]
            : [
                r.email || '',
                username,
                r.domain || '',
                r.status || 'unknown',
                scoreVal,
                safeVal,
                'true',
                r.flags?.disposable ? 'true' : 'false',
                r.flags?.roleBased ? 'true' : 'false',
                mxAccepts,
                mxRecordsVal,
                canSmtpVal,
                isInboxFull,
                r.flags?.catchAll ? 'true' : 'false',
                isDeliverable,
                isDisabled,
                'false',
                freeEmail,
                'false',
            ];
        return [...origVals, ...verifVals];
    });

    const sheetName = category === 'all' ? 'All Results'
        : category === 'valid' ? 'Valid Emails'
        : category === 'unknown' ? 'Unknown Emails'
        : category === 'catch_all' ? 'Catch All Emails'
        : 'Invalid Emails';

    if (format === 'excel') {
        // Use ExcelJS (secure, no known vulnerabilities)
        const wb2 = new ExcelJS.Workbook();
        const ws2 = wb2.addWorksheet(sheetName);
        ws2.addRow(headers);
        rows.forEach(r => ws2.addRow(r));
        const buf = await wb2.xlsx.writeBuffer();
        const fname = `truesendy_${category}_${req.params.jobId}.xlsx`;
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
        return res.send(buf);
    }

    // CSV
    const fname = `truesendy_${category}_${req.params.jobId}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.send([headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n'));
});

// ======================== API v1 — PUBLIC API (Agency Plan) ========================

// Middleware: validate API key from header
function apiKeyAuth(req, res, next) {
    const key = req.headers['x-api-key'] || req.query.api_key;
    if (!key || typeof key !== 'string' || key.length > 80) {
        return res.status(401).json({ error: 'Missing API key. Buy one at truesendy.com/key.' });
    }
    // Only accept keys matching our format
    if (!/^ts_[a-f0-9]{48}$/.test(key)) {
        return res.status(401).json({ error: 'This is not a valid TrueSendy key. Keys start with "ts_" and come from truesendy.com/key.' });
    }
    const result = store.validateApiKey(key);
    if (result.error) return res.status(401).json({ error: result.error });
    req.apiKey = key;
    req.apiRecord = result.record;
    next();
}

// All API v1 routes: rate limited per API key
app.get('/api/v1/balance', apiLimiter, apiKeyAuth, (req, res) => {
    const st = store.getUserTokenStatus(req.apiRecord.userId);
    if (!st) return res.status(404).json({ error: 'User not found.' });
    res.json({
        tokens: st.total,
        tokensUsed: st.tokensUsed,
        expiresAt: null,
        daysRemaining: null,
    });
});

// Verify single email via API
app.post('/api/v1/verify', apiLimiter, apiKeyAuth, async (req, res) => {
    const { email } = req.body;
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required.' });

    const d = store.deductToken(req.apiRecord.userId, 1);
    if (!d.ok) return res.status(402).json({ error: 'Insufficient tokens.' });

    try {
        const result = await verifier.verifyEmail(email);
        store.stampApiUse(req.apiRecord.userId);
        res.json({
            email:           result.email,
            status:          result.status,
            safe_to_send:    result.safeToSend !== undefined ? result.safeToSend : (result.status === 'safe' || result.status === 'valid'),
            overall_score:   result.overallScore !== undefined ? result.overallScore : undefined,
            reason:          result.reasonCode,
            provider:        result.mxProvider || result.providerType,
            category:        result.emailCategory || 'Professional',
            mx_records:      result.mxRecords || '',
            flags:           result.flags || {},
            tokensRemaining: store.getUserCredits(req.apiRecord.userId),
        });
    } catch (e) {
        store.refundToken(req.apiRecord.userId, 1);
        res.status(500).json({ error: 'Verification failed: ' + e.message });
    }
});

// Verify bulk emails via API
app.post('/api/v1/verify-bulk', apiLimiter, apiKeyAuth, async (req, res) => {
    const { emails } = req.body;
    if (!Array.isArray(emails) || emails.length === 0) {
        return res.status(400).json({ error: 'Provide an array of emails.' });
    }
    if (emails.length > 500) {
        return res.status(400).json({ error: 'Maximum 500 emails per request.' });
    }

    // Dedupe + syntax-validate so the user isn't charged for duplicates or garbage.
    const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,63}$/;
    const seen = new Set();
    const cleanEmails = [];
    for (const e of emails) {
        if (typeof e === 'string' && EMAIL_RE.test(e)) {
            const lc = e.toLowerCase().trim();
            if (!seen.has(lc)) { seen.add(lc); cleanEmails.push(lc); }
        }
    }
    if (cleanEmails.length === 0) {
        return res.status(400).json({ error: 'No valid email addresses in the request.' });
    }
    const skipped = emails.length - cleanEmails.length;

    // Check + deduct from the shared balance — only for the valid, unique set
    const have = store.getUserCredits(req.apiRecord.userId);
    if (have < cleanEmails.length) {
        return res.status(402).json({ error: `Not enough tokens. Need ${cleanEmails.length}, have ${have}.` });
    }
    const d = store.deductToken(req.apiRecord.userId, cleanEmails.length);
    if (!d.ok) return res.status(402).json({ error: 'Insufficient tokens.' });

    // Verify concurrently (max 20 at a time)
    const results = [];
    const batchSize = 20;
    for (let i = 0; i < cleanEmails.length; i += batchSize) {
        const batch = cleanEmails.slice(i, i + batchSize);
        const batchResults = await Promise.all(
            batch.map(async email => {
                try {
                    const r = await verifier.verifyEmail(email);
                    return {
                        email:         r.email,
                        status:        r.status,
                        safe_to_send:  r.safeToSend !== undefined ? r.safeToSend : (r.status === 'safe' || r.status === 'valid'),
                        overall_score: r.overallScore,
                        reason:        r.reasonCode,
                        provider:      r.mxProvider || r.providerType,
                        category:      r.emailCategory || 'Professional',
                        mx_records:    r.mxRecords || '',
                        flags:         r.flags || {},
                    };
                } catch {
                    return { email, status: 'error', safe_to_send: false, reason: 'verification_failed' };
                }
            })
        );
        results.push(...batchResults);
    }

    store.stampApiUse(req.apiRecord.userId);
    res.json({
        total:           results.length,
        valid:           results.filter(r => r.status === 'safe' || r.status === 'valid').length,
        invalid:         results.filter(r => r.status === 'invalid').length,
        unknown:         results.filter(r => r.status === 'unknown').length,
        catch_all:       results.filter(r => r.status === 'catch_all').length,
        skipped,
        results,
        tokensRemaining: store.getUserCredits(req.apiRecord.userId),
    });
});

// ======================== API KEY MANAGEMENT (logged-in users) ========================

// Generate API key (Agency plan only)
app.post('/api/keys/generate', authMiddleware, (req, res) => {
    const result = store.generateApiKey(req.user.id);
    if (result.error) return res.status(403).json({ error: result.error });
    res.json({
        key: result.apiKey.key,
        tokens: result.apiKey.tokens,
        expiresAt: result.apiKey.expiresAt,
        message: 'API key generated. Store it securely — it will only be shown once.',
    });
});

// List user's API keys
app.get('/api/keys', authMiddleware, (req, res) => {
    const keys = store.getUserApiKeys(req.user.id);
    res.json({ keys });
});

// Revoke API key
app.post('/api/keys/revoke', authMiddleware, (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ error: 'Key required.' });
    const ok = store.revokeApiKey(key);
    if (!ok) return res.status(404).json({ error: 'Key not found.' });
    res.json({ success: true, message: 'API key revoked.' });
});

// ======================== VERIFICATION KEY STORE (one-time purchase) ========================

// Public — price + allowance shown on the /key purchase page
app.get('/api/key-price', (req, res) => {
    const product = settings.getKeyProduct();
    res.json({
        priceUsd:         product.priceUsd,
        tokens:           product.tokens,
        validityDays:     product.validityDays,
        currency:         product.currency || 'usd',
        stripeConfigured: pricing.isStripeConfigured(),
    });
});

// Returns the 6 preset credit packages for the checkout page.
app.get('/api/packages', (req, res) => {
    res.json({
        packages:         settings.getPackages(),
        validityDays:     settings.getKeyProduct().validityDays,
        stripeConfigured: pricing.isStripeConfigured(),
    });
});

// Calculate the price for a custom credit amount (the slider on /buycredits).
// Price is computed server-side so it can't be tampered with from the browser.
app.get('/api/calculate-price', (req, res) => {
    const tokens = parseInt(req.query.tokens, 10);
    const calc = pricing.calculatePrice(tokens);
    if (!calc) return res.status(400).json({ error: 'Amount must be between 100 and 100,000.' });
    res.json(calc);
});

// Buy a CUSTOM credit amount (from the slider). Authenticated users only —
// the dashboard Buy Credits page uses this.
app.post('/api/keys/custom-checkout', authMiddleware, async (req, res) => {
    const { tokens } = req.body || {};
    const origin = req.headers.origin || `http://localhost:${PORT}`;
    if (pricing.isStripeConfigured()) {
        const result = await pricing.createCustomCheckoutSession(
            `${origin}/dashboard?success=1`,
            `${origin}/buycredits?canceled=1`,
            req.user.email,
            req.user.id,
            tokens
        );
        if (result.error) return res.status(400).json(result);
        return res.json({ checkoutUrl: result.url, sessionId: result.sessionId });
    }
    // Dev mode — grant the credits immediately without payment.
    if (process.env.ALLOW_DEV_PAYMENTS !== 'true') {
        return res.status(503).json({ error: 'Payments are not configured. Please contact support.' });
    }
    const calc = pricing.calculatePrice(tokens);
    if (!calc) return res.status(400).json({ error: 'Invalid amount.' });
    const result = store.purchaseApiKey(req.user.id, calc.tokens);
    if (result.error) return res.status(400).json(result);
    res.json({ devMode: true, message: 'Dev mode — credits granted.', tokens: calc.tokens });
});

// [SUPERSEDED — kept for logged-in buyers] The public /key → /checkout flow now uses
// /api/keys/guest-checkout (no login). This route still works for an authenticated user.
app.post('/api/keys/purchase-checkout', authMiddleware, async (req, res) => {
    const origin = req.headers.origin || `http://localhost:${PORT}`;
    const { packageId } = req.body || {};

    // Resolve selected package (null = default keyProduct)
    const pkg = packageId ? settings.getPackage(packageId) : null;
    if (packageId && !pkg) {
        return res.status(400).json({ error: 'Invalid package selected.' });
    }

    if (pricing.isStripeConfigured()) {
        const result = await pricing.createKeyCheckoutSession(
            `${origin}/key?success=1`,
            `${origin}/key?canceled=1`,
            req.user.email,
            req.user.id,
            pkg
        );
        if (result.error) return res.status(400).json(result);
        return res.json({ checkoutUrl: result.url, sessionId: result.sessionId });
    }

    // Stripe not configured — require the explicit dev-payments opt-in to mint
    // a key locally. Without this gate, /key would hand out free keys.
    if (process.env.ALLOW_DEV_PAYMENTS !== 'true') {
        return res.status(503).json({ error: 'Payments are not configured on this server. Please contact support.' });
    }

    const product = settings.getKeyProduct();
    const tokens  = pkg ? Number(pkg.tokens) : product.tokens;
    const result = store.purchaseApiKey(req.user.id, tokens);
    if (result.error) return res.status(400).json(result);
    await sendApiKeyEmail(req.user.email, result.apiKey.key, tokens, product.validityDays);
    res.json({
        devMode: true,
        message: 'Dev mode — key created without payment.',
        key: result.apiKey.key,
        tokens,
        validityDays: product.validityDays,
    });
});

// ── Guest checkout: buy a key WITHOUT logging in. Buyer enters an email on the
// /checkout page, pays via the admin-configured Stripe; the webhook verifies
// payment and emails the key. find-or-create handles the account so the unified
// token balance still backs the key.
app.post('/api/keys/guest-checkout', async (req, res) => {
    const { email, packageId } = req.body || {};
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    const cleanEmail = String(email).toLowerCase().trim();
    const origin = req.headers.origin || `http://localhost:${PORT}`;

    // Resolve the selected package (falls back to default 100k if none specified)
    const pkg = packageId ? settings.getPackage(packageId) : null;
    if (packageId && !pkg) {
        return res.status(400).json({ error: 'Invalid package selected.' });
    }

    if (pricing.isStripeConfigured()) {
        const result = await pricing.createKeyCheckoutSession(
            `${origin}/checkout?success=1&email=${encodeURIComponent(cleanEmail)}`,
            `${origin}/checkout?canceled=1`,
            cleanEmail,
            null,                     // no userId — guest purchase; webhook keys on email
            pkg                       // package override (null = use default keyProduct)
        );
        if (result.error) return res.status(400).json(result);
        return res.json({ checkoutUrl: result.url, sessionId: result.sessionId });
    }

    // Dev mode — fulfill immediately without payment (testing only).
    if (process.env.ALLOW_DEV_PAYMENTS !== 'true') {
        return res.status(503).json({ error: 'Payments are not configured on this server. Please contact support.' });
    }
    const user   = store.findOrCreateKeyBuyer(cleanEmail);
    const result = store.purchaseApiKey(user.id, pkg ? Number(pkg.tokens) : undefined);
    if (result.error) return res.status(400).json(result);
    const product = settings.getKeyProduct();
    const tokens  = pkg ? Number(pkg.tokens) : product.tokens;
    await sendApiKeyEmail(cleanEmail, result.apiKey.key, tokens, product.validityDays);
    res.json({ devMode: true, message: `Dev mode — key created and emailed to ${cleanEmail} (printed to server console).` });
});

// ======================== CLI TOOL DOWNLOAD ========================

// ======================== ADMIN PAGE ========================
// (Defined once above — no duplicate needed)

// ======================== ADMIN API ========================

// Single unified JWT secret — matches authMiddleware.js
// Same secret as user JWTs (imported from authMiddleware at the top). Has a
// random fallback so the server boots even if JWT_SECRET isn't set as an env var.
const ADMIN_JWT_SECRET = JWT_SECRET;

// Master admin credentials. In production, MASTER_ADMIN_USERNAME + MASTER_ADMIN_PASSWORD
// MUST be set via env vars — no hardcoded default ships (would let anyone with source
// access log in as admin). In development (NODE_ENV !== 'production') a default is
// allowed for convenience.
const _isAdminEnvSet = !!(process.env.MASTER_ADMIN_USERNAME && process.env.MASTER_ADMIN_PASSWORD);
if (!_isAdminEnvSet && process.env.NODE_ENV === 'production') {
    console.error('[TrueSendy][FATAL] MASTER_ADMIN_USERNAME + MASTER_ADMIN_PASSWORD must be set in production. Aborting.');
    process.exit(1);
}
const _adminUser = process.env.MASTER_ADMIN_USERNAME || 'admin';
const _adminPass = process.env.MASTER_ADMIN_PASSWORD || 'truesendy-dev-admin';
if (!_isAdminEnvSet) {
    console.warn('[TrueSendy] DEV ONLY: using default admin (admin / truesendy-dev-admin). Set MASTER_ADMIN_* env vars for production.');
}
const MASTER_ADMIN = { username: _adminUser, password: _adminPass, role: 'master' };

// Admin auth middleware — uses unified ADMIN_JWT_SECRET
function adminAuth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No admin token.' });
    try {
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, ADMIN_JWT_SECRET, { algorithms: ['HS256'] });
        if (!decoded.isAdmin) return res.status(403).json({ error: 'Not an admin.' });
        req.admin = decoded;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid admin token.' });
    }
}

// Admin login — uses unified ADMIN_JWT_SECRET + timing-safe comparison
app.post('/api/admin/login', adminLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username and password required.' });
    }
    if (username.length > 64 || password.length > 128) {
        return res.status(400).json({ error: 'Invalid credentials.' });
    }

    const jwt = require('jsonwebtoken');

    // Check master admin — only if credentials are configured via env vars
    if (MASTER_ADMIN.username && MASTER_ADMIN.password &&
        timingSafeEqual(username, MASTER_ADMIN.username) && timingSafeEqual(password, MASTER_ADMIN.password)) {
        const token = jwt.sign({ isAdmin: true, role: 'master', username: MASTER_ADMIN.username }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
        return res.json({ token, role: 'master', username: MASTER_ADMIN.username });
    }

    // Check sub-admin accounts
    const allUsers = store.getAllUsers();
    const subAdmin = store.findUserByEmail(username) ||
                     allUsers.find(u => u.username === username.toLowerCase());
    if (subAdmin && subAdmin.role === 'subadmin') {
        const fullUser = store.findUserByEmail(subAdmin.email);
        if (fullUser) {
            const valid = await bcrypt.compare(password, fullUser.password);
            if (valid) {
                const token = jwt.sign({ isAdmin: true, role: 'subadmin', username: subAdmin.username, email: subAdmin.email }, ADMIN_JWT_SECRET, { expiresIn: '12h' });
                return res.json({ token, role: 'subadmin', username: subAdmin.username });
            }
        }
    }

    return res.status(401).json({ error: 'Invalid credentials.' });
});

// Admin API routes — all protected by adminLimiter + adminAuth
app.get('/api/admin/stats', adminLimiter, adminAuth, (req, res) => {
    const stats = store.getStats();
    stats.botDownloads = settings.getBotDownloads();   // total exe downloads (from settings)
    res.json(stats);
});

// Get all users
app.get('/api/admin/users', adminLimiter, adminAuth, (req, res) => {
    res.json({ users: store.getAllUsers() });
});

// Update user credits
app.post('/api/admin/users/:id/credits', adminLimiter, adminAuth, (req, res) => {
    const { credits } = req.body;
    const ok = store.updateUserCredits(req.params.id, credits);
    if (!ok) return res.status(404).json({ error: 'User not found.' });
    res.json({ success: true });
});

// Update user plan
app.post('/api/admin/users/:id/plan', adminLimiter, adminAuth, (req, res) => {
    const { plan } = req.body;
    if (!['free', 'starter', 'pro', 'agency'].includes(plan)) {
        return res.status(400).json({ error: 'Invalid plan.' });
    }
    const ok = store.updateUserPlan(req.params.id, plan);
    if (!ok) return res.status(404).json({ error: 'User not found.' });
    res.json({ success: true });
});

// ── Agency approval workflow ──
// User-side: request Agency plan access (no payment — admin approves manually).
app.post('/api/request-agency', authMiddleware, (req, res) => {
    const result = store.requestAgency(req.user.id);
    if (result.error) return res.status(400).json(result);
    res.json(result);
});

// User-side: check Agency request status WITHOUT creating a request.
app.get('/api/agency-status', authMiddleware, (req, res) => {
    const user = store.findUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({
        plan: user.plan || 'free',
        agencyRequested: !!user.agencyRequested,
        canDownload: user.plan === 'agency',
    });
});

// Admin-side: list pending Agency requests.
app.get('/api/admin/agency-requests', adminLimiter, adminAuth, (req, res) => {
    res.json({ requests: store.getPendingAgencyRequests() });
});

// Admin-side: approve a request → grants Agency plan.
app.post('/api/admin/agency-requests/:id/approve', adminLimiter, adminAuth, (req, res) => {
    const result = store.approveAgency(req.params.id);
    if (result.error) return res.status(404).json(result);
    res.json({ success: true });
});

// Admin-side: deny a request.
app.post('/api/admin/agency-requests/:id/deny', adminLimiter, adminAuth, (req, res) => {
    const result = store.denyAgency(req.params.id);
    if (result.error) return res.status(404).json(result);
    res.json({ success: true });
});

// Grant purchased tokens (non-resetting). Used for the tester account + support.
app.post('/api/admin/users/:id/grant-tokens', adminLimiter, adminAuth, (req, res) => {
    const { amount } = req.body || {};
    const n = parseInt(amount, 10);
    if (!n || n <= 0) return res.status(400).json({ error: 'amount must be a positive number.' });
    const ok = store.grantTokens(req.params.id, n);
    if (!ok) return res.status(404).json({ error: 'User not found.' });
    res.json({ success: true, granted: n });
});

// Ban / Unban user
app.post('/api/admin/users/:id/ban', adminLimiter, adminAuth, (req, res) => {
    const { banned } = req.body;
    const ok = store.banUser(req.params.id, !!banned);
    if (!ok) return res.status(404).json({ error: 'User not found.' });
    res.json({ success: true });
});

// ── Support / "control everything" actions on a user ──

// List a user's API keys (masked) — admin visibility
app.get('/api/admin/users/:id/keys', adminLimiter, adminAuth, (req, res) => {
    res.json({ keys: store.getUserApiKeys(req.params.id) });
});

// Revoke one specific key (body: { key } — masked form as shown in the panel)
app.post('/api/admin/users/:id/keys/revoke', adminLimiter, adminAuth, (req, res) => {
    const { key } = req.body || {};
    const ok = store.revokeUserKey(req.params.id, key);
    if (!ok) return res.status(404).json({ error: 'Key not found for this user.' });
    res.json({ success: true });
});

// Manually credit purchased tokens (support / refund-style)
app.post('/api/admin/users/:id/credit', adminLimiter, adminAuth, (req, res) => {
    const { amount } = req.body || {};
    const r = store.creditUserTokens(req.params.id, amount);
    if (r.error) return res.status(400).json({ error: r.error });
    res.json({ success: true, ...r });
});

// Resend the buyer's latest purchased key to their email (recovery when the
// original delivery failed)
app.post('/api/admin/users/:id/resend-key', adminLimiter, adminAuth, async (req, res) => {
    const rec = store.getLatestKeyForUser(req.params.id);
    if (!rec) return res.status(404).json({ error: 'No active purchased key for this user.' });
    const user = store.findUserById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const product = settings.getKeyProduct();
    const ok = await sendApiKeyEmail(user.email, rec.key, product.tokens, product.validityDays);
    if (!ok) return res.status(502).json({ error: 'Email delivery failed. Check SMTP config.' });
    res.json({ success: true, sentTo: user.email });
});

// Delete user (master only)
app.delete('/api/admin/users/:id', adminLimiter, adminAuth, (req, res) => {
    if (req.admin.role !== 'master') return res.status(403).json({ error: 'Only master admin can delete users.' });
    const ok = store.deleteUser(req.params.id);
    if (!ok) return res.status(404).json({ error: 'User not found.' });
    res.json({ success: true });
});

// Create sub-admin (master only)
app.post('/api/admin/subadmin', adminLimiter, adminAuth, async (req, res) => {
    if (req.admin.role !== 'master') return res.status(403).json({ error: 'Only master admin can create sub-admins.' });
    const { email, username, password } = req.body;
    if (!email || !username || !password) return res.status(400).json({ error: 'All fields required.' });
    const result = await store.createSubAdmin(email, username, password);
    if (result.error) return res.status(409).json({ error: result.error });
    res.json({ success: true, user: { email: result.user.email, username: result.user.username, role: 'subadmin' } });
});

// ======================== ADMIN: PRICE MANAGEMENT ========================

app.get('/api/admin/pricing', adminLimiter, adminAuth, (req, res) => {
    res.json(pricing.loadPricing());
});

app.post('/api/admin/pricing', adminLimiter, adminAuth, (req, res) => {
    if (req.admin.role !== 'master') return res.status(403).json({ error: 'Only master admin can update pricing.' });
    const { plan, priceMonthly, priceAnnual } = req.body;
    if (!plan) return res.status(400).json({ error: 'Plan required.' });
    const result = pricing.updatePlanPrice(plan, priceMonthly, priceAnnual);
    if (result.error) return res.status(400).json(result);
    res.json({ success: true, plan: result.plan });
});

// ======================== ADMIN: PAYMENT & KEY SETTINGS (master only) ========================
// The boss manages his Stripe account and the key product here — no redeploy.

app.get('/api/admin/settings', adminLimiter, adminAuth, (req, res) => {
    if (req.admin.role !== 'master') return res.status(403).json({ error: 'Master admin only.' });
    res.json(settings.getMaskedSettings());
});

// Update Stripe keys (boss swaps his account here). A field left blank in the
// request body is treated as "keep current"; an explicit empty string clears it.
app.post('/api/admin/settings/stripe', adminLimiter, adminAuth, (req, res) => {
    if (req.admin.role !== 'master') return res.status(403).json({ error: 'Master admin only.' });
    const { secretKey, webhookSecret } = req.body || {};
    if (secretKey !== undefined && typeof secretKey !== 'string') return res.status(400).json({ error: 'Invalid key.' });
    if (webhookSecret !== undefined && typeof webhookSecret !== 'string') return res.status(400).json({ error: 'Invalid secret.' });
    settings.setStripeKeys(
        secretKey === undefined ? undefined : secretKey.trim(),
        webhookSecret === undefined ? undefined : webhookSecret.trim()
    );
    pricing.resetStripeCache();
    res.json({ success: true, stripe: settings.getMaskedSettings().stripe });
});

// Test the Stripe connection — calls stripe.accounts.retrieve() so the admin can
// verify keys work BEFORE a real transaction. Returns the account ID on success.
app.get('/api/admin/stripe-test', adminLimiter, adminAuth, async (req, res) => {
    if (req.admin.role !== 'master') return res.status(403).json({ error: 'Master admin only.' });
    const stripe = pricing.getStripe();
    if (!stripe) return res.status(400).json({ error: 'Stripe is not configured. Enter your secret key first.' });
    try {
        const account = await stripe.accounts.retrieve();
        res.json({ ok: true, accountId: account.id, country: account.country, email: account.email || '' });
    } catch (err) {
        res.status(400).json({ error: err.message || 'Stripe authentication failed. Check your secret key.' });
    }
});

// Update the key product (price / token allowance / validity).
app.post('/api/admin/settings/key-product', adminLimiter, adminAuth, (req, res) => {
    if (req.admin.role !== 'master') return res.status(403).json({ error: 'Master admin only.' });
    const { priceUsd, tokens, validityDays } = req.body || {};
    const product = settings.setKeyProduct({
        priceUsd:     priceUsd     !== undefined ? Number(priceUsd)     : undefined,
        tokens:       tokens       !== undefined ? Number(tokens)       : undefined,
        validityDays: validityDays !== undefined ? Number(validityDays) : undefined,
    });
    res.json({ success: true, keyProduct: product });
});

// ======================== START ========================

// 404 handler — catch-all for unknown routes
app.use((req, res) => {
    res.status(404).json({ error: 'Not found.' });
});

// Global safe error handler — MUST be last, NEVER leaks stack traces
app.use(safeErrorHandler);

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`[TrueSendy] Live at http://localhost:${PORT}`);
});

// Graceful shutdown (Render / systemd / pm2 send SIGTERM/SIGINT on restart/deploy).
let shuttingDown = false;
function shutdown(sig) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[TrueSendy] ${sig} received — draining connections, then exiting.`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 8000).unref();   // hard exit after 8s if still hung
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
