require('./lib/loadEnv');          // MUST be first: populates process.env before any module reads it
const express     = require('express');
const multer      = require('multer');
const fs          = require('fs');
const path        = require('path');
const crypto      = require('crypto');
const bcrypt      = require('bcryptjs');
const compression = require('compression');
const verifier    = require('./verifier');
const xlsx        = require('xlsx');
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
    '/dashboard'     : path.join(__dirname, 'dashboard.html'),
};

// Verify all files exist at boot — fail loud, not silently at runtime
Object.entries(PAGE_FILES).forEach(([route, fp]) => {
    if (!fs.existsSync(fp)) console.warn(`[TrueSendy] WARNING: missing page file for ${route}: ${fp}`);
});

// ── [FIX #1] activeJobs with TTL — prevents memory leak on long-running servers
const activeJobs = {};
const JOB_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours
setInterval(() => {
    const cutoff = Date.now() - JOB_TTL_MS;
    for (const [id, job] of Object.entries(activeJobs)) {
        if (job.createdAt < cutoff || job.status === 'complete' || job.status === 'expired') {
            delete activeJobs[id];
        }
    }
}, 15 * 60 * 1000).unref(); // Run every 15min, don't block process exit

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

// ── Premium-gated bot download ───────────────────────────────────────────────
// The exe is NOT served as a public static file. Requires ?token=<jwt> of a
// PUBLIC download — anyone can get the bot (standard SaaS pattern: download freely,
// sign in inside the app). Optionally count the download if a token is present.
function serveBotExe(req, res, filePath, filename) {
    // Optional: count the download for the user if they're logged in
    const token = (req.query.token || '').toString();
    if (token) {
        try {
            const jwtLib = require('jsonwebtoken');
            const userId = jwtLib.verify(token, JWT_SECRET, { algorithms: ['HS256'] }).id;
            store.markBotDownloaded(userId);
        } catch { /* not logged in — that's fine, download is public */ }
    }
    settings.incBotDownload();

    if (!fs.existsSync(filePath)) {
        // File not cached on this server — redirect to GitHub release (one-time, cached on next boot).
        return res.redirect(302, 'https://github.com/0ngkur/truesendy/releases/download/v1.1.0/TrueSendy-Setup.exe');
    }
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
}

// ── Boot-time exe fetcher: download the installer from GitHub + cache it locally ──
// so the exe is served from truesendy.com, not a redirect. Runs once on first boot.
const EXE_CACHE_PATH = path.join(__dirname, 'downloads', 'TrueSendy-Setup.exe');
const EXE_GITHUB_URL = 'https://github.com/0ngkur/truesendy/releases/download/v1.1.0/TrueSendy-Setup.exe';
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
                return { email, status: r.status, reason: r.reasonCode, provider: r.mxProvider || r.providerType, flags: r.flags || {} };
            } catch {
                return { email, status: 'error', reason: 'verification_failed' };
            }
        }));
        results.push(...batchResults);
    }
    res.json({
        total: results.length,
        valid: results.filter(r => r.status === 'valid').length,
        invalid: results.filter(r => r.status !== 'valid').length,
        skipped,
        results,
        tokensRemaining: store.getUserCredits(req.user.id),
    });
});

// ======================== BULK UPLOAD ========================

app.post('/api/upload', authMiddleware, upload.single('list'), validateUpload, async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const emails = new Set();
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const ext = path.extname(req.file.originalname).toLowerCase();

    try {
        let rawText = '';
        if (ext === '.xlsx' || ext === '.xls') {
            const workbook = xlsx.readFile(req.file.path);
            workbook.SheetNames.forEach(sheetName => {
                const sheet = workbook.Sheets[sheetName];
                rawText += xlsx.utils.sheet_to_csv(sheet) + ' ';
            });
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
        const found = rawText.match(emailRegex);
        if (found) found.forEach(e => emails.add(e.toLowerCase().trim()));
    } catch (e) {
        console.error('Extraction error:', e);
        try { fs.unlinkSync(req.file.path); } catch (_) {}
        return res.status(500).json({ error: 'Failed to parse the file.' });
    }

    try { fs.unlinkSync(req.file.path); } catch (_) {}

    const validEmails = Array.from(emails);

    // Cap total emails per upload (memory protection against huge files)
    const MAX_EMAILS_PER_UPLOAD = 100000;
    if (validEmails.length > MAX_EMAILS_PER_UPLOAD) {
        return res.status(413).json({ error: `Too many emails (${validEmails.length}). Maximum ${MAX_EMAILS_PER_UPLOAD.toLocaleString()} per upload — split your file.` });
    }

    const userCredits = store.getUserCredits(req.user.id);

    if (userCredits < validEmails.length) {
        return res.status(402).json({ error: `Not enough credits. You have ${userCredits} but need ${validEmails.length}. Please upgrade.` });
    }


    const jobId = crypto.randomUUID();   // unguessable — defeats job-id brute force

    // ── [FIX #4] Per-user concurrent job limit — 1 active job at a time
    const userHasActiveJob = Object.values(activeJobs).some(
        j => j.userId === req.user.id && j.status === 'running'
    );
    if (userHasActiveJob) {
        return res.status(429).json({ error: 'You already have a job running. Wait for it to complete.' });
    }

    // ── Global concurrent-job cap — protects memory + SMTP under platform load
    const MAX_CONCURRENT_JOBS = 20;
    const runningJobs = Object.values(activeJobs).filter(j => j.status === 'running').length;
    if (runningJobs >= MAX_CONCURRENT_JOBS) {
        return res.status(503).json({ error: 'Server is at capacity. Please try again in a moment.' });
    }

    activeJobs[jobId] = {
        userId    : req.user.id,
        emails    : validEmails,
        processed : 0,
        valid     : 0,
        invalid   : 0,
        results   : [],
        recentValid   : [],
        recentInvalid : [],
        status    : 'running',
        createdAt : Date.now(),   // ← required by TTL cleanup
    };
    res.json({ jobId, total: validEmails.length });
    processJob(jobId).catch(err => {
        console.error('[TrueSendy] processJob unhandled:', err.message);
        if (activeJobs[jobId]) activeJobs[jobId].status = 'error';
    });

});

// ======================== PROGRESS ========================

app.get('/api/progress/:jobId', authMiddleware, (req, res) => {
    const job = activeJobs[req.params.jobId];
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.userId !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    res.json({
        processed: job.processed,
        total: job.emails.length,
        valid: job.valid,
        invalid: job.invalid,
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

    // ── [FIX #8] Reduced concurrency: 20 workers max
    // 50 workers × 7s SMTP timeout = 350 open sockets under load — too many
    // 20 workers keeps throughput high while respecting OS socket limits
    const CONCURRENCY = 20;
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
                job.results.push(data);
                if (data.status === 'valid') {
                    job.valid++;
                    job.recentValid.unshift(email);
                    if (job.recentValid.length > 5) job.recentValid.pop();
                } else {
                    job.invalid++;
                    job.recentInvalid.unshift({ email, reason: data.reasonCode });
                    if (job.recentInvalid.length > 5) job.recentInvalid.pop();
                }
            } catch (err) {
                console.error(`[TrueSendy] verify error "${email}":`, err.message);
                job.results.push({
                    email, domain: email.split('@')[1] || 'unknown',
                    providerType: 'Unknown', mxProvider: null, emailCategory: 'Unknown',
                    status: 'invalid', reasonCode: 'internal_error',
                    flags: { disposable: false, roleBased: false, catchAll: false },
                });
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
    }
}

// ======================== DOWNLOAD ========================

app.get('/api/download/:jobId', authMiddleware, (req, res) => {
    const job = activeJobs[req.params.jobId];
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (job.userId !== req.user.id) return res.status(403).json({ error: 'Access denied' });
    if (job.status !== 'complete' && job.status !== 'out_of_credits') {
        return res.status(400).json({ error: 'Job still processing.' });
    }

    const format = req.query.format || 'csv';
    const category = req.query.category || 'valid'; // valid | invalid | all

    // Filter results by category
    let results;
    if (category === 'all') {
        results = job.results;
    } else if (category === 'invalid') {
        results = job.results.filter(r => r.status !== 'valid');
    } else {
        results = job.results.filter(r => r.status === 'valid');
    }

    // TXT format — just email list (like competitor)
    if (format === 'txt') {
        const fname = `truesendy_${category}_${req.params.jobId}.txt`;
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
        return res.send(results.map(r => r.email).join('\n'));
    }

    // CSV / Excel — rich columns with ALL verification data (like competitor)
    const headers = [
        'Email', 'Status', 'Safe_To_Send', 'Category', 'Provider',
        'Reason', 'Domain', 'Is_Disposable', 'Is_Role_Based', 'Is_Catch_All',
        'Is_Free_Email', 'Syntax_Valid', 'MX_Accepts_Mail', 'Can_Connect_SMTP'
    ];

    const rows = results.map(r => [
        r.email || '',
        r.status || 'unknown',
        r.status === 'valid' ? 'true' : 'false',
        r.emailCategory || 'unknown',
        r.mxProvider || r.providerType || 'unknown',
        r.reasonCode || '',
        r.domain || '',
        r.flags?.disposable ? 'true' : 'false',
        r.flags?.roleBased ? 'true' : 'false',
        r.flags?.catchAll ? 'true' : 'false',
        r.emailCategory === 'Free' ? 'true' : 'false',
        'true', // passed syntax check (otherwise wouldn't be verified)
        r.flags?.catchAll ? 'true' : 'true', // MX accepts (otherwise invalid)
        r.status === 'valid' || r.status === 'invalid' ? 'true' : 'false'
    ]);

    const sheetName = category === 'all' ? 'All Results' : category === 'valid' ? 'Valid Emails' : 'Invalid Emails';

    if (format === 'excel') {
        const ws = xlsx.utils.aoa_to_sheet([headers, ...rows]);
        const wb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(wb, ws, sheetName);
        const buf = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
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
            email: result.email,
            status: result.status,
            reason: result.reasonCode,
            provider: result.mxProvider || result.providerType,
            category: result.emailCategory || 'unknown',
            flags: result.flags || {},
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
                        email: r.email,
                        status: r.status,
                        reason: r.reasonCode,
                        provider: r.mxProvider || r.providerType,
                        flags: r.flags || {},
                    };
                } catch {
                    return { email, status: 'error', reason: 'verification_failed' };
                }
            })
        );
        results.push(...batchResults);
    }

    store.stampApiUse(req.apiRecord.userId);
    res.json({
        total: results.length,
        valid: results.filter(r => r.status === 'valid').length,
        invalid: results.filter(r => r.status !== 'valid').length,
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

// Master admin credentials. Set MASTER_ADMIN_USERNAME / MASTER_ADMIN_PASSWORD
// as env vars for stable creds. If unset (e.g. fresh Render deploy), default
// username to 'admin' and generate a strong random password, printed to the
// logs — copy it from the Render log stream. Keeps admin enabled without a
// hardcoded (guessable) password.
// Default admin credentials (used when MASTER_ADMIN_* env vars aren't set) so
// the panel works out-of-the-box on a fresh Render deploy. Set the env vars to
// override with secure, custom credentials for production.
const _adminUser = process.env.MASTER_ADMIN_USERNAME || 'Shakil007';
const _adminPass = process.env.MASTER_ADMIN_PASSWORD || 'Shakil007Oldisgold100%';
if (!process.env.MASTER_ADMIN_PASSWORD) {
    console.warn('[TrueSendy] Using default admin login (Shakil007). For production, set MASTER_ADMIN_USERNAME + MASTER_ADMIN_PASSWORD env vars.');
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
