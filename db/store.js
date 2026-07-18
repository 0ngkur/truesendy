const fs   = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH  = path.join(__dirname, 'users.json');

// ── In-memory cache ──────────────────────────────────────────────────────────
// Read once at boot; all reads are instant from RAM.
// Writes are serialized via a lock queue to prevent file corruption.

let _dbCache  = null;   // users + OTPs
let _apiCache = null;   // API keys

// Write-lock: ensures only one write at a time — prevents corruption under load
let _writeLock = Promise.resolve();

function _lock(fn) {
    _writeLock = _writeLock.then(fn).catch(err => console.error('[store] write error:', err));
    return _writeLock;
}

function loadDB() {
    if (_dbCache) return _dbCache;
    if (!fs.existsSync(DB_PATH)) {
        fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], otps: [] }, null, 2));
    }
    _dbCache = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    if (!_dbCache.users) _dbCache.users = [];
    if (!_dbCache.otps)  _dbCache.otps  = [];
    return _dbCache;
}

function saveDB(data) {
    _dbCache = data;
    // Fire-and-forget locked write — never blocks request handlers
    _lock(() => new Promise((res, rej) => {
        fs.writeFile(DB_PATH, JSON.stringify(data, null, 2), err => err ? rej(err) : res());
    }));
}

// Synchronous durable write for MONEY-CRITICAL paths (token deduct / purchase /
// refund). Blocks ~1-3ms but guarantees the paid balance is on disk before the
// response, so a crash can never lose a deduction or a purchased-token grant.
function saveDBSync(data) {
    _dbCache = data;
    try {
        fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
    } catch (err) {
        console.error('[store] sync write error:', err.message);
    }
}

// ======================== USER OPERATIONS ========================

function findUserByEmail(email) {
    const db = loadDB();
    return db.users.find(u => u.email === email.toLowerCase().trim());
}

function findUserById(id) {
    const db = loadDB();
    const user = db.users.find(u => u.id === id);
    if (user && maybeResetMonthlyQuota(user)) saveDB(db);   // lazy monthly top-up
    return user;
}

// Find or create a "key-only" account for a GUEST buyer (no login required to
// buy a key). If the email matches an existing user, return them; otherwise
// create a verified account with a random password — the buyer can set a real
// one later via "forgot password" if they want web access. This account holds
// the purchased tokens + the minted API key so the unified balance works.
function findOrCreateKeyBuyer(email) {
    const crypto = require('crypto');
    const db = loadDB();
    const e = (email || '').toLowerCase().trim();
    const existing = db.users.find(u => u.email === e);
    if (existing) return existing;
    const buyer = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
        email: e,
        username: 'buyer_' + crypto.randomBytes(4).toString('hex'),
        password: bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 10), // unusable until reset
        verified: true,
        credits: 0,
        plan: 'free',
        planCredits: 0,
        purchasedTokens: 0,
        tokensUsed: 0,
        quotaMonth: null,
        keyBuyer: true,
        createdAt: new Date().toISOString(),
    };
    db.users.push(buyer);
    saveDB(db);
    return buyer;
}

async function createUser(email, password, username) {
    const db = loadDB();
    // NEW-7: generic message — don't reveal whether the email or username is the conflict (enumeration defense)
    const exists = db.users.find(u => u.email === email.toLowerCase().trim());
    const usernameTaken = db.users.find(u => u.username === username.toLowerCase().trim());
    if (exists || usernameTaken) return { error: 'An account with that email or username already exists.' };

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
        email: email.toLowerCase().trim(),
        username: username.toLowerCase().trim(),
        password: hashedPassword,
        verified: false,
        credits: 0,           // free monthly (5/mo). Resets each calendar month.
        plan: 'free',         // free | starter | pro | agency
        planCredits: 0,       // monthly allowance from a paid plan (resets monthly)
        purchasedTokens: 0,   // one-time tokens bought via /key (never expire, never reset)
        tokensUsed: 0,        // lifetime verifications counter (web + bot)
        quotaMonth: null,     // "YYYY-MM" of last monthly reset
        createdAt: new Date().toISOString(),
    };

    db.users.push(user);
    saveDB(db);
    return { user };
}

function verifyUser(email) {
    const db = loadDB();
    const user = db.users.find(u => u.email === email.toLowerCase().trim());
    if (!user) return false;
    user.verified = true;
    user.credits = FREE_MONTHLY_TOKENS;   // free tier: 5 verifications/month
    user.quotaMonth = _monthKey();        // start the monthly clock
    saveDB(db);
    return true;
}

async function updatePassword(email, newPassword) {
    const db = loadDB();
    const user = db.users.find(u => u.email === email.toLowerCase().trim());
    if (!user) return false;
    user.password = await bcrypt.hash(newPassword, 10);
    saveDB(db);
    return true;
}

// ── Monthly quota ─────────────────────────────────────────────────────────────
// Free accounts: 5 verifications / calendar month. Paid plans: their monthly
// token allowance. Unused quota does NOT carry over. The reset is lazy — it
// runs on the first credit read/deduct in a new month. Purchased API-key
// tokens (100k / 30 days, in apikeys.json) are a SEPARATE bucket and are never
// touched by this logic.
const FREE_MONTHLY_TOKENS = 50;
const PLAN_MONTHLY_TOKENS = { starter: 1000, pro: 10000, agency: 100000 };

function _monthKey() { return new Date().toISOString().slice(0, 7); } // e.g. "2026-07"

function maybeResetMonthlyQuota(user) {
    if (!user) return false;
    const month = _monthKey();
    if (user.quotaMonth === month) return false;
    user.quotaMonth = month;
    if (user.keyBuyer) {
        // Key-only (guest buyer) accounts get NO free monthly tier — a purchased
        // key must equal exactly the boss-configured allowance, with no bonus
        // credits the bot could consume past the cap.
        user.credits = 0;
        user.planCredits = 0;
    } else if (user.plan && PLAN_MONTHLY_TOKENS[user.plan]) {
        user.planCredits = PLAN_MONTHLY_TOKENS[user.plan];
        user.credits = 0; // plan allowance subsumes the free tier
    } else {
        user.credits = FREE_MONTHLY_TOKENS;
        user.planCredits = 0;
    }
    return true;
}

// ── Unified token balance ────────────────────────────────────────────────────
// ONE balance per user, consumed by BOTH the web UI and the bot/API. This is
// the single source of truth — no separate per-key bucket. Deduction priority:
// purchased tokens (never expire) → plan monthly → free monthly.
function deductToken(userId, count = 1) {
    count = Math.max(1, parseInt(count, 10) || 1);
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return { ok: false };

    const reset = maybeResetMonthlyQuota(user);
    const total = (user.purchasedTokens || 0) + (user.planCredits || 0) + (user.credits || 0);
    if (total < count) {
        if (reset) saveDB(db);   // persist the month rollover even on insufficient balance
        return { ok: false };
    }

    let need = count;
    const fromPurchased = Math.min(need, user.purchasedTokens || 0);
    user.purchasedTokens = (user.purchasedTokens || 0) - fromPurchased;
    need -= fromPurchased;
    const fromPlan = Math.min(need, user.planCredits || 0);
    user.planCredits = (user.planCredits || 0) - fromPlan;
    need -= fromPlan;
    user.credits = Math.max(0, (user.credits || 0) - need);

    user.tokensUsed = (user.tokensUsed || 0) + count;
    // Track usage history for the dashboard (cap at 100 entries to bound growth)
    if (!Array.isArray(user.usageLog)) user.usageLog = [];
    user.usageLog.unshift({ ts: Date.now(), amount: count });
    if (user.usageLog.length > 100) user.usageLog.length = 100;
    saveDBSync(db);   // durable: paid deduction must hit disk before we respond
    return { ok: true };
}

// Refund a failed verification. Credited to purchasedTokens (non-expiring) so a
// monthly reset can never claw back a refunded token.
function refundToken(userId, count = 1) {
    count = Math.max(1, parseInt(count, 10) || 1);
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return false;
    user.purchasedTokens = (user.purchasedTokens || 0) + count;
    user.tokensUsed = Math.max(0, (user.tokensUsed || 0) - count);
    saveDBSync(db);   // durable refund
    return true;
}

// Back-compat shim — older callers deduct 1 token.
function deductCredit(userId) { return deductToken(userId, 1).ok; }

function getUserCredits(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return 0;
    if (maybeResetMonthlyQuota(user)) saveDB(db);
    return (user.credits || 0) + (user.planCredits || 0) + (user.purchasedTokens || 0);
}

// Return recent usage entries for the dashboard credit-history widget.
function getUsageHistory(userId, limit = 20) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user || !Array.isArray(user.usageLog)) return [];
    return user.usageLog.slice(0, Math.min(limit, 50));
}

// ── Job history (Tasks & Results panel) ──────────────────────────────────────
// Persist a short summary of each completed verification job so the user can
// see past jobs + re-download results from the dashboard.
function recordJobSummary(userId, summary) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return false;
    if (!Array.isArray(user.jobHistory)) user.jobHistory = [];
    user.jobHistory.unshift({
        id: summary.id || null,
        date: Date.now(),
        total: summary.total || 0,
        valid: summary.valid || 0,
        invalid: summary.invalid || 0,
        unknown: summary.unknown || 0,
        filename: summary.filename || '',
        status: summary.status || 'complete',
    });
    if (user.jobHistory.length > 50) user.jobHistory.length = 50;
    saveDB(db);
    return true;
}

function getJobHistory(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user || !Array.isArray(user.jobHistory)) return [];
    return user.jobHistory;
}

// ── 7-day retention cleanup ──────────────────────────────────────────────────
// Purges jobHistory + usageLog entries older than 7 days for ALL users.
// Runs periodically (called from server.js setInterval) to bound storage.
const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;   // 7 days
function cleanupOldHistory() {
    const db = loadDB();
    const cutoff = Date.now() - RETENTION_MS;
    let changed = false;
    for (const user of db.users) {
        if (Array.isArray(user.jobHistory) && user.jobHistory.length) {
            const before = user.jobHistory.length;
            user.jobHistory = user.jobHistory.filter(j => (j.date || 0) > cutoff);
            if (user.jobHistory.length !== before) changed = true;
        }
        if (Array.isArray(user.usageLog) && user.usageLog.length) {
            const before = user.usageLog.length;
            user.usageLog = user.usageLog.filter(h => (h.ts || 0) > cutoff);
            if (user.usageLog.length !== before) changed = true;
        }
    }
    if (changed) saveDB(db);
    return changed;
}

// Lifetime usage + bucket breakdown for display (CLI balance, admin).
function getUserTokenStatus(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return null;
    if (maybeResetMonthlyQuota(user)) saveDB(db);
    return {
        total:       (user.credits || 0) + (user.planCredits || 0) + (user.purchasedTokens || 0),
        purchased:   user.purchasedTokens || 0,
        plan:        user.planCredits || 0,
        free:        user.credits || 0,
        tokensUsed:  user.tokensUsed || 0,
    };
}

// Stamp the user's last API activity (for the "recent bot users" admin metric).
function stampApiUse(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return;
    user.lastApiUse = new Date().toISOString();
    saveDB(db);
}

// Mark that the user downloaded the bot (unique-downloader admin metric).
function markBotDownloaded(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user || user.downloadedBot) return;
    user.downloadedBot = true;
    saveDB(db);
}

// Monthly credit allowance per plan. Shared by upgradePlan + approveAgency so
// the two paths can't drift apart.
const PLAN_MONTHLY_CREDITS = { free: 50, starter: 1000, pro: 10000, agency: 100000 };

function upgradePlan(userId, plan) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return false;

    user.plan = plan;
    user.planCredits = PLAN_MONTHLY_CREDITS[plan] || 0;
    saveDB(db);

    // CR-06: API access requires the Agency plan. Downgrading away from Agency
    // automatically revokes all active API keys — no continued API access without paying.
    if (plan !== 'agency') revokeAllApiKeysForUser(userId);

    return true;
}

// ── Agency approval workflow ─────────────────────────────────────────────────
// Agency plan (bot download access) is granted manually by the admin.
// Flow: user requests → admin approves → user.plan = 'agency'.

// User requests Agency plan access. Returns { ok, status } where status is
// 'requested' (new) or 'already_requested' or 'already_agency'.
function requestAgency(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return { error: 'User not found.' };
    if (user.plan === 'agency') return { ok: true, status: 'already_agency' };
    if (user.agencyRequested) return { ok: true, status: 'already_requested' };
    user.agencyRequested = true;
    user.agencyRequestedAt = new Date().toISOString();
    saveDB(db);
    return { ok: true, status: 'requested' };
}

// Admin approves a user's Agency request.
function approveAgency(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return { error: 'User not found.' };

    user.plan = 'agency';
    user.planCredits = PLAN_MONTHLY_CREDITS.agency;
    user.agencyRequested = false;
    user.agencyApprovedAt = new Date().toISOString();
    saveDB(db);
    return { ok: true };
}

// Admin denies / revokes an Agency request.
function denyAgency(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return { error: 'User not found.' };
    user.agencyRequested = false;
    saveDB(db);
    return { ok: true };
}

// Returns all users with a pending Agency request.
function getPendingAgencyRequests() {
    const db = loadDB();
    return db.users
        .filter(u => u.agencyRequested && u.plan !== 'agency')
        .map(u => ({
            id: u.id,
            email: u.email,
            username: u.username,
            agencyRequestedAt: u.agencyRequestedAt,
            createdAt: u.createdAt,
        }));
}

// ======================== OTP OPERATIONS ========================

function storeOTP(email, otp, purpose) {
    const db = loadDB();
    // Remove any existing OTP for this email + purpose
    db.otps = db.otps.filter(o => !(o.email === email && o.purpose === purpose));
    db.otps.push({
        email: email.toLowerCase().trim(),
        otp,
        purpose, // 'verify' | 'reset'
        createdAt: Date.now(),
        expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
    });
    saveDB(db);
}

function verifyOTP(email, otp, purpose) {
    const db = loadDB();
    const record = db.otps.find(
        o => o.email === email.toLowerCase().trim() && o.otp === otp && o.purpose === purpose
    );
    if (!record) return false;
    if (Date.now() > record.expiresAt) {
        // Expired — clean up
        db.otps = db.otps.filter(o => o !== record);
        saveDB(db);
        return false;
    }
    // Valid — remove it (one-time use)
    db.otps = db.otps.filter(o => o !== record);
    saveDB(db);
    return true;
}

// ======================== ADMIN OPERATIONS ========================

function getAllUsers() {
    const db = loadDB();
    return (db.users || []).map(u => ({
        id: u.id,
        email: u.email,
        username: u.username,
        verified: u.verified,
        credits: u.credits || 0,
        planCredits: u.planCredits || 0,
        purchasedTokens: u.purchasedTokens || 0,
        tokensUsed: u.tokensUsed || 0,
        totalCredits: (u.credits || 0) + (u.planCredits || 0) + (u.purchasedTokens || 0),
        plan: u.plan || 'free',
        role: u.role || 'user',
        banned: u.banned || false,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin || null,
    }));
}

function updateUserCredits(userId, credits) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return false;
    user.credits = parseInt(credits, 10) || 0;
    saveDB(db);
    return true;
}

function updateUserPlan(userId, plan) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return false;
    const planCredits = { free: 0, starter: 1000, pro: 10000, agency: 100000 };
    user.plan = plan;
    user.planCredits = planCredits[plan] !== undefined ? planCredits[plan] : user.planCredits;
    saveDB(db);
    return true;
}

// Grant purchased tokens (one-time, NEVER reset by the monthly quota). Used for
// the tester account + support/refunds. Durable write (saveDBSync).
function grantTokens(userId, amount) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return false;
    const n = parseInt(amount, 10);
    if (!n || n <= 0) return false;
    user.purchasedTokens = (user.purchasedTokens || 0) + n;
    saveDBSync(db);
    return true;
}

function banUser(userId, banned) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return false;
    user.banned = banned;
    saveDB(db);
    return true;
}

function deleteUser(userId) {
    const db = loadDB();
    const before = db.users.length;
    db.users = db.users.filter(u => u.id !== userId);
    if (db.users.length === before) return false;
    saveDB(db);
    return true;
}

async function createSubAdmin(email, username, password) {
    const db = loadDB();
    const exists = db.users.find(u => u.email === email.toLowerCase().trim());
    if (exists) return { error: 'Email already registered.' };
    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
        email: email.toLowerCase().trim(),
        username: username.toLowerCase().trim(),
        password: hashedPassword,
        verified: true,
        credits: 0,
        plan: 'admin',
        planCredits: 0,
        purchasedTokens: 0,
        tokensUsed: 0,
        role: 'subadmin',
        createdAt: new Date().toISOString(),
    };
    db.users.push(admin);
    saveDB(db);
    return { user: admin };
}

function getStats() {
    const db = loadDB();
    const users = db.users || [];
    const regular = users.filter(u => u.role !== 'subadmin');
    const apiDb = loadApiDB();
    const activeKeyUsers = new Set((apiDb.keys || []).filter(k => k.active).map(k => k.userId));
    const MONTH = 30 * 24 * 60 * 60 * 1000;
    return {
        totalUsers: regular.length,
        verifiedUsers: regular.filter(u => u.verified).length,
        planCounts: {
            free:    regular.filter(u => u.plan === 'free').length,
            starter: regular.filter(u => u.plan === 'starter').length,
            pro:     regular.filter(u => u.plan === 'pro').length,
            agency:  regular.filter(u => u.plan === 'agency').length,
        },
        totalCreditsIssued: regular.reduce((s, u) => s + (u.credits || 0) + (u.planCredits || 0) + (u.purchasedTokens || 0), 0),
        totalTokensUsed: regular.reduce((s, u) => s + (u.tokensUsed || 0), 0),
        activeBotUsers: regular.filter(u => activeKeyUsers.has(u.id)).length,
        recentBotUsers: regular.filter(u => u.lastApiUse && (Date.now() - new Date(u.lastApiUse).getTime()) < MONTH).length,
        botDownloaders: regular.filter(u => u.downloadedBot).length,
        subAdmins: users.filter(u => u.role === 'subadmin').length,
    };
}

// ======================== API KEY OPERATIONS ========================

const crypto = require('crypto');

const API_DB_PATH = path.join(__dirname, 'apikeys.json');

function loadApiDB() {
    if (!fs.existsSync(API_DB_PATH)) {
        fs.writeFileSync(API_DB_PATH, JSON.stringify({ keys: [] }));
    }
    return JSON.parse(fs.readFileSync(API_DB_PATH, 'utf8'));
}

function saveApiDB(data) {
    fs.writeFileSync(API_DB_PATH, JSON.stringify(data, null, 2));
}

function generateApiKey(userId) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return { error: 'User not found.' };
    if (user.plan !== 'agency') return { error: 'API keys are only available for Agency plan subscribers.' };

    const apiDb = loadApiDB();
    // One active key per user (revoke previous)
    apiDb.keys.forEach(k => { if (k.userId === userId && k.active) k.active = false; });

    const key = 'ts_' + crypto.randomBytes(24).toString('hex');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days

    // Auth-only credential: maps the bot to this user. Verifications draw from
    // the user's shared token balance — no per-key token bucket.
    const apiKey = {
        key, userId, email: user.email,
        active: true,
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
    };
    apiDb.keys.push(apiKey);
    saveApiDB(apiDb);
    return { apiKey: { ...apiKey, tokens: getUserCredits(userId) } }; // tokens = account balance (display)
}

// ── Purchased key (direct sale, NOT tied to an Agency subscription) ──
// Creates a brand-new key with the boss-configured token allowance and does
// NOT revoke existing keys — a user may legitimately own several purchased
// keys. Called by the Stripe webhook after a successful key_purchase payment.
function purchaseApiKey(userId, overrideAmount) {
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return { error: 'User not found.' };

    const settings = require('./settings');
    const product  = settings.getKeyProduct();
    const amount   = (typeof overrideAmount === 'number' && overrideAmount > 0)
        ? Math.floor(overrideAmount)
        : (product.tokens || 100000);

    // Credit the user's SHARED balance — these tokens are consumed by BOTH the
    // web UI and the bot (single source of truth).
    user.purchasedTokens = (user.purchasedTokens || 0) + amount;
    saveDBSync(db);   // durable: purchased tokens must hit disk immediately

    // Mint an auth key so the bot can identify the account (no token bucket).
    const apiDb = loadApiDB();
    const key = 'ts_' + crypto.randomBytes(24).toString('hex');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (product.validityDays || 30) * 24 * 60 * 60 * 1000);
    const apiKey = {
        key, userId, email: user.email,
        active: true, purchased: true,
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
    };
    apiDb.keys.push(apiKey);
    saveApiDB(apiDb);
    return { apiKey: { key, expiresAt: apiKey.expiresAt }, tokens: amount, balance: getUserCredits(userId) };
}

function validateApiKey(key) {
    const apiDb = loadApiDB();
    const record = apiDb.keys.find(k => k.key === key && k.active);
    if (!record) return { error: 'This is not a valid TrueSendy key. Keys start with "ts_" and come from truesendy.com/key.' };

    // Check expiry
    if (new Date() > new Date(record.expiresAt)) {
        record.active = false;
        saveApiDB(apiDb);
        return { error: 'API key expired. Please purchase a new key from the website.' };
    }

    // No per-key token check — the bot draws from the user's shared balance.
    return { record };
}

// NOTE: deductApiToken / getApiKeyBalance were removed — the bot now draws from
// the user's shared balance via deductToken(userId) / getUserCredits(userId).

function getUserApiKeys(userId) {
    const apiDb = loadApiDB();
    return apiDb.keys
        .filter(k => k.userId === userId)
        .map(k => ({
            key: k.key.slice(0, 8) + '...' + k.key.slice(-6),
            active: k.active,
            purchased: !!k.purchased,
            expired: new Date() > new Date(k.expiresAt),
            createdAt: k.createdAt,
            expiresAt: k.expiresAt,
            daysRemaining: Math.max(0, Math.ceil((new Date(k.expiresAt) - new Date()) / (1000 * 60 * 60 * 24))),
        }));
}

function revokeApiKey(key) {
    const apiDb = loadApiDB();
    const record = apiDb.keys.find(k => k.key === key);
    if (!record) return false;
    record.active = false;
    saveApiDB(apiDb);
    return true;
}

// Revoke a key belonging to a specific user, matching either the full key or its
// masked form (as shown in the admin panel).
function revokeUserKey(userId, keyId) {
    if (!keyId) return false;
    const apiDb = loadApiDB();
    const rec = apiDb.keys.find(k => k.userId === userId && (k.key === keyId || (k.key.slice(0, 8) + '...' + k.key.slice(-6)) === keyId));
    if (!rec) return false;
    rec.active = false;
    saveApiDB(apiDb);
    return true;
}

function revokeAllApiKeysForUser(userId) {
    const apiDb = loadApiDB();
    let revoked = 0;
    apiDb.keys.forEach(k => {
        if (k.userId === userId && k.active) {
            k.active = false;
            revoked++;
        }
    });
    if (revoked > 0) saveApiDB(apiDb);
    return revoked;
}

// ── Admin: support / recovery helpers ────────────────────────────────────────

// Full (unmasked) latest active purchased key for a user — used by the admin
// "Resend key" action when a buyer's key email didn't arrive.
function getLatestKeyForUser(userId) {
    const apiDb = loadApiDB();
    const rec = apiDb.keys
        .filter(k => k.userId === userId && k.active && k.purchased)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
    if (!rec) return null;
    return { key: rec.key, createdAt: rec.createdAt, expiresAt: rec.expiresAt };
}

// Manually credit a user's purchased token balance (admin support / refund).
function creditUserTokens(userId, amount) {
    amount = Math.max(0, parseInt(amount, 10) || 0);
    if (amount <= 0) return { ok: false, error: 'Amount must be greater than 0.' };
    const db = loadDB();
    const user = db.users.find(u => u.id === userId);
    if (!user) return { ok: false, error: 'User not found.' };
    user.purchasedTokens = (user.purchasedTokens || 0) + amount;
    saveDBSync(db);   // durable: admin credit / refund must persist
    return { ok: true, purchasedTokens: user.purchasedTokens, total: getUserCredits(userId) };
}

// ── Stripe webhook idempotency ───────────────────────────────────────────────
// Stripe retries events; without dedup a retried key_purchase would double-credit
// tokens. Track processed event IDs for 48h (db/processedEvents.json, gitignored).
const EVENTS_PATH = path.join(__dirname, 'processedEvents.json');
const EVENT_TTL_MS = 48 * 60 * 60 * 1000;
function _loadEvents() {
    if (!fs.existsSync(EVENTS_PATH)) return { events: [] };
    try { return JSON.parse(fs.readFileSync(EVENTS_PATH, 'utf8')); } catch { return { events: [] }; }
}
function isEventProcessed(eventId) {
    if (!eventId) return false;
    const cutoff = Date.now() - EVENT_TTL_MS;
    return _loadEvents().events.some(e => e.id === eventId && e.ts > cutoff);
}
function markEventProcessed(eventId) {
    if (!eventId) return;
    const db = _loadEvents();
    db.events = db.events.filter(e => e.ts > Date.now() - EVENT_TTL_MS);   // TTL cleanup
    if (!db.events.some(e => e.id === eventId)) {
        db.events.push({ id: eventId, ts: Date.now() });
        try { fs.writeFileSync(EVENTS_PATH, JSON.stringify(db, null, 2)); } catch (e) { console.error('[store] event log write error:', e.message); }
    }
}

// ── One-time migration: fold legacy per-key token balances into the user's
// shared purchasedTokens so nobody loses paid tokens in the unification.
// Idempotent — each key is migrated at most once.
function _migrateLegacyKeyTokens() {
    try {
        const apiDb = loadApiDB();
        const db    = loadDB();
        let changed = false;
        apiDb.keys.forEach(k => {
            if (k.migrated) return;
            if (k.purchased && (k.tokens || 0) > 0) {
                const user = db.users.find(u => u.id === k.userId);
                if (user) user.purchasedTokens = (user.purchasedTokens || 0) + (k.tokens || 0);
            }
            k.migrated = true;
            changed = true;
        });
        if (changed) {
            saveApiDB(apiDb);
            saveDB(db);
        }
    } catch (e) {
        console.error('[store] legacy token migration error:', e.message);
    }
}
_migrateLegacyKeyTokens();

module.exports = {
    findUserByEmail,
    findUserById,
    findOrCreateKeyBuyer,
    createUser,
    verifyUser,
    updatePassword,
    // Tokens — single shared balance for web AND bot
    deductToken,
    refundToken,
    deductCredit,          // back-compat shim (deducts 1)
    getUserCredits,
    getUsageHistory,
    getJobHistory,
    recordJobSummary,
    cleanupOldHistory,
    getUserTokenStatus,
    stampApiUse,
    markBotDownloaded,
    upgradePlan,
    requestAgency,
    approveAgency,
    denyAgency,
    getPendingAgencyRequests,
    storeOTP,
    verifyOTP,
    // Admin
    getAllUsers,
    updateUserCredits,
    updateUserPlan,
    grantTokens,
    banUser,
    deleteUser,
    createSubAdmin,
    getStats,
    // API Keys (auth credentials — no per-key token balance anymore)
    generateApiKey,
    purchaseApiKey,
    validateApiKey,
    getUserApiKeys,
    revokeApiKey,
    revokeUserKey,
    revokeAllApiKeysForUser,
    getLatestKeyForUser,
    creditUserTokens,
    // Webhook idempotency
    isEventProcessed,
    markEventProcessed,
};
