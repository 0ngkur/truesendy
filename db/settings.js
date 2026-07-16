// ── Boss-managed runtime settings ────────────────────────────────────────────
// Stored in db/settings.json (gitignored — holds the Stripe secret key).
// The master admin edits these from the masterenter panel so the boss never
// needs to touch server env vars or redeploy to swap his Stripe account or
// change the key product's price / token allowance.
//
// Precedence for Stripe keys: this settings file FIRST, then process.env
// fallback (so a host-configured deploy still works if settings.json is empty).

const fs   = require('fs');
const path = require('path');

const SETTINGS_PATH = path.join(__dirname, 'settings.json');

const DEFAULTS = {
    stripe: {
        secretKey:     '',
        webhookSecret: '',
        configuredAt:  null,
    },
    keyProduct: {
        priceUsd:     49,       // one-time price of a verification key
        tokens:       100000,   // hard cap: emails one key can verify
        validityDays: 30,       // key expires after this many days
        currency:     'usd',
    },
    packages: [
        { id: 'starter',  name: 'Starter',  tokens: 1000,   priceUsd: 1.99,  perEmail: '$0.0020', popular: false },
        { id: 'basic',    name: 'Basic',    tokens: 5000,   priceUsd: 6.99,  perEmail: '$0.0014', popular: false },
        { id: 'standard', name: 'Standard', tokens: 10000,  priceUsd: 11.99, perEmail: '$0.0012', popular: true  },
        { id: 'growth',   name: 'Growth',   tokens: 25000,  priceUsd: 24.99, perEmail: '$0.0010', popular: false },
        { id: 'pro',      name: 'Pro',      tokens: 50000,  priceUsd: 39.99, perEmail: '$0.0008', popular: false },
        { id: 'ultimate', name: 'Ultimate', tokens: 100000, priceUsd: 49,    perEmail: '$0.00049', popular: false },
    ],
    stats: {
        botDownloads: 0,        // total gated exe downloads (incremented per successful download)
    },
};

let _cache = null;
let _writeLock = Promise.resolve();

function load() {
    if (_cache) return _cache;
    if (!fs.existsSync(SETTINGS_PATH)) {
        _cache = JSON.parse(JSON.stringify(DEFAULTS));
        return _cache;
    }
    try {
        const parsed = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
        _cache = {
            stripe:     { ...DEFAULTS.stripe,     ...(parsed.stripe || {}) },
            keyProduct: { ...DEFAULTS.keyProduct, ...(parsed.keyProduct || {}) },
            stats:      { ...DEFAULTS.stats,      ...(parsed.stats || {}) },
        };
    } catch (e) {
        console.error('[settings] settings.json was unreadable, using defaults:', e.message);
        _cache = JSON.parse(JSON.stringify(DEFAULTS));
    }
    return _cache;
}

function persist() {
    const data = _cache || load();
    _writeLock = _writeLock.then(() => {
        try {
            fs.writeFileSync(SETTINGS_PATH, JSON.stringify(data, null, 2));
        } catch (err) {
            console.error('[settings] write failed:', err.message);
        }
    });
}

// ── Stripe keys ──
function getStripeKeys() {
    const s = load().stripe;
    return { secretKey: s.secretKey || '', webhookSecret: s.webhookSecret || '' };
}

function setStripeKeys(secretKey, webhookSecret) {
    const data = load();
    // undefined = leave the field unchanged (partial update); empty string = clear it.
    if (secretKey !== undefined) {
        data.stripe.secretKey = typeof secretKey === 'string' ? secretKey.trim() : '';
    }
    if (webhookSecret !== undefined) {
        data.stripe.webhookSecret = typeof webhookSecret === 'string' ? webhookSecret.trim() : '';
    }
    if (secretKey || webhookSecret) {
        data.stripe.configuredAt = new Date().toISOString();
    }
    persist();
    return data.stripe;
}

// ── Key product (price / token allowance) ──
function getKeyProduct() {
    return load().keyProduct;
}

// ── Credit packages (6 preset tiers) ──
function getPackages() {
    const pkgs = load().packages;
    return Array.isArray(pkgs) && pkgs.length ? pkgs : DEFAULTS.packages;
}

function getPackage(id) {
    return getPackages().find(p => p.id === id) || null;
}

function setKeyProduct({ priceUsd, tokens, validityDays } = {}) {
    const data = load();
    if (typeof priceUsd === 'number' && isFinite(priceUsd) && priceUsd >= 0) {
        data.keyProduct.priceUsd = priceUsd;
    }
    if (typeof tokens === 'number' && isFinite(tokens) && tokens > 0) {
        data.keyProduct.tokens = Math.floor(tokens);
    }
    if (typeof validityDays === 'number' && isFinite(validityDays) && validityDays > 0) {
        data.keyProduct.validityDays = Math.floor(validityDays);
    }
    persist();
    return data.keyProduct;
}

// ── Masked view for the admin panel (never expose the full secret key) ──
function maskValue(v) {
    if (!v || typeof v !== 'string') return '';
    if (v.length <= 12) return '••••';
    return v.slice(0, 8) + '••••' + v.slice(-4);
}

function getMaskedSettings() {
    const data = load();
    return {
        stripe: {
            secretKeyMasked:    maskValue(data.stripe.secretKey),
            webhookSecretMasked: maskValue(data.stripe.webhookSecret),
            configured:         !!data.stripe.secretKey,
            configuredAt:       data.stripe.configuredAt,
        },
        keyProduct: data.keyProduct,
    };
}

// ── Runtime stats counters ───────────────────────────────────────────────────
function incBotDownload() {
    const data = load();
    data.stats = data.stats || { botDownloads: 0 };
    data.stats.botDownloads = (data.stats.botDownloads || 0) + 1;
    persist();
    return data.stats.botDownloads;
}

function getBotDownloads() {
    const data = load();
    return (data.stats && data.stats.botDownloads) || 0;
}

module.exports = {
    load,
    getStripeKeys,
    setStripeKeys,
    getKeyProduct,
    setKeyProduct,
    getPackages,
    getPackage,
    getMaskedSettings,
    incBotDownload,
    getBotDownloads,
};
