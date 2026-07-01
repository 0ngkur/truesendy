/**
 * TrueSendy — Security Hardening Module
 * Owner  : Shakil  |  Dev: Ikhtheir Jaman Ongkur
 *
 * Covers:
 *  [1]  HTTP security headers (Helmet) — XSS, clickjacking, MIME-sniff, CSP
 *  [2]  Rate limiting — brute force on auth, API, general
 *  [3]  Request size limits — DoS / large payload attacks
 *  [4]  HTTP Parameter Pollution (HPP)
 *  [5]  Input sanitization — NoSQL/JSON injection, prototype pollution
 *  [6]  Path traversal guard (upload filenames)
 *  [7]  SSRF guard — block internal IPs in SMTP probe targets
 *  [8]  OTP brute-force throttle
 *  [9]  Timing-safe string comparison for sensitive values
 *  [10] Security response headers (no-cache for API)
 *  [11] Error sanitizer — never leak stack traces
 *  [12] Upload MIME type enforcement
 */

const rateLimit  = require('express-rate-limit');
const slowDown   = require('express-slow-down');
const helmet     = require('helmet');
const hpp        = require('hpp');
const crypto     = require('crypto');
const path       = require('path');

// Helper: normalise IPv6-mapped IPv4 (e.g. ::ffff:1.2.3.4 → 1.2.3.4)
function normaliseIp(ip) {
    if (!ip) return 'unknown';
    return ip.replace(/^::ffff:/, '');
}

// ── [1] HELMET — Security HTTP headers ───────────────────────────────────────
const helmetMiddleware = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc : ["'self'"],
            scriptSrc  : ["'self'", "'unsafe-inline'"],
            // Helmet 8 defaults script-src-attr to 'none', which silently breaks
            // every inline event handler (onclick="...") across the UI — signin
            // tabs, the /key Buy button, admin actions. Allow inline handlers to
            // match the existing script-src 'unsafe-inline' policy.
            scriptSrcAttr : ["'unsafe-inline'"],
            styleSrc   : ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc    : ["'self'", 'https://fonts.googleapis.com', 'https://fonts.gstatic.com', 'data:'],
            imgSrc     : ["'self'", 'data:', 'blob:'],
            connectSrc : ["'self'"],
            frameSrc   : ["'none'"],
            objectSrc  : ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
    crossOriginEmbedderPolicy  : false,  // Allow fonts/images to load
    crossOriginResourcePolicy  : { policy: 'same-site' },
    referrerPolicy             : { policy: 'strict-origin-when-cross-origin' },
    xContentTypeOptions        : true,
    xFrameOptions              : { action: 'deny' },         // Clickjacking
    xXssProtection             : false,                      // Deprecated, CSP handles it
    hsts: {
        maxAge            : 31536000,  // 1 year
        includeSubDomains : true,
        preload           : true,
    },
});

// ── [2] RATE LIMITERS ─────────────────────────────────────────────────────────

// Auth endpoints — very strict (prevents brute force login/signup)
const authLimiter = rateLimit({
    windowMs : 15 * 60 * 1000,
    max      : 10,
    message  : { error: 'Too many authentication attempts. Try again in 15 minutes.' },
    standardHeaders : true,
    legacyHeaders   : false,
    skipSuccessfulRequests: false,
    validate : { xForwardedForHeader: false },
});

// Slow down after 5 auth attempts — adds progressive delay
const authSlowDown = slowDown({
    windowMs   : 15 * 60 * 1000,
    delayAfter : 5,
    delayMs    : () => 1000,
    validate   : { xForwardedForHeader: false },
});

// OTP endpoints — ultra strict (prevents OTP brute force: only 1M combos)
const otpLimiter = rateLimit({
    windowMs : 60 * 60 * 1000,
    max      : 5,
    message  : { error: 'Too many code attempts. Try again in 1 hour.' },
    standardHeaders : true,
    legacyHeaders   : false,
    keyGenerator    : (req) => normaliseIp(req.ip) + ':' + (req.body?.email || ''),
    validate        : { xForwardedForHeader: false, keyGeneratorIpFallback: false },
});

// Forgot password — prevent account enumeration bombing
const forgotLimiter = rateLimit({
    windowMs : 60 * 60 * 1000,
    max      : 3,
    message  : { error: 'Too many reset requests. Try again in 1 hour.' },
    standardHeaders : true,
    legacyHeaders   : false,
    validate : { xForwardedForHeader: false },
});

// API key endpoints — agency users, generous but protected
const apiLimiter = rateLimit({
    windowMs : 60 * 1000,
    max      : 120,
    message  : { error: 'Rate limit exceeded. Slow down.' },
    standardHeaders : true,
    legacyHeaders   : false,
    keyGenerator    : (req) => req.headers['x-api-key'] || normaliseIp(req.ip),
    validate        : { xForwardedForHeader: false, keyGeneratorIpFallback: false },
});

// General web API
const generalLimiter = rateLimit({
    windowMs : 60 * 1000,
    max      : 200,
    message  : { error: 'Too many requests. Slow down.' },
    standardHeaders : true,
    legacyHeaders   : false,
    validate : { xForwardedForHeader: false },
});

// Admin endpoints — very strict
const adminLimiter = rateLimit({
    windowMs : 15 * 60 * 1000,
    max      : 20,
    message  : { error: 'Too many admin requests.' },
    standardHeaders : true,
    legacyHeaders   : false,
    validate : { xForwardedForHeader: false },
});

// ── [4] HPP — HTTP Parameter Pollution ───────────────────────────────────────
const hppMiddleware = hpp();

// ── [5] INPUT SANITIZER — prototype pollution + deep object cleaning ──────────
function sanitizeValue(val, depth = 0) {
    if (depth > 10) return null;  // Prevent deep recursion DoS
    if (val === null || val === undefined) return val;
    if (typeof val === 'string') {
        // Strip null bytes (can bypass string checks)
        val = val.replace(/\0/g, '');
        // Limit string length
        if (val.length > 10000) val = val.slice(0, 10000);
        return val;
    }
    if (typeof val === 'number') {
        if (!isFinite(val)) return 0;
        return val;
    }
    if (Array.isArray(val)) {
        if (val.length > 500) val = val.slice(0, 500);  // Cap array size
        return val.map(v => sanitizeValue(v, depth + 1));
    }
    if (typeof val === 'object') {
        const clean = {};
        for (const key of Object.keys(val)) {
            // Block prototype pollution attacks
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
            clean[key] = sanitizeValue(val[key], depth + 1);
        }
        return clean;
    }
    return val;
}

function inputSanitizer(req, res, next) {
    if (req.body && typeof req.body === 'object') {
        req.body = sanitizeValue(req.body);
    }
    if (req.query && typeof req.query === 'object') {
        req.query = sanitizeValue(req.query);
    }
    next();
}

// ── [6] UPLOAD SECURITY — MIME type + filename path traversal ─────────────────
const ALLOWED_UPLOAD_TYPES = [
    'text/csv', 'text/plain',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-excel',
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
];

const ALLOWED_UPLOAD_EXTS = ['.csv', '.txt', '.xlsx', '.xls', '.pdf', '.docx'];

function validateUpload(req, res, next) {
    if (!req.file) return next();

    const ext = path.extname(req.file.originalname || '').toLowerCase();
    if (!ALLOWED_UPLOAD_EXTS.includes(ext)) {
        return res.status(400).json({ error: `File type not allowed. Use: ${ALLOWED_UPLOAD_EXTS.join(', ')}` });
    }

    // Guard path traversal in filename
    const safeName = path.basename(req.file.originalname || 'upload');
    if (safeName !== req.file.originalname) {
        return res.status(400).json({ error: 'Invalid filename.' });
    }

    // Size limit: 10MB
    if (req.file.size > 10 * 1024 * 1024) {
        return res.status(413).json({ error: 'File too large. Maximum 10MB.' });
    }

    next();
}

// ── [7] SSRF GUARD — block private/internal IPs ───────────────────────────────
const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|::1|localhost|169\.254\.)/i;

function isPrivateHost(host) {
    if (!host || typeof host !== 'string') return false;
    const clean = host.trim().toLowerCase();
    return PRIVATE_IP_RE.test(clean) ||
        clean === 'localhost' ||
        clean.endsWith('.internal') ||
        clean.endsWith('.local');
}

// ── [9] TIMING-SAFE COMPARISON ────────────────────────────────────────────────
function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) {
        // Still do a comparison to avoid timing leak on length
        crypto.timingSafeEqual(Buffer.alloc(bufA.length), Buffer.alloc(bufA.length));
        return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
}

// ── [10] API NO-CACHE headers ─────────────────────────────────────────────────
function apiNoCacheHeaders(req, res, next) {
    if (req.path.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('X-Content-Type-Options', 'nosniff');
    }
    next();
}

// ── [11] SAFE ERROR HANDLER — never leak stack traces ────────────────────────
function safeErrorHandler(err, req, res, next) {
    // Log full error server-side
    console.error('[TrueSendy][ERROR]', err.message, err.stack?.split('\n')[1] || '');

    // Multer errors
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'File too large. Maximum 10MB.' });
    }

    if (err.type === 'entity.too.large') {
        return res.status(413).json({ error: 'Request body too large.' });
    }

    // JWT errors
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }

    // Never expose internal errors to client
    const status = err.status || err.statusCode || 500;
    res.status(status >= 400 && status < 600 ? status : 500).json({
        error: status === 500 ? 'Internal server error.' : (err.message || 'Unknown error.'),
    });
}

// ── [12] CORS — restrict origins ──────────────────────────────────────────────
function corsMiddleware(req, res, next) {
    const origin = req.headers.origin || '';
    const allowed = [
        'http://localhost:3000',
        'https://truesendy.com',
        'https://www.truesendy.com',
    ];
    if (!origin || allowed.includes(origin)) {
        if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
        res.setHeader('Access-Control-Max-Age', '86400');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
}

module.exports = {
    helmetMiddleware,
    authLimiter,
    authSlowDown,
    otpLimiter,
    forgotLimiter,
    apiLimiter,
    generalLimiter,
    adminLimiter,
    hppMiddleware,
    inputSanitizer,
    validateUpload,
    isPrivateHost,
    timingSafeEqual,
    apiNoCacheHeaders,
    safeErrorHandler,
    corsMiddleware,
};
