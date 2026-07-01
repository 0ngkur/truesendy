const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const store = require('../db/store');

// JWT secret. Set JWT_SECRET as an env var in production for STABLE sessions.
// If unset, generate a strong random one so the server still BOOTS — but tokens
// won't survive a restart (users get logged out on redeploy / cold-start).
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
if (!process.env.JWT_SECRET) {
    console.warn('[TrueSendy] WARNING: JWT_SECRET env var not set — using a random secret. Set JWT_SECRET for stable sessions (so users stay logged in across restarts).');
}

function generateToken(user) {
    return jwt.sign(
        { id: user.id, email: user.email, username: user.username },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

function authMiddleware(req, res, next) {
    let token = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ error: 'Not authenticated. Please log in.' });
    }

    try {
        // Pin the algorithm to HS256 (our signing alg) — defeats alg:none / algorithm-confusion attacks.
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        const user = store.findUserById(decoded.id);
        if (!user) {
            return res.status(401).json({ error: 'User not found.' });
        }
        if (user.banned) {
            return res.status(403).json({ error: 'Your account has been suspended. Contact support.' });
        }
        if (!user.verified) {
            return res.status(403).json({ error: 'Email not verified.' });
        }
        req.user = user;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
}

module.exports = { generateToken, authMiddleware, JWT_SECRET };
