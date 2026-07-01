const jwt = require('jsonwebtoken');
const store = require('../db/store');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('[TrueSendy] FATAL: JWT_SECRET environment variable is required.');
    process.exit(1);
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
