const fs = require('fs');
const path = require('path');

const HISTORY_PATH = path.join(__dirname, '..', 'db', 'history.json');
const REPUTATION_PATH = path.join(__dirname, '..', 'db', 'domain-reputation.json');

const MAX_HISTORY = 500000;
const MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;
const SAVE_INTERVAL = 5000;

let _history = null;
let _reputation = null;
let _dirty = false;
let _saveTimer = null;

function loadHistory() {
    if (_history) return _history;
    try {
        const raw = fs.readFileSync(HISTORY_PATH, 'utf8');
        _history = JSON.parse(raw);
    } catch (_) {
        _history = {};
    }
    return _history;
}

function loadReputation() {
    if (_reputation) return _reputation;
    try {
        const raw = fs.readFileSync(REPUTATION_PATH, 'utf8');
        _reputation = JSON.parse(raw);
    } catch (_) {
        _reputation = {};
    }
    return _reputation;
}

function scheduleSave() {
    if (_saveTimer) return;
    _saveTimer = setTimeout(() => {
        _saveTimer = null;
        _dirty = false;
        try {
            fs.writeFileSync(HISTORY_PATH, JSON.stringify(_history));
        } catch (e) { console.error('[History] Save error:', e.message); }
        try {
            fs.writeFileSync(REPUTATION_PATH, JSON.stringify(_reputation));
        } catch (e) { console.error('[Reputation] Save error:', e.message); }
    }, SAVE_INTERVAL);
}

function recordResult(email, domain, status, score, reasonCode) {
    const h = loadHistory();
    h[email.toLowerCase()] = {
        domain: domain.toLowerCase(),
        status,
        score,
        reasonCode,
        timestamp: Date.now(),
    };
    _dirty = true;
    
    if (Object.keys(h).length > MAX_HISTORY) {
        cleanup();
    }
    
    const r = loadReputation();
    const d = domain.toLowerCase();
    if (!r[d]) {
        r[d] = { total: 0, valid: 0, invalid: 0, catchAll: 0, unknown: 0, firstSeen: Date.now(), lastSeen: Date.now() };
    }
    r[d].total++;
    r[d].lastSeen = Date.now();
    if (status === 'safe' || status === 'valid') r[d].valid++;
    else if (status === 'invalid') r[d].invalid++;
    else if (status === 'catch_all') r[d].catchAll++;
    else r[d].unknown++;
    
    scheduleSave();
}

function getEmailHistory(email) {
    const h = loadHistory();
    const entry = h[email.toLowerCase()];
    if (!entry) return null;
    if (Date.now() - entry.timestamp > MAX_AGE_MS) {
        delete h[email.toLowerCase()];
        return null;
    }
    return entry;
}

function getDomainReputation(domain) {
    const r = loadReputation();
    const d = domain.toLowerCase();
    const rep = r[d];
    if (!rep) return null;
    
    const ageMs = Date.now() - rep.firstSeen;
    const ageDays = ageMs / (24 * 60 * 60 * 1000);
    const validRate = rep.total > 0 ? rep.valid / rep.total : 0;
    
    return {
        ...rep,
        ageDays: Math.floor(ageDays),
        isNew: ageDays < 7,
        isTrusted: rep.total >= 10 && validRate >= 0.90,
        validRate: Math.round(validRate * 100),
    };
}

function cleanup() {
    const h = loadHistory();
    const cutoff = Date.now() - MAX_AGE_MS;
    let removed = 0;
    for (const [email, entry] of Object.entries(h)) {
        if (entry.timestamp < cutoff) {
            delete h[email];
            removed++;
        }
    }
    if (removed > 0) {
        _dirty = true;
        scheduleSave();
    }
    return removed;
}

function getStats() {
    const h = loadHistory();
    const r = loadReputation();
    return {
        historyEntries: Object.keys(h).length,
        trackedDomains: Object.keys(r).length,
    };
}

setInterval(() => cleanup(), 60 * 60 * 1000).unref();

module.exports = {
    recordResult,
    getEmailHistory,
    getDomainReputation,
    cleanup,
    getStats,
};
