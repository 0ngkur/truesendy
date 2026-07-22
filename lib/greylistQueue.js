const fs = require('fs');
const path = require('path');

const QUEUE_PATH = path.join(__dirname, '..', 'db', 'greylist.json');

let _queue = null;
let _saveTimer = null;

function loadQueue() {
    if (_queue) return _queue;
    try {
        _queue = JSON.parse(fs.readFileSync(QUEUE_PATH, 'utf8'));
    } catch (_) {
        _queue = {};
    }
    return _queue;
}

function saveQueue() {
    if (_saveTimer) clearTimeout(_saveTimer);
    _saveTimer = setTimeout(() => {
        try {
            fs.writeFileSync(QUEUE_PATH, JSON.stringify(_queue));
        } catch (err) {
            console.error('[Greylist] Save error:', err.message);
        }
    }, 2000);
}

function addToQueue(email, domain, mxHosts) {
    const q = loadQueue();
    q[email] = {
        domain,
        mxHosts,
        retryCount: 0,
        nextRetryAt: Date.now() + 300000,
        createdAt: Date.now(),
        result: null,
    };
    saveQueue();
}

function getPending() {
    const q = loadQueue();
    const now = Date.now();
    const pending = [];
    for (const [email, entry] of Object.entries(q)) {
        if (entry.result !== null) continue;
        if (entry.nextRetryAt <= now) {
            pending.push({ email, ...entry });
        }
    }
    return pending;
}

function updateEntry(email, result) {
    const q = loadQueue();
    if (!q[email]) return;
    if (result === 'accepted' || result === 'rejected' || (result.result === 'accepted' || result.result === 'rejected' || result.result === 'sender_rejected')) {
        q[email].result = result;
    } else {
        q[email].retryCount = (q[email].retryCount || 0) + 1;
        if (q[email].retryCount >= 3) {
            q[email].result = { result: 'connection_failed', reason: 'greylist_exhausted' };
        } else {
            const delays = [300000, 900000, 1800000];
            q[email].nextRetryAt = Date.now() + delays[q[email].retryCount] || 1800000;
        }
    }
    saveQueue();
}

function getResult(email) {
    const q = loadQueue();
    return q[email] ? q[email].result : null;
}

function isGreylisted(email) {
    const q = loadQueue();
    return !!q[email] && q[email].result === null;
}

function cleanup() {
    const q = loadQueue();
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000;
    let changed = false;
    for (const [email, entry] of Object.entries(q)) {
        if (entry.result !== null || (now - entry.createdAt) > maxAge) {
            delete q[email];
            changed = true;
        }
    }
    if (changed) saveQueue();
}

function startWorker(verifyFn, intervalMs) {
    const interval = intervalMs || 60000;
    setInterval(async () => {
        const pending = getPending();
        if (pending.length === 0) return;
        console.log(`[Greylist] Processing ${pending.length} queued emails...`);
        for (const entry of pending.slice(0, 50)) {
            try {
                const result = await verifyFn(entry.email);
                updateEntry(entry.email, result);
            } catch (err) {
                updateEntry(entry.email, { result: 'connection_failed', reason: err.message });
            }
        }
        cleanup();
    }, interval).unref();
    
    setInterval(() => cleanup(), 15 * 60 * 1000).unref();
}

module.exports = { addToQueue, getPending, updateEntry, getResult, isGreylisted, cleanup, startWorker };
