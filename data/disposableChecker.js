const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname);

let _disposableSet = null;
let _spamtrapSet = null;

function loadDisposable() {
    if (_disposableSet) return _disposableSet;
    try {
        const arr = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'disposable-domains.json'), 'utf8'));
        _disposableSet = new Set(arr);
    } catch (_) {
        _disposableSet = new Set();
    }
    return _disposableSet;
}

function loadSpamtrap() {
    if (_spamtrapSet) return _spamtrapSet;
    try {
        const arr = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'spamtrap-domains.json'), 'utf8'));
        _spamtrapSet = new Set(arr);
    } catch (_) {
        _spamtrapSet = new Set();
    }
    return _spamtrapSet;
}

function isDisposable(domain) {
    if (!domain) return false;
    const d = domain.toLowerCase();
    const set = loadDisposable();
    if (set.has(d)) return true;
    const parts = d.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
        const parent = parts.slice(i).join('.');
        if (set.has(parent)) return true;
    }
    return false;
}

function isSpamtrap(domain) {
    if (!domain) return false;
    const d = domain.toLowerCase();
    const set = loadSpamtrap();
    return set.has(d);
}

function getDisposableCount() {
    return loadDisposable().size;
}

function getSpamtrapCount() {
    return loadSpamtrap().size;
}

module.exports = { isDisposable, isSpamtrap, getDisposableCount, getSpamtrapCount, loadDisposable, loadSpamtrap };
