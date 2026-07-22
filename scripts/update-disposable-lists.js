#!/usr/bin/env node
/**
 * Daily auto-refresh script for disposable and spamtrap domain lists.
 * Run via: node scripts/update-disposable-lists.js
 * Or set up as a daily cron job.
 */
const fs = require('fs');
const path = require('path');

const SOURCES = [
    {
        name: 'canonical',
        url: 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
        parse: (text) => text.split('\n').map(d => d.trim().toLowerCase()).filter(d => d && !d.startsWith('#')),
    },
    {
        name: 'large-list',
        url: 'https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.json',
        parse: (text) => { try { return JSON.parse(text.replace(/^\uFEFF/, '')).map(d => (d||'').trim().toLowerCase()).filter(Boolean); } catch { return []; } },
    },
    {
        name: 'stopforumspam',
        url: 'https://www.stopforumspam.com/downloads/toxic_domains_whole.txt',
        parse: (text) => text.split('\n').map(d => d.trim().toLowerCase()).filter(d => d && !d.startsWith('#')),
        isSpamtrap: true,
    },
];

async function fetchText(url) {
    const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return res.text();
}

async function main() {
    console.log('[update-lists] Starting domain list refresh...');
    const allDisposable = new Set();
    const allSpamtrap = new Set();

    for (const src of SOURCES) {
        try {
            const text = await fetchText(src.url);
            const domains = src.parse(text);
            console.log(`[update-lists] ${src.name}: ${domains.length} domains`);
            if (src.isSpamtrap) {
                domains.forEach(d => allSpamtrap.add(d));
            }
            domains.forEach(d => allDisposable.add(d));
        } catch (err) {
            console.error(`[update-lists] ${src.name} FAILED: ${err.message}`);
        }
    }

    const dataDir = path.join(__dirname, '..', 'data');
    const disposableSorted = [...allDisposable].sort();
    const spamtrapSorted = [...allSpamtrap].sort();

    fs.writeFileSync(path.join(dataDir, 'disposable-domains.json'), JSON.stringify(disposableSorted));
    fs.writeFileSync(path.join(dataDir, 'spamtrap-domains.json'), JSON.stringify(spamtrapSorted));

    console.log(`[update-lists] Done. Disposable: ${disposableSorted.length}, Spamtrap: ${spamtrapSorted.length}`);
    console.log('[update-lists] Restart server to load updated lists.');
}

main().catch(err => { console.error('[update-lists] Fatal:', err); process.exit(1); });
