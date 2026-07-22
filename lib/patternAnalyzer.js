/**
 * Local-part pattern analyzer — detects fake/generated email addresses.
 * Returns a penalty score (0 = normal, higher = more suspicious).
 */

const KEYBOARD_PATTERNS = [
    'qwerty', 'asdf', 'zxcv', 'qwer', 'asdfgh', 'qwertyuiop',
    '123456', '1234567', '12345678', 'abcdef', 'abc123',
];

const TEST_PATTERNS = [
    'test', 'example', 'sample', 'demo', 'dummy', 'fake',
    'temp', 'temporary', 'placeholder', 'noreply', 'no-reply',
    'donotreply', 'do-not-reply', 'spam', 'trash', 'junk',
];

const SUSPICIOUS_TLDS = new Set([
    '.xyz', '.click', '.loan', '.work', '.men', '.review', '.party',
    '.trade', '.date', '.stream', '.gdn', '.racing', '.download',
    '.science', '.accountant', '.cricket', '.faith', '.bid',
    '.win', '.top', '.kim', '.cn', '.gq', '.tk', '.ml', '.cf', '.ga',
]);

function hasVowels(str) {
    return /[aeiouAEIOU]/.test(str);
}

function consecutiveConsonants(str) {
    let max = 0, current = 0;
    for (const ch of str) {
        if (/[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]/.test(ch)) {
            current++;
            max = Math.max(max, current);
        } else {
            current = 0;
        }
    }
    return max;
}

function analyzeLocalPart(localPart) {
    if (!localPart || localPart.length === 0) return { penalty: 0, flags: [] };

    const lp = localPart.toLowerCase();
    const flags = [];
    let penalty = 0;

    // 1. All numbers
    if (/^\d+$/.test(lp)) {
        flags.push('all_numbers');
        penalty += 15;
    }

    // 2. Gibberish — high consecutive consonants without vowels
    if (lp.length > 4 && !hasVowels(lp.replace(/[._\-\d]/g, ''))) {
        flags.push('no_vowels');
        penalty += 20;
    } else if (consecutiveConsonants(lp) >= 6) {
        flags.push('gibberish_consonants');
        penalty += 15;
    }

    // 3. Too many dots
    const dotCount = (lp.match(/\./g) || []).length;
    if (dotCount > 3) {
        flags.push('excessive_dots');
        penalty += 10;
    }

    // 4. Keyboard smash patterns
    for (const pattern of KEYBOARD_PATTERNS) {
        if (lp.includes(pattern)) {
            flags.push('keyboard_pattern');
            penalty += 15;
            break;
        }
    }

    // 5. Excessive length
    if (lp.length > 30) {
        flags.push('excessive_length');
        penalty += 10;
    }

    // 6. Test/spam patterns (only on non-role accounts — those are handled separately)
    for (const pattern of TEST_PATTERNS) {
        if (lp === pattern || lp.startsWith(pattern + '@') || lp === pattern + 's') {
            flags.push('test_pattern');
            penalty += 5;
            break;
        }
    }

    // 7. Looks like a random hash (mix of letters and numbers, no recognizable words)
    if (lp.length >= 8 && /[a-z]/.test(lp) && /\d/.test(lp) && !hasVowels(lp.substring(0, 4))) {
        flags.push('random_hash');
        penalty += 10;
    }

    return { penalty: Math.min(penalty, 40), flags };
}

function isSuspiciousTLD(domain) {
    if (!domain) return false;
    const d = domain.toLowerCase();
    for (const tld of SUSPICIOUS_TLDS) {
        if (d.endsWith(tld)) return true;
    }
    return false;
}

module.exports = { analyzeLocalPart, isSuspiciousTLD, SUSPICIOUS_TLDS };
