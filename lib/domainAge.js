/**
 * Domain age and reputation scoring.
 * Uses history database + TLD heuristics to assess domain trustworthiness.
 */
const historyDB = require('./historyDB');
const { isSuspiciousTLD } = require('./patternAnalyzer');

function getDomainRiskScore(domain) {
    if (!domain) return { penalty: 0, flags: [] };

    const d = domain.toLowerCase();
    const flags = [];
    let penalty = 0;

    // 1. Suspicious TLD
    if (isSuspiciousTLD(d)) {
        flags.push('suspicious_tld');
        penalty += 15;
    }

    // 2. Domain reputation from history
    const rep = historyDB.getDomainReputation(d);
    if (rep) {
        if (rep.isNew) {
            // Domain first seen < 7 days ago in our system
            if (rep.ageDays < 1) {
                flags.push('domain_seen_today');
                penalty += 20;
            } else {
                flags.push('new_domain');
                penalty += 10;
            }
        }

        // High invalid rate — domain has mostly invalid emails
        if (rep.total >= 10 && rep.validRate < 30) {
            flags.push('low_valid_rate');
            penalty += 15;
        }
    } else {
        // Never seen this domain before — slight penalty
        flags.push('unknown_domain');
        penalty += 5;
    }

    return { penalty: Math.min(penalty, 35), flags, reputation: rep };
}

module.exports = { getDomainRiskScore };
