const { classifyProvider, isDisposable, isRoleAccount, FREE_PROVIDERS } = require('../data/domainData');

const LOW_TRUST_SMTP_DOMAINS = new Set([
  'yahoo.com', 'yahoo.co.uk', 'ymail.com', 'rocketmail.com',
]);

/**
 * Classify an email into: personal vs professional, active vs inactive,
 * and a granular status with confidence score.
 */
function buildResult({ email, localPart, domain, smtpOutcome, isCatchAllDomain, hadMx }) {
  const providerType = classifyProvider(domain);
  const disposable = isDisposable(domain);
  const roleBased = isRoleAccount(localPart);

  // Personal = free provider, Professional = custom domain
  const emailCategory = FREE_PROVIDERS[domain] ? 'Personal' : 'Professional';

  // --- Hard fails first ---
  if (!hadMx) {
    return finalize('invalid', 0, 'no_mx_record', 'Inactive');
  }
  if (disposable) {
    return finalize('disposable', 10, 'disposable_domain', 'Risky');
  }

  // --- SMTP-derived outcomes ---
  if (smtpOutcome.result === 'rejected') {
    return finalize('invalid', 5, 'smtp_rejected_rcpt', 'Inactive');
  }

  if (smtpOutcome.result === 'temp_fail') {
    return finalize('unknown', 50, 'greylisted_or_temp_error', 'Unknown');
  }

  if (smtpOutcome.result === 'connection_failed') {
    // Port 25 is blocked locally — this is NOT the email's fault.
    // We know MX exists, so the domain is real. Mark as risky/unknown, not invalid.
    return finalize('risky', 60, 'smtp_port_blocked_locally', 'Unknown');
  }

  // --- smtpOutcome.result === 'accepted' ---
  if (isCatchAllDomain) {
    return finalize('catch_all', 55, 'domain_accepts_all_addresses', 'Active (Catch-All)');
  }

  if (roleBased) {
    return finalize('role_based', 65, 'shared_mailbox_pattern', 'Active');
  }

  if (LOW_TRUST_SMTP_DOMAINS.has(domain)) {
    return finalize('risky', 70, 'smtp_accept_unreliable_for_this_provider', 'Likely Active');
  }

  return finalize('valid', 97, 'smtp_accepted_rcpt', 'Active');

  function finalize(status, score, reasonCode, activity) {
    return {
      email,
      domain,
      providerType,
      emailCategory,  // "Personal" or "Professional"
      status,
      score,
      activity,        // "Active", "Inactive", "Unknown", etc.
      flags: { disposable, roleBased, catchAll: isCatchAllDomain },
      reasonCode,
    };
  }
}

module.exports = { buildResult };
