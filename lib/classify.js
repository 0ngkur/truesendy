const { classifyProvider, identifyMxProvider, isAntiProbeProvider, isDisposable, isRoleAccount, FREE_PROVIDERS } = require('../data/domainData');

/**
 * THREE-WAY classification: VALID, INVALID, or UNKNOWN.
 *
 * Only mark VALID or INVALID when we have DEFINITIVE proof. Everything
 * unconfirmable → UNKNOWN (so we never false-label an email).
 *
 * VALID (confirmed the mailbox exists + can receive):
 *   - SMTP 250 accepted on a NON-catch-all mailbox (server confirmed the specific address)
 *   - Mailbox full (5.2.2) — server confirmed the mailbox EXISTS, just full
 *
 * INVALID (confirmed the mailbox does NOT exist / cannot receive):
 *   - No MX record (domain can't receive mail at all)
 *   - Disposable domain (temporary email service)
 *   - Mailbox not found (5.1.1, "does not exist", "user unknown") — server EXPLICITLY said it doesn't exist
 *
 * UNKNOWN (cannot determine — could be either):
 *   - Catch-all domain (accepts everything — can't confirm the specific mailbox)
 *   - Policy/anti-spam rejection (server blocked the probe, not the mailbox)
 *   - Sender-IP blocked (OUR IP blacklisted — says nothing about the mailbox)
 *   - Connection failed (couldn't reach the server)
 *   - Temp fail / greylisting (server said "try again later")
 *   - Ambiguous rejection (can't tell if mailbox or policy)
 *   - Sender rejected (MAIL FROM blocked — anti-spam, not mailbox)
 */
function buildResult({ email, localPart, domain, smtpOutcome, isCatchAllDomain, hadMx, mxHosts }) {
  const providerType = classifyProvider(domain);
  const disposable = isDisposable(domain);
  const roleBased = isRoleAccount(localPart);
  const mxProvider = identifyMxProvider(mxHosts || []);
  const isAntiProbe = isAntiProbeProvider(mxProvider);

  const emailCategory = FREE_PROVIDERS[domain] ? 'Personal' : 'Professional';

  // ── CONFIRMED INVALID — domain/mailbox definitively can't receive ──────────
  if (!hadMx) {
    return finalize('invalid', 'no_mx_record');
  }
  if (disposable) {
    return finalize('invalid', 'disposable_domain');
  }

  // ── CONFIRMED VALID — server definitively accepted the specific mailbox ────
  if (smtpOutcome.result === 'accepted') {
    // Catch-all: server accepts ALL addresses — can't confirm the specific one → UNKNOWN
    if (isCatchAllDomain) {
      return finalize('unknown', 'catch_all_domain');
    }
    return finalize('valid', 'smtp_accepted');
  }

  if (smtpOutcome.result === 'rejected') {
    const rejType = smtpOutcome.rejectionType;

    // CONFIRMED INVALID — server explicitly said "this mailbox does not exist"
    if (rejType === 'mailbox_not_found') {
      return finalize('invalid', 'mailbox_not_found');
    }

    // Mailbox full = the mailbox EXISTS (server confirmed) → VALID
    if (rejType === 'mailbox_full') {
      return finalize('valid', 'mailbox_full');
    }

    // Everything else from a rejection is UNCONFIRMABLE → UNKNOWN:
    // - policy_rejection: server blocked the probe (anti-spam), not the mailbox
    // - sender_blocked: OUR IP is blacklisted (Spamhaus/RBL), nothing about the mailbox
    // - ambiguous_550: can't tell if mailbox-not-found or policy block
    // - unknown_rejection: server gave a code we can't interpret
    if (rejType === 'policy_rejection')      return finalize('unknown', 'policy_rejection');
    if (rejType === 'sender_blocked')        return finalize('unknown', 'sender_ip_blocked');
    if (rejType === 'ambiguous_550')         return finalize('unknown', isAntiProbe ? 'anti_probe_provider' : 'ambiguous_rejection');
    return finalize('unknown', 'server_rejected_probe');
  }

  // Sender rejected (MAIL FROM) — anti-spam on OUR sender, not the mailbox → UNKNOWN
  if (smtpOutcome.result === 'sender_rejected') {
    return finalize('unknown', smtpOutcome.rejectionType === 'sender_blocked' ? 'sender_ip_blocked' : 'sender_rejected_antispam');
  }

  // Temp fail (4xx) — greylisting / "try again later" → UNKNOWN (a retry might succeed)
  if (smtpOutcome.result === 'temp_fail') {
    return finalize('unknown', smtpOutcome.rejectionType === 'sender_blocked' ? 'sender_ip_blocked' : 'greylisted_or_temp_error');
  }

  // Connection failed but MX exists — we couldn't reach the server to verify → UNKNOWN
  if (smtpOutcome.result === 'connection_failed') {
    return finalize('unknown', 'mx_exists_smtp_blocked');
  }

  // Fallback — shouldn't reach here, but if it does, don't guess → UNKNOWN
  return finalize('unknown', 'unknown');

  function finalize(status, reasonCode) {
    return {
      email,
      domain,
      providerType,
      mxProvider: mxProvider || null,
      emailCategory,
      status,
      reasonCode,
      flags: { disposable, roleBased, catchAll: isCatchAllDomain },
    };
  }
}

module.exports = { buildResult };
