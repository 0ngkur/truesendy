const { classifyProvider, identifyMxProvider, isAntiProbeProvider, isDisposable, isRoleAccount, FREE_PROVIDERS } = require('../data/domainData');

/**
 * Binary classification: VALID or INVALID.
 * CONSERVATIVE — only mark VALID when we have POSITIVE confirmation the mailbox
 * exists and can receive. Everything unconfirmable is INVALID (protects cold
 * email sender reputation from bounces).
 *
 * VALID only when:
 *   - SMTP 250 accepted for a NON-catch-all mailbox (the one definitive signal)
 *   - Mailbox full (5.2.2) — the server confirmed the mailbox EXISTS, just full
 *
 * INVALID when:
 *   - No MX record / disposable domain
 *   - Catch-all domain (accepts everything — can't confirm the specific mailbox)
 *   - Mailbox not found (5.1.1 / "does not exist")
 *   - Sender-IP blocked (Spamhaus/RBL — our IP, not the recipient)
 *   - Policy / anti-spam rejection (server blocked the probe — unconfirmable)
 *   - Ambiguous rejection, temp fail, connection failed (unconfirmable)
 */
function buildResult({ email, localPart, domain, smtpOutcome, isCatchAllDomain, hadMx, mxHosts }) {
  const providerType = classifyProvider(domain);
  const disposable = isDisposable(domain);
  const roleBased = isRoleAccount(localPart);
  const mxProvider = identifyMxProvider(mxHosts || []);
  const isAntiProbe = isAntiProbeProvider(mxProvider);

  const emailCategory = FREE_PROVIDERS[domain] ? 'Personal' : 'Professional';

  // --- Hard INVALID cases ---
  if (!hadMx) {
    return finalize('invalid', 'no_mx_record');
  }
  if (disposable) {
    return finalize('invalid', 'disposable_domain');
  }

  // --- SMTP result analysis ---
  if (smtpOutcome.result === 'accepted') {
    // Catch-all domain: the server accepts EVERY address (real + fake probe both
    // accepted), so we CANNOT confirm the specific mailbox exists. For cold email,
    // an unconfirmable address is a bounce risk → mark INVALID (conservative).
    // Only a TRUE single-mailbox acceptance is VALID.
    if (isCatchAllDomain) {
      return finalize('invalid', 'catch_all_domain');
    }
    return finalize('valid', 'smtp_accepted');
  }

  if (smtpOutcome.result === 'rejected') {
    const rejType = smtpOutcome.rejectionType;

    // Only mark INVALID if the server explicitly said "this mailbox does not exist"
    if (rejType === 'mailbox_not_found') {
      return finalize('invalid', 'mailbox_not_found');
    }

    // ── Sender-IP block (Spamhaus / RBL / reputation) ─────────────────────────
    // The rejection is about OUR sending IP, not the recipient. We CANNOT
    // determine if the mailbox exists. Mark INVALID (conservative) — never give
    // a false "valid" when the probe was blocked at the IP level. The user
    // should delist the server IP from the RBL for accurate results.
    if (rejType === 'sender_blocked') {
      return finalize('invalid', 'sender_ip_blocked');
    }

    // Mailbox full = email EXISTS, just full. That's valid.
    if (rejType === 'mailbox_full') {
      return finalize('valid', 'mailbox_full');
    }

    // Policy rejection = server blocked the probe. We CANNOT confirm the mailbox
    // exists → INVALID (conservative). For cold email, don't risk a bounce.
    if (rejType === 'policy_rejection') {
      return finalize('invalid', 'policy_rejection');
    }

    // Ambiguous 550 (anti-probe provider or unknown) — couldn't verify → INVALID.
    if (rejType === 'ambiguous_550') {
      return finalize('invalid', isAntiProbe ? 'anti_probe_provider' : 'ambiguous_rejection');
    }

    // Any other rejection — unverified → INVALID.
    return finalize('invalid', 'server_rejected_probe');
  }

  // Sender rejected (MAIL FROM rejected) — the server won't even accept our
  // sender address, so we can't verify the recipient → INVALID.
  if (smtpOutcome.result === 'sender_rejected') {
    return finalize('invalid', smtpOutcome.rejectionType === 'sender_blocked' ? 'sender_ip_blocked' : 'sender_rejected_antispam');
  }

  // Temp fail (4xx) — greylisting or temporary issue. Couldn't confirm → INVALID.
  if (smtpOutcome.result === 'temp_fail') {
    return finalize('invalid', smtpOutcome.rejectionType === 'sender_blocked' ? 'sender_ip_blocked' : 'greylisted_or_temp_error');
  }

  // Connection failed but MX records exist — couldn't reach the server to verify → INVALID.
  if (smtpOutcome.result === 'connection_failed') {
    return finalize('invalid', 'mx_exists_smtp_blocked');
  }

  // Fallback — should never reach here, but if MX existed, lean valid
  return finalize('valid', 'unknown');

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
