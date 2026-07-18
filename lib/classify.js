const { classifyProvider, identifyMxProvider, isAntiProbeProvider, isDisposable, isRoleAccount, FREE_PROVIDERS } = require('../data/domainData');

/**
 * Pure binary classification: VALID or INVALID.
 * No scores. No ambiguity. Just the verdict.
 *
 * Logic:
 *   - No MX record → INVALID (domain can't receive mail)
 *   - Disposable domain → INVALID
 *   - SMTP accepted → VALID
 *   - SMTP rejected with clear "mailbox not found" → INVALID
 *   - SMTP rejected with policy/anti-spam reason → VALID (server is blocking US, not the mailbox)
 *   - SMTP rejected with ambiguous 550 on anti-probe provider → VALID (Google/Microsoft/etc love to reject probes)
 *   - SMTP temp_fail (greylisting) → VALID (server exists, just being cautious)
 *   - SMTP connection failed but MX exists → VALID (port 25 blocked by ISP, domain is legit)
 *   - Sender rejected (MAIL FROM rejected) → VALID (anti-spam blocking our probe sender, not the mailbox)
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
    return finalize('valid', isCatchAllDomain ? 'catch_all_domain' : 'smtp_accepted');
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

    // Policy rejection = server is blocking our probe, not the mailbox
    if (rejType === 'policy_rejection') {
      return finalize('valid', 'policy_rejection');
    }

    // Ambiguous 550 on a known anti-probe provider (Google Workspace, Microsoft 365, etc.)
    // These providers reject cold probes as standard anti-spam behavior
    if (rejType === 'ambiguous_550' && isAntiProbe) {
      return finalize('valid', 'anti_probe_provider');
    }

    // Ambiguous 550 on unknown provider — still likely policy, but less certain
    // Corporate servers overwhelmingly use generic 550s for anti-spam
    if (rejType === 'ambiguous_550') {
      return finalize('valid', 'ambiguous_rejection');
    }

    // Unknown rejection type — if MX exists and resolved, lean valid
    // A working mail server that rejects a cold probe is normal behavior
    return finalize('valid', 'server_rejected_probe');
  }

  // Sender rejected (MAIL FROM rejected) — usually anti-spam, BUT if it's a
  // sender-IP block (Spamhaus/RBL) we can't verify the mailbox at all → INVALID.
  if (smtpOutcome.result === 'sender_rejected') {
    if (smtpOutcome.rejectionType === 'sender_blocked') {
      return finalize('invalid', 'sender_ip_blocked');
    }
    return finalize('valid', 'sender_rejected_antispam');
  }

  // Temp fail (4xx) — greylisting or temporary issue. Server exists and works.
  // BUT if the 4xx is actually a sender-IP rate-limit/block, we can't verify → INVALID.
  if (smtpOutcome.result === 'temp_fail') {
    if (smtpOutcome.rejectionType === 'sender_blocked') {
      return finalize('invalid', 'sender_ip_blocked');
    }
    return finalize('valid', 'greylisted_or_temp_error');
  }

  // Connection failed but MX records exist — ISP blocks port 25, domain is legit
  if (smtpOutcome.result === 'connection_failed') {
    return finalize('valid', 'mx_exists_smtp_blocked');
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
