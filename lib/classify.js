const {
  classifyProvider,
  identifyMxProvider,
  isAntiProbeProvider,
  isDisposable,
  isRoleAccount,
  FREE_PROVIDERS,
  isKnownBigProvider,
  isKnownCatchAllProvider,
} = require('../data/domainData');

/**
 * FIVE-WAY classification matching industry-standard verifiers (Reon, NeverBounce, ZeroBounce):
 *
 *  "safe"        – SMTP 250 accepted on a NON-catch-all, NON-role mailbox. Definitively good.
 *  "valid"       – SMTP accepted but is a role account (info@, admin@) — deliverable, use with caution.
 *  "catch_all"   – Domain accepts every address — cannot confirm the specific mailbox.
 *  "invalid"     – Confirmed does NOT exist (no MX, explicit mailbox-not-found, disposable, disabled).
 *  "unknown"     – SMTP blocked / unreachable. Cannot determine. Sub-typed via reasonCode.
 *
 * safe_to_send logic:
 *   - "safe"      → true
 *   - "valid"     → true  (role accounts are deliverable)
 *   - "catch_all" → false (risky — will bounce if mailbox doesn't exist)
 *   - "invalid"   → false
 *   - "unknown"   → depends on reason:
 *       - anti-probe provider (M365, Google WS, Mimecast, Proofpoint, etc.) → true
 *         (these providers intentionally block SMTP probes but the domain/mailbox is very likely real)
 *       - otherwise → false
 *
 * overall_score (0–100):
 *   - "safe"      → 98
 *   - "valid" role→ 85
 *   - "catch_all" → 75 (matches Reon score for confirmed catch-all)
 *   - "unknown" anti-probe → 75
 *   - "unknown" other → 30
 *   - "invalid"   → 0–5
 */
function buildResult({ email, localPart, domain, smtpOutcome, isCatchAllDomain, hadMx, mxHosts }) {
  const providerType = classifyProvider(domain);
  const disposable   = isDisposable(domain);
  const roleBased    = isRoleAccount(localPart);
  const mxProvider   = identifyMxProvider(mxHosts || []);
  const isAntiProbe  = isAntiProbeProvider(mxProvider);
  const isFreeEmail  = !!FREE_PROVIDERS[domain.toLowerCase()];
  const knownCatchAll = isKnownCatchAllProvider(mxProvider);

  // "Personal" for well-known webmail providers, "Professional" for custom domains
  const emailCategory = isFreeEmail ? 'Personal' : 'Professional';

  // ── CONFIRMED INVALID — domain/mailbox definitively can't receive ────────────
  if (!hadMx) {
    return finalize('invalid', 'no_mx_record', false, 0);
  }
  if (disposable) {
    return finalize('invalid', 'disposable_domain', false, 2);
  }

  // ── CATCH-ALL via MX provider heuristic ──────────────────────────────────────
  // Certain MX infrastructure providers (e.g. FastMail) are known to be catch-all.
  // We don't need SMTP proof — classify directly.
  if (knownCatchAll && smtpOutcome.result !== 'rejected') {
    return finalize('catch_all', 'known_catchall_provider', false, 75);
  }

  // ── SMTP ACCEPTED ────────────────────────────────────────────────────────────
  if (smtpOutcome.result === 'accepted') {
    if (isCatchAllDomain) {
      // Server accepts ALL addresses — can't confirm the specific mailbox
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    if (roleBased) {
      return finalize('valid', 'smtp_accepted', true, 85);
    }
    return finalize('safe', 'smtp_accepted', true, 98);
  }

  // ── SMTP REJECTED ────────────────────────────────────────────────────────────
  if (smtpOutcome.result === 'rejected') {
    const rejType = smtpOutcome.rejectionType;

    // Confirmed invalid — server explicitly said this mailbox does not exist
    if (rejType === 'mailbox_not_found') {
      return finalize('invalid', 'mailbox_not_found', false, 0);
    }

    // Mailbox disabled — EXISTS but can't receive (5.2.1)
    if (rejType === 'mailbox_disabled') {
      return finalize('invalid', 'mailbox_disabled', false, 3);
    }

    // Mailbox full — EXISTS (server confirmed) but full right now (5.2.2)
    if (rejType === 'mailbox_full') {
      return roleBased
        ? finalize('valid', 'mailbox_full', true, 80)
        : finalize('safe', 'mailbox_full', true, 90);
    }

    // Policy rejection — server blocked the probe (anti-spam), not the mailbox
    if (rejType === 'policy_rejection') {
      if (isCatchAllDomain) {
        return finalize('catch_all', 'catch_all_domain', false, 75);
      }
      const safeSend = isAntiProbe || isKnownBigProvider(domain);
      const score    = safeSend ? 75 : 30;
      return finalize('unknown', 'policy_rejection', safeSend, score);
    }

    // Our sending IP is blacklisted — says nothing about the mailbox
    if (rejType === 'sender_blocked') {
      if (isCatchAllDomain) {
        return finalize('catch_all', 'catch_all_domain', false, 75);
      }
      // On anti-probe providers, sender blocks are common — still likely valid
      const safeSend = isAntiProbe || isKnownBigProvider(domain);
      return finalize('unknown', 'sender_ip_blocked', safeSend, safeSend ? 70 : 25);
    }

    // Ambiguous 550 — can't tell if mailbox-not-found or policy
    if (rejType === 'ambiguous_550') {
      if (isCatchAllDomain) {
        return finalize('catch_all', 'catch_all_domain', false, 75);
      }
      const safeSend = isAntiProbe;
      const reason   = isAntiProbe ? 'anti_probe_provider' : 'ambiguous_rejection';
      const score    = isAntiProbe ? 70 : 20;
      return finalize('unknown', reason, safeSend, score);
    }

    // Generic unknown rejection
    if (isCatchAllDomain) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    return finalize('unknown', 'server_rejected_probe', false, 20);
  }

  // ── MAIL FROM rejected — anti-spam on OUR sender, not the mailbox ───────────
  if (smtpOutcome.result === 'sender_rejected') {
    if (isCatchAllDomain) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    const safeSend = isAntiProbe;
    const reason   = smtpOutcome.rejectionType === 'sender_blocked'
      ? 'sender_ip_blocked'
      : 'sender_rejected_antispam';
    return finalize('unknown', reason, safeSend, isAntiProbe ? 70 : 25);
  }

  // ── Temp fail (4xx) — greylisting / "try again later" ───────────────────────
  if (smtpOutcome.result === 'temp_fail') {
    if (isCatchAllDomain) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    const safeSend = isAntiProbe;
    const reason   = smtpOutcome.rejectionType === 'sender_blocked'
      ? 'sender_ip_blocked'
      : 'greylisted_or_temp_error';
    return finalize('unknown', reason, safeSend, isAntiProbe ? 70 : 35);
  }

  // ── Connection failed — MX exists but all ports unreachable ──────────────────
  // For ANTI-PROBE PROVIDERS (Microsoft 365, Google Workspace, Mimecast, Proofpoint, etc.):
  //   These providers INTENTIONALLY block external SMTP probes. The domain is real,
  //   MX records exist — the email is very likely valid.
  //   → safe_to_send = TRUE, score = 75 (matches Reon's behavior for these providers)
  //
  // If the domain is also a known catch-all provider → classify as catch_all.
  //
  // For unknown/custom servers: truly unreachable — cannot determine.
  //   → safe_to_send = FALSE, score = 30
  if (smtpOutcome.result === 'connection_failed') {
    if (isCatchAllDomain || knownCatchAll) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    const safeSend = isAntiProbe || isKnownBigProvider(domain);
    const score    = safeSend ? 75 : 30;
    return finalize('unknown', 'mx_exists_smtp_blocked', safeSend, score);
  }

  // Fallback — shouldn't reach here
  return finalize('unknown', 'unknown', false, 20);

  function finalize(status, reasonCode, safeToSend, score) {
    return {
      email,
      domain,
      providerType,
      mxProvider: mxProvider || null,
      emailCategory,
      status,
      reasonCode,
      safeToSend,
      overallScore: score,
      flags: {
        disposable,
        roleBased,
        catchAll: isCatchAllDomain,
        freeEmail: isFreeEmail,
      },
    };
  }
}

module.exports = { buildResult };
