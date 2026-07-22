const {
  classifyProvider,
  identifyMxProvider,
  isAntiProbeProvider,
  isDisposable,
  isSpamtrap,
  isRoleAccount,
  FREE_PROVIDERS,
  isKnownBigProvider,
  isKnownCatchAllProvider,
} = require('../data/domainData');
const historyDB = require('./historyDB');
const { analyzeLocalPart } = require('./patternAnalyzer');
const { getDomainRiskScore } = require('./domainAge');

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
  const spamtrap     = isSpamtrap(domain);
  const roleBased    = isRoleAccount(localPart);
  const mxProvider   = identifyMxProvider(mxHosts || []);
  const isAntiProbe  = isAntiProbeProvider(mxProvider);
  const isFreeEmail  = !!FREE_PROVIDERS[domain.toLowerCase()];
  const knownCatchAll = isKnownCatchAllProvider(mxProvider);
  const mxRecords    = (mxHosts || []).join('; ');

  // Domain reputation from historical data (Phase 2)
  const domainRep = historyDB.getDomainReputation(domain);
  const isTrustedDomain = domainRep ? domainRep.isTrusted : false;
  const isNewDomain = domainRep ? domainRep.isNew : false;
  const domainValidRate = domainRep ? domainRep.validRate : null;

  // Phase 4: Pattern analysis + domain risk
  const patternResult = analyzeLocalPart(localPart);
  const domainRisk = getDomainRiskScore(domain);
  const totalRiskPenalty = patternResult.penalty + domainRisk.penalty;

  // "Personal" for well-known webmail providers, "Professional" for custom domains
  const emailCategory = isFreeEmail ? 'Personal' : 'Professional';

  // ── SPAMTRAP DETLECTION — known toxic domains ───────────────────────────────
  if (spamtrap && !isFreeEmail) {
    return finalize('invalid', 'spamtrap_domain', false, 0);
  }

  // ── CONFIRMED INVALID — domain/mailbox definitively can't receive ────────────
  if (!hadMx) {
    return finalize('invalid', 'no_mx_record', false, 0);
  }
  // NOTE: Disposable/temp-mail domains are NOT auto-rejected. They are verified
  // normally through SMTP and just flagged as is_disposable=true in the result.
  // This matches Reon's behavior — verify everything, remove nothing.

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
      // On anti-probe providers, policy rejections are expected — doesn't mean invalid
      if (isAntiProbe || isKnownBigProvider(domain)) {
        return finalize('unknown', 'policy_rejection', true, 75);
      }
      // On regular servers, a policy rejection usually means the mailbox doesn't exist
      // or the domain has strict anti-spam that rejects unknown recipients.
      // Reoon classifies these as invalid — we should too.
      return finalize('invalid', 'policy_rejection', false, 5);
    }

    // Our sending IP is blacklisted — says nothing about the mailbox
    if (rejType === 'sender_blocked') {
      if (isCatchAllDomain) {
        return finalize('catch_all', 'catch_all_domain', false, 75);
      }
      // On anti-probe providers, sender blocks are common — still likely valid
      if (isAntiProbe || isKnownBigProvider(domain)) {
        return finalize('unknown', 'sender_ip_blocked', true, 70);
      }
      // On regular/unknown servers, sender_blocked often correlates with
      // non-existent mailboxes (small mail servers block + reject unknown).
      // Reoon classifies these as invalid for non-big providers.
      return finalize('invalid', 'sender_ip_blocked', false, 5);
    }

    // Ambiguous 550 — can't tell if mailbox-not-found or policy
    if (rejType === 'ambiguous_550') {
      if (isCatchAllDomain) {
        return finalize('catch_all', 'catch_all_domain', false, 75);
      }
      // On anti-probe providers, a 550 may be a false negative (blocking probes)
      if (isAntiProbe) {
        return finalize('unknown', 'anti_probe_provider', true, 70);
      }
      // On regular servers, a bare 550 without anti-probe is almost always
      // "mailbox not found". Reoon classifies these as invalid. We should too
      // instead of marking them unknown.
      return finalize('invalid', 'ambiguous_rejection', false, 5);
    }

    // Generic unknown rejection
    if (isCatchAllDomain) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    // On anti-probe providers, unknown rejections are likely anti-spam
    if (isAntiProbe) {
      return finalize('unknown', 'server_rejected_probe', true, 70);
    }
    // On regular servers, any 5xx rejection without a clear reason
    // is more likely invalid than unknown. Reoon agrees.
    return finalize('invalid', 'server_rejected_probe', false, 5);
  }

  // ── MAIL FROM rejected — anti-spam on OUR sender, not the mailbox ───────────
  if (smtpOutcome.result === 'sender_rejected') {
    if (isCatchAllDomain) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    const reason = smtpOutcome.rejectionType === 'sender_blocked'
      ? 'sender_ip_blocked'
      : 'sender_rejected_antispam';
    if (isAntiProbe || isKnownBigProvider(domain)) {
      return finalize('unknown', reason, true, 70);
    }
    // On regular servers, persistent sender rejection means the server
    // doesn't want our probes — classify as invalid (matches Reoon).
    return finalize('invalid', reason, false, 5);
  }

  // ── Temp fail (4xx) — greylisting / "try again later" ───────────────────────
  if (smtpOutcome.result === 'temp_fail') {
    if (isCatchAllDomain) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    // sender_blocked via 4xx — same logic as 5xx sender_blocked
    if (smtpOutcome.rejectionType === 'sender_blocked') {
      if (isAntiProbe || isKnownBigProvider(domain)) {
        return finalize('unknown', 'sender_ip_blocked', true, 70);
      }
      return finalize('invalid', 'sender_ip_blocked', false, 5);
    }
    // On anti-probe providers, 4xx is expected greylisting behavior
    if (isAntiProbe) {
      return finalize('unknown', 'greylisted_or_temp_error', true, 70);
    }
    // On regular servers, persistent 4xx (even after retry in smtpProbe.js)
    // usually means the server is misconfigured or the mailbox is problematic.
    // Mark as unknown — we genuinely can't tell.
    return finalize('unknown', 'greylisted_or_temp_error', false, 35);
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

  function finalize(status, reasonCode, safeToSend, baseScore) {
    // Feature-weighted score adjustment (Phase 2 + Phase 4)
    let score = baseScore;
    
    // Trusted domain bonus (high valid rate over many checks)
    if (isTrustedDomain && score > 0) score = Math.min(100, score + 10);
    
    // New domain penalty (registered < 7 days ago in our system)
    if (isNewDomain && score > 0) score = Math.max(0, score - 15);
    
    // Previously verified email bonus — check history for this exact email
    const emailHistory = historyDB.getEmailHistory(email);
    if (emailHistory && (emailHistory.status === 'safe' || emailHistory.status === 'valid') && score > 0) {
      score = Math.min(100, score + 10);
    }
    
    // Free email provider small bonus (Gmail, Outlook, etc. — infrastructure is reliable)
    if (isFreeEmail && score > 0 && status !== 'invalid') score = Math.min(100, score + 3);
    
    // Phase 4: Pattern analysis penalty (gibberish, numbers, keyboard smash)
    if (totalRiskPenalty > 0 && score > 0 && status !== 'invalid') {
      score = Math.max(0, score - totalRiskPenalty);
    }
    
    return {
      email,
      domain,
      providerType,
      mxProvider: mxProvider || null,
      mxRecords: mxRecords || '',
      emailCategory,
      status,
      reasonCode,
      safeToSend,
      overallScore: Math.round(score),
      flags: {
        disposable,
        spamtrap,
        roleBased,
        catchAll: isCatchAllDomain || status === 'catch_all',
        freeEmail: isFreeEmail,
      },
    };
  }
}

module.exports = { buildResult };
