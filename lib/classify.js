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
        ? finalize('valid', 'mailbox_full', true, 85)
        : finalize('safe', 'mailbox_full', true, 95);
    }

    // Policy rejection — server blocked the probe (anti-spam), not the mailbox
    if (rejType === 'policy_rejection') {
      if (isCatchAllDomain) {
        return finalize('catch_all', 'catch_all_domain', false, 75);
      }
      // On anti-probe providers, policy rejections are expected — can't determine
      if (isAntiProbe || isKnownBigProvider(domain)) {
        return finalize('unknown', 'policy_rejection', false, 0);
      }
      return finalize('invalid', 'policy_rejection', false, 3);
    }

    // Our sending IP is blacklisted — says nothing about the mailbox
    if (rejType === 'sender_blocked') {
      if (isCatchAllDomain) {
        return finalize('catch_all', 'catch_all_domain', false, 75);
      }
      if (isAntiProbe || isKnownBigProvider(domain)) {
        return finalize('unknown', 'sender_ip_blocked', false, 0);
      }
      return finalize('invalid', 'sender_ip_blocked', false, 3);
    }

    // Ambiguous 550 — can't tell if mailbox-not-found or policy
    if (rejType === 'ambiguous_550') {
      if (isCatchAllDomain) {
        return finalize('catch_all', 'catch_all_domain', false, 75);
      }
      if (isAntiProbe) {
        return finalize('unknown', 'anti_probe_provider', false, 0);
      }
      return finalize('invalid', 'ambiguous_rejection', false, 3);
    }

    // Generic unknown rejection
    if (isCatchAllDomain) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    if (isAntiProbe) {
      return finalize('unknown', 'server_rejected_probe', false, 0);
    }
    return finalize('invalid', 'server_rejected_probe', false, 3);
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
      return finalize('unknown', reason, false, 0);
    }
    return finalize('invalid', reason, false, 3);
  }

  // ── Temp fail (4xx) — greylisting / "try again later" ───────────────────────
  if (smtpOutcome.result === 'temp_fail') {
    if (isCatchAllDomain) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    if (smtpOutcome.rejectionType === 'sender_blocked') {
      if (isAntiProbe || isKnownBigProvider(domain)) {
        return finalize('unknown', 'sender_ip_blocked', false, 0);
      }
      return finalize('invalid', 'sender_ip_blocked', false, 3);
    }
    if (isAntiProbe) {
      return finalize('unknown', 'greylisted_or_temp_error', false, 0);
    }
    return finalize('unknown', 'greylisted_or_temp_error', false, 0);
  }

  // ── Connection failed — MX exists but all ports unreachable ──────────────────
  // Fix 2+5: Anti-probe providers return unknown with NO score, safeToSend=false
  // (matches Reoon exactly). Non-anti-probe with no MX acceptance = invalid.
  if (smtpOutcome.result === 'connection_failed') {
    if (isCatchAllDomain || knownCatchAll) {
      return finalize('catch_all', 'catch_all_domain', false, 75);
    }
    // Anti-probe providers block SMTP — can't determine, conservative
    if (isAntiProbe || isKnownBigProvider(domain)) {
      return finalize('unknown', 'mx_exists_smtp_blocked', false, 0);
    }
    // Fix 5: Unknown domain with SMTP blocked and no catch-all = invalid
    return finalize('invalid', 'mx_exists_smtp_blocked', false, 3);
  }

  // Fallback — shouldn't reach here
  return finalize('unknown', 'unknown', false, 20);

  function finalize(status, reasonCode, safeToSend, baseScore) {
    // Feature-weighted score adjustment (Phase 2 + Phase 4)
    // Penalties ONLY apply to 'unknown' status — safe/valid/catch_all are
    // definitive results from SMTP/M365 and should not be penalized.
    let score = baseScore;
    
    // Trusted domain bonus (high valid rate over many checks)
    if (isTrustedDomain && score > 0) score = Math.min(100, score + 10);
    
    // New domain penalty — only for unknown status
    if (isNewDomain && score > 0 && status === 'unknown') score = Math.max(0, score - 15);
    
    // Previously verified email bonus — check history for this exact email
    const emailHistory = historyDB.getEmailHistory(email);
    if (emailHistory && (emailHistory.status === 'safe' || emailHistory.status === 'valid') && score > 0) {
      score = Math.min(100, score + 10);
    }
    
    // Free email provider small bonus (Gmail, Outlook, etc. — infrastructure is reliable)
    if (isFreeEmail && score > 0 && status !== 'invalid') score = Math.min(100, score + 3);
    
    // Phase 4: Pattern analysis penalty — only for unknown status
    if (totalRiskPenalty > 0 && score > 0 && status === 'unknown') {
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
