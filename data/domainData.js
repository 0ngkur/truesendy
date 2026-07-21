// --- Free / well-known webmail providers -> normalized "type" label ---
const FREE_PROVIDERS = {
  // Google
  'gmail.com': 'Google',
  'googlemail.com': 'Google',
  // Microsoft
  'outlook.com': 'Microsoft',
  'hotmail.com': 'Microsoft',
  'hotmail.co.uk': 'Microsoft',
  'hotmail.fr': 'Microsoft',
  'hotmail.de': 'Microsoft',
  'hotmail.es': 'Microsoft',
  'hotmail.it': 'Microsoft',
  'live.com': 'Microsoft',
  'live.co.uk': 'Microsoft',
  'live.fr': 'Microsoft',
  'msn.com': 'Microsoft',
  'passport.com': 'Microsoft',
  // Yahoo / AT&T (Yahoo infrastructure)
  'yahoo.com': 'Yahoo',
  'yahoo.co.uk': 'Yahoo',
  'yahoo.co.in': 'Yahoo',
  'yahoo.fr': 'Yahoo',
  'yahoo.de': 'Yahoo',
  'yahoo.es': 'Yahoo',
  'yahoo.it': 'Yahoo',
  'yahoo.ca': 'Yahoo',
  'yahoo.com.au': 'Yahoo',
  'ymail.com': 'Yahoo',
  'rocketmail.com': 'Yahoo',
  'att.net': 'Yahoo',       // AT&T uses Yahoo mail infrastructure
  'sbcglobal.net': 'Yahoo', // SBC Global uses Yahoo mail infrastructure
  'bellsouth.net': 'Yahoo',
  'ameritech.net': 'Yahoo',
  'pacbell.net': 'Yahoo',
  'swbell.net': 'Yahoo',
  // AOL / Verizon (AOL infrastructure)
  'aol.com': 'AOL',
  'aim.com': 'AOL',
  'verizon.net': 'AOL',   // Verizon uses AOL mail infrastructure
  'netscape.net': 'AOL',
  // Apple
  'icloud.com': 'Apple',
  'me.com': 'Apple',
  'mac.com': 'Apple',
  // ProtonMail
  'protonmail.com': 'ProtonMail',
  'proton.me': 'ProtonMail',
  'pm.me': 'ProtonMail',
  // Zoho
  'zoho.com': 'Zoho',
  'zohomail.com': 'Zoho',
  // GMX
  'gmx.com': 'GMX',
  'gmx.net': 'GMX',
  'gmx.de': 'GMX',
  'gmx.at': 'GMX',
  'gmx.ch': 'GMX',
  // Yandex
  'yandex.com': 'Yandex',
  'yandex.ru': 'Yandex',
  'ya.ru': 'Yandex',
  // Others
  'mail.com': 'Mail.com',
  'email.com': 'Mail.com',
  'qq.com': 'QQ',
  '163.com': 'NetEase',
  '126.com': 'NetEase',
  'foxmail.com': 'Tencent',
  'tutanota.com': 'Tutanota',
  'tuta.io': 'Tutanota',
  'fastmail.com': 'FastMail',
  'fastmail.fm': 'FastMail',
  'inbox.com': 'Inbox',
  'rediffmail.com': 'Rediff',
};

// --- MX hostname patterns to identify the underlying mail provider ---
// Corporate domains using Google Workspace, Microsoft 365, etc.
const MX_PROVIDER_PATTERNS = [
  { pattern: /google\.com$/i,              provider: 'Google Workspace' },
  { pattern: /googlemail\.com$/i,          provider: 'Google Workspace' },
  { pattern: /gmail-smtp-in\.l\.google\.com$/i, provider: 'Google Workspace' },
  { pattern: /aspmx\.l\.google\.com$/i,    provider: 'Google Workspace' },
  { pattern: /smtp\.google\.com$/i,        provider: 'Google Workspace' },
  { pattern: /alt\d?\.aspmx\.l\.google\.com$/i, provider: 'Google Workspace' },
  { pattern: /outlook\.com$/i,             provider: 'Microsoft 365' },
  { pattern: /microsoft\.com$/i,           provider: 'Microsoft 365' },
  { pattern: /protection\.outlook\.com$/i, provider: 'Microsoft 365' },
  { pattern: /mail\.protection\.outlook\.com$/i, provider: 'Microsoft 365' },
  { pattern: /pphosted\.com$/i,            provider: 'Proofpoint' },
  { pattern: /ppe-hosted\.com$/i,          provider: 'Proofpoint' },
  { pattern: /mimecast\.com$/i,            provider: 'Mimecast' },
  { pattern: /mimecast\.org$/i,            provider: 'Mimecast' },
  { pattern: /barracuda\.com$/i,           provider: 'Barracuda' },
  { pattern: /barracudanetworks\.com$/i,   provider: 'Barracuda' },
  { pattern: /messagelabs\.com$/i,         provider: 'MessageLabs' },
  { pattern: /symanteccloud\.com$/i,       provider: 'MessageLabs' },
  { pattern: /yahoodns\.net$/i,            provider: 'Yahoo' },
  { pattern: /am0\.yahoodns\.net$/i,       provider: 'Yahoo' },
  { pattern: /zoho\.com$/i,               provider: 'Zoho' },
  { pattern: /secureserver\.net$/i,        provider: 'GoDaddy' },
  { pattern: /emailsrvr\.com$/i,           provider: 'Rackspace' },
  { pattern: /mailgun\.org$/i,             provider: 'Mailgun' },
  { pattern: /sendgrid\.net$/i,            provider: 'SendGrid' },
  { pattern: /postmarkapp\.com$/i,         provider: 'Postmark' },
  { pattern: /firebasemail\.com$/i,        provider: 'Google Firebase' },
  { pattern: /amazonaws\.com$/i,           provider: 'Amazon SES' },
  { pattern: /ovh\.net$/i,                 provider: 'OVH' },
  { pattern: /registrar-servers\.com$/i,   provider: 'Namecheap' },
  { pattern: /titan\.email$/i,             provider: 'Titan' },
  { pattern: /privateemail\.com$/i,        provider: 'Namecheap Private' },
  { pattern: /forcepoint\.com$/i,          provider: 'Forcepoint' },
  { pattern: /protonmail\.ch$/i,           provider: 'ProtonMail' },
  { pattern: /ionos\.(com|co\.uk|de|fr|es|it)$/i, provider: 'IONOS' },
  { pattern: /hostinger\.com$/i,           provider: 'Hostinger' },
  { pattern: /mxroute\.com$/i,             provider: 'MXroute' },
  { pattern: /porkbun\.com$/i,             provider: 'Porkbun' },
  { pattern: /antispam\.mailspamprotection\.com$/i, provider: 'MailSpamProtection' },
  { pattern: /mailspamprotection\.com$/i,  provider: 'MailSpamProtection' },
  { pattern: /proofpoint\.com$/i,          provider: 'Proofpoint' },
  { pattern: /spamexperts\.com$/i,         provider: 'SpamExperts' },
  { pattern: /messagingengine\.com$/i,     provider: 'FastMail' },  // FastMail (newyorkjets.com etc)
  { pattern: /123-reg\.co\.uk$/i,          provider: 'Custom/Business' },
  { pattern: /aiso\.net$/i,               provider: 'Custom/Business' },
  { pattern: /weidner\.com$/i,             provider: 'Proofpoint' },
  { pattern: /udr\.com$/i,                provider: 'Proofpoint' },
  { pattern: /anterra\.com$/i,             provider: 'Mimecast' },
  { pattern: /cortland\.com$/i,            provider: 'Mimecast' },
  { pattern: /cortlandpartners\.com$/i,    provider: 'Mimecast' },
  { pattern: /ess\.barracudanetworks\.com$/i, provider: 'Barracuda' },
  { pattern: /spamfilter\.us$/i,           provider: 'Custom/Business' },
  // ── Additional providers (reduces false unknowns) ──
  { pattern: /trendmicro\.com$/i,          provider: 'TrendMicro' },
  { pattern: /trendmicro\.eu$/i,           provider: 'TrendMicro' },
  { pattern: /websitewelcome\.com$/i,      provider: 'HostGator' },
  { pattern: /hostgator\.com$/i,           provider: 'HostGator' },
  { pattern: /kundenserver\.de$/i,         provider: 'IONOS' },
  { pattern: /pair\.com$/i,                provider: 'Pair Networks' },
  { pattern: /dreamhost\.com$/i,           provider: 'DreamHost' },
  { pattern: /hover\.com$/i,               provider: 'Hover' },
  { pattern: /migadu\.com$/i,              provider: 'Migadu' },
  { pattern: /cloudflare\.net$/i,          provider: 'Cloudflare' },
  { pattern: /improvmx\.com$/i,            provider: 'ImprovMX' },
  { pattern: /mx\.cloudflare\.net$/i,      provider: 'Cloudflare' },
  { pattern: /forwardemail\.net$/i,        provider: 'ForwardEmail' },
  { pattern: /bluehost\.com$/i,            provider: 'Bluehost' },
  { pattern: /siteground\.com$/i,          provider: 'SiteGround' },
  { pattern: /inmotionhosting\.com$/i,     provider: 'InMotion' },
  { pattern: /a2hosting\.com$/i,           provider: 'A2Hosting' },
  { pattern: /netcorecloud\.net$/i,        provider: 'Netcore' },
  { pattern: /cisco\.com$/i,               provider: 'Cisco ESA' },
  { pattern: /iphmx\.com$/i,              provider: 'Cisco ESA' },
  { pattern: /sophos\.com$/i,              provider: 'Sophos' },
];

// --- Providers known to aggressively block SMTP probes (RCPT TO) ---
// For these, SMTP connection failure or policy rejection does NOT mean the mailbox is invalid.
// These providers protect their users by refusing external verification attempts.
// Reon/NeverBounce/ZeroBounce all treat these as "probably valid" (safe_to_send=true, score~75).
const ANTI_PROBE_PROVIDERS = new Set([
  'Google Workspace',
  'Microsoft 365',
  'Proofpoint',
  'Mimecast',
  'Barracuda',
  'Symantec',
  'Forcepoint',
  'Amazon SES',
  'SpamExperts',
  'MailSpamProtection',
  'FastMail',         // FastMail blocks external probes
  'MessageLabs',      // Broadcom/Symantec cloud gateway
  'GoDaddy',          // secureserver.net — blocks RCPT TO probes
  'Namecheap Private', // privateemail.com — blocks RCPT TO probes
  'TrendMicro',       // Trend Micro security gateway blocks probes
  'Cisco ESA',        // Cisco IronPort/ESA blocks probes
  'Sophos',           // Sophos email gateway blocks probes
]);

// --- Providers KNOWN to be catch-all (accept every RCPT TO) ---
// Confirmed from real-world data: these MX infrastructures always accept all addresses.
// Using domain-level heuristics here avoids needing an SMTP probe at all.
const KNOWN_CATCHALL_MX_PROVIDERS = new Set([
  'FastMail',          // in1-smtp.messagingengine.com — always catch-all
  'ImprovMX',          // improvmx.com — email forwarding, always accepts all
  'Cloudflare',        // Cloudflare Email Routing — forwards all mail
  'ForwardEmail',      // forwardemail.net — forwarding service, accepts all
]);

// --- Well-known large legitimate email providers (for scoring) ---
// These are domains where, if MX exists but SMTP is blocked, we assume deliverable.
const KNOWN_BIG_PROVIDER_DOMAINS = new Set([
  'gmail.com', 'googlemail.com',
  'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'live.com', 'msn.com',
  'yahoo.com', 'yahoo.co.uk', 'ymail.com', 'att.net', 'sbcglobal.net',
  'aol.com', 'verizon.net',
  'icloud.com', 'me.com', 'mac.com',
  'protonmail.com', 'proton.me',
]);

// --- Disposable / temporary email domains ---
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com',
  'tempmail.com',
  '10minutemail.com',
  'guerrillamail.com',
  'throwawaymail.com',
  'yopmail.com',
  'getnada.com',
  'trashmail.com',
  'fakeinbox.com',
  'sharklasers.com',
  'guerrillamail.info',
  'grr.la',
  'guerrillamail.net',
  'guerrillamail.de',
  'tmail.ws',
  'dispostable.com',
  'maildrop.cc',
  'temp-mail.org',
  'tempail.com',
  'mohmal.com',
  'emailondeck.com',
  'mintemail.com',
  'binka.me',
  'discard.email',
  'mailnesia.com',
  'harakirimail.com',
  'mailcatch.com',
  'meltmail.com',
  'spamgourmet.com',
  'mytemp.email',
  'tmpmail.net',
  'throwam.com',
  'burnermail.io',
  'us2.mx1.mailhostbox.com',  // mailhostbox is a known disposable provider
  'mailhostbox.com',
]);

// --- Role-based local parts ---
const ROLE_LOCAL_PARTS = new Set([
  'admin', 'administrator', 'support', 'info', 'contact', 'sales',
  'help', 'billing', 'noreply', 'no-reply', 'postmaster', 'webmaster',
  'hostmaster', 'abuse', 'marketing', 'office', 'hr', 'careers',
  'team', 'feedback', 'press', 'media', 'security', 'compliance',
  'legal', 'ops', 'operations', 'devops', 'engineering',
  'hello', 'enquiries', 'enquiry', 'accounts', 'accounts', 'invoice',
  'invoices', 'payments', 'billing', 'orders', 'order', 'shop',
  'newsletter', 'news', 'updates', 'notifications', 'alerts',
  'service', 'services', 'manager', 'management', 'director',
  'connect', 'welcome', 'reply', 'replies', 'bounce', 'bounces',
]);

function classifyProvider(domain) {
  const d = domain.toLowerCase();
  return FREE_PROVIDERS[d] || 'Custom/Business';
}

/**
 * Identify the mail infrastructure provider from MX hostnames.
 * This is crucial — a corporate domain using Google Workspace
 * should be treated like Google, not like an unknown server.
 */
function identifyMxProvider(mxHosts) {
  if (!mxHosts || mxHosts.length === 0) return null;

  for (const host of mxHosts) {
    const lower = host.toLowerCase();
    for (const { pattern, provider } of MX_PROVIDER_PATTERNS) {
      if (pattern.test(lower)) {
        return provider;
      }
    }
  }
  return null;
}

function isAntiProbeProvider(mxProvider) {
  return ANTI_PROBE_PROVIDERS.has(mxProvider);
}

/**
 * Is this MX provider known to accept ALL recipient addresses (catch-all)?
 * If true, we don't need an SMTP probe — we know it's catch-all.
 */
function isKnownCatchAllProvider(mxProvider) {
  return KNOWN_CATCHALL_MX_PROVIDERS.has(mxProvider);
}

/**
 * Is this a well-known big email provider domain?
 * Used as a secondary signal when MX provider can't be identified.
 */
function isKnownBigProvider(domain) {
  return KNOWN_BIG_PROVIDER_DOMAINS.has((domain || '').toLowerCase());
}

function isDisposable(domain) {
  return DISPOSABLE_DOMAINS.has(domain.toLowerCase());
}

function isRoleAccount(localPart) {
  return ROLE_LOCAL_PARTS.has(localPart.toLowerCase());
}

module.exports = {
  classifyProvider,
  identifyMxProvider,
  isAntiProbeProvider,
  isKnownCatchAllProvider,
  isKnownBigProvider,
  isDisposable,
  isRoleAccount,
  FREE_PROVIDERS,
  MX_PROVIDER_PATTERNS,
  ANTI_PROBE_PROVIDERS,
  KNOWN_CATCHALL_MX_PROVIDERS,
};
