// --- Free / well-known webmail providers -> normalized "type" label ---
const FREE_PROVIDERS = {
  'gmail.com': 'Google',
  'googlemail.com': 'Google',
  'outlook.com': 'Microsoft',
  'hotmail.com': 'Microsoft',
  'hotmail.co.uk': 'Microsoft',
  'live.com': 'Microsoft',
  'msn.com': 'Microsoft',
  'yahoo.com': 'Yahoo',
  'yahoo.co.uk': 'Yahoo',
  'ymail.com': 'Yahoo',
  'rocketmail.com': 'Yahoo',
  'icloud.com': 'Apple',
  'me.com': 'Apple',
  'mac.com': 'Apple',
  'aol.com': 'AOL',
  'protonmail.com': 'ProtonMail',
  'proton.me': 'ProtonMail',
  'zoho.com': 'Zoho',
  'gmx.com': 'GMX',
  'gmx.net': 'GMX',
  'yandex.com': 'Yandex',
  'yandex.ru': 'Yandex',
  'mail.com': 'Mail.com',
  'qq.com': 'QQ',
  '163.com': 'NetEase',
};

// --- MX hostname patterns to identify the underlying mail provider ---
// Corporate domains using Google Workspace, Microsoft 365, etc.
const MX_PROVIDER_PATTERNS = [
  { pattern: /google\.com$/i,          provider: 'Google Workspace' },
  { pattern: /googlemail\.com$/i,      provider: 'Google Workspace' },
  { pattern: /outlook\.com$/i,         provider: 'Microsoft 365' },
  { pattern: /microsoft\.com$/i,       provider: 'Microsoft 365' },
  { pattern: /protection\.outlook\.com$/i, provider: 'Microsoft 365' },
  { pattern: /pphosted\.com$/i,        provider: 'Proofpoint' },
  { pattern: /mimecast\.com$/i,        provider: 'Mimecast' },
  { pattern: /barracuda\.com$/i,       provider: 'Barracuda' },
  { pattern: /messagelabs\.com$/i,     provider: 'Symantec' },
  { pattern: /yahoodns\.net$/i,        provider: 'Yahoo' },
  { pattern: /zoho\.com$/i,            provider: 'Zoho' },
  { pattern: /secureserver\.net$/i,    provider: 'GoDaddy' },
  { pattern: /emailsrvr\.com$/i,       provider: 'Rackspace' },
  { pattern: /mailgun\.org$/i,         provider: 'Mailgun' },
  { pattern: /sendgrid\.net$/i,        provider: 'SendGrid' },
  { pattern: /postmarkapp\.com$/i,     provider: 'Postmark' },
  { pattern: /firebasemail\.com$/i,    provider: 'Google Firebase' },
  { pattern: /amazonaws\.com$/i,       provider: 'Amazon SES' },
  { pattern: /ovh\.net$/i,             provider: 'OVH' },
  { pattern: /registrar-servers\.com$/i, provider: 'Namecheap' },
  { pattern: /titan\.email$/i,         provider: 'Titan' },
  { pattern: /privateemail\.com$/i,    provider: 'Namecheap Private' },
  { pattern: /forcepoint\.com$/i,      provider: 'Forcepoint' },
  { pattern: /protonmail\.ch$/i,       provider: 'ProtonMail' },
];

// --- Providers known to aggressively reject RCPT TO probes ---
// For these, a policy rejection does NOT mean the mailbox is invalid.
const ANTI_PROBE_PROVIDERS = new Set([
  'Google Workspace',
  'Microsoft 365',
  'Proofpoint',
  'Mimecast',
  'Barracuda',
  'Symantec',
  'Forcepoint',
  'Amazon SES',
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
]);

// --- Role-based local parts ---
const ROLE_LOCAL_PARTS = new Set([
  'admin', 'administrator', 'support', 'info', 'contact', 'sales',
  'help', 'billing', 'noreply', 'no-reply', 'postmaster', 'webmaster',
  'hostmaster', 'abuse', 'marketing', 'office', 'hr', 'careers',
  'team', 'feedback', 'press', 'media', 'security', 'compliance',
  'legal', 'ops', 'operations', 'devops', 'engineering',
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
  isDisposable,
  isRoleAccount,
  FREE_PROVIDERS,
  MX_PROVIDER_PATTERNS,
  ANTI_PROBE_PROVIDERS,
};
