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
]);

// --- Role-based local parts ---
const ROLE_LOCAL_PARTS = new Set([
  'admin', 'administrator', 'support', 'info', 'contact', 'sales',
  'help', 'billing', 'noreply', 'no-reply', 'postmaster', 'webmaster',
  'hostmaster', 'abuse', 'marketing', 'office', 'hr', 'careers',
]);

function classifyProvider(domain) {
  const d = domain.toLowerCase();
  return FREE_PROVIDERS[d] || 'Custom/Business';
}

function isDisposable(domain) {
  return DISPOSABLE_DOMAINS.has(domain.toLowerCase());
}

function isRoleAccount(localPart) {
  return ROLE_LOCAL_PARTS.has(localPart.toLowerCase());
}

module.exports = { classifyProvider, isDisposable, isRoleAccount, FREE_PROVIDERS };
