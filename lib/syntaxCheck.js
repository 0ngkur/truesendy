// Pragmatic RFC 5322-ish syntax check.
const EMAIL_REGEX =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

function checkSyntax(email) {
  if (typeof email !== 'string') {
    return { valid: false, reason: 'not_a_string' };
  }
  const trimmed = email.trim();

  if (trimmed.length === 0 || trimmed.length > 254) {
    return { valid: false, reason: 'invalid_length' };
  }
  if (!EMAIL_REGEX.test(trimmed)) {
    return { valid: false, reason: 'invalid_format' };
  }

  const [localPart, domain] = trimmed.split('@');
  if (localPart.length > 64) {
    return { valid: false, reason: 'local_part_too_long' };
  }
  if (trimmed.includes('..')) {
    return { valid: false, reason: 'consecutive_dots' };
  }

  return { valid: true, localPart, domain: domain.toLowerCase(), email: trimmed };
}

module.exports = { checkSyntax };
