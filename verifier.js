const { checkSyntax } = require('./lib/syntaxCheck');
const { resolveMailServers } = require('./lib/dnsLookup');
const { checkMailbox } = require('./lib/smtpProbe');
const { buildResult } = require('./lib/classify');

async function verifyEmail(rawEmail) {
  const syntax = checkSyntax(rawEmail);

  if (!syntax.valid) {
    return {
      email: rawEmail,
      domain: null,
      providerType: null,
      emailCategory: null,
      status: 'invalid',
      score: 0,
      activity: 'Inactive',
      flags: { disposable: false, roleBased: false, catchAll: false },
      reasonCode: syntax.reason,
    };
  }

  const { email, localPart, domain } = syntax;

  // Step 1: DNS resolution (with DoH fallback built in)
  const mxHosts = await resolveMailServers(domain);
  const hadMx = mxHosts.length > 0;

  if (!hadMx) {
    return buildResult({
      email, localPart, domain,
      smtpOutcome: { result: 'rejected' },
      isCatchAllDomain: false,
      hadMx: false,
    });
  }

  // Step 2: SMTP probe (real connection, no faking)
  const { smtpResult, isCatchAll } = await checkMailbox(mxHosts, domain, email);

  // NO MORE RANDOM FALLBACK.
  // If SMTP connection fails (port 25 blocked by ISP), the classifier
  // handles it properly — marking as "risky" with a 60 score instead of
  // randomly rolling a dice between valid/invalid/temp_fail.
  // This was the #1 cause of your email being falsely marked invalid.

  return buildResult({
    email,
    localPart,
    domain,
    smtpOutcome: smtpResult,
    isCatchAllDomain: isCatchAll,
    hadMx: true,
  });
}

module.exports = { verifyEmail };
