const test = require('node:test');
const assert = require('node:assert');
const { checkMailbox } = require('../lib/smtpProbe');

const noSleep = () => Promise.resolve();

/**
 * Scripted prober: routes outcomes by whether the probed address is the REAL
 * email (rcptTo === realEmail) or a FAKE catch-all probe address. Each list is
 * consumed in call order; running out returns connection_failed.
 */
function scriptedProber(realScript, fakeScript, realEmail) {
    const realQ = [...realScript];
    const fakeQ = [...fakeScript];
    return (mxHosts, mailFrom, rcptTo, heloDomain, timeoutMs) => {
        if (rcptTo === realEmail) {
            return Promise.resolve(realQ.shift() || { result: 'connection_failed' });
        }
        return Promise.resolve(fakeQ.shift() || { result: 'connection_failed' });
    };
}

// ── WS1: catch-all probe must be as resilient as the real probe ──────────────
// The real-email probe already retries on temp_fail (greylisting) and falls back
// to a domain sender on sender_rejected. The catch-all probe historically did
// neither, so catch-all domains that greylist probes were missed — the root cause
// of TrueSendy's catch-all under-detection vs Reoon.

test('fake catch-all probe retries on greylist (temp_fail) and detects catch-all', async () => {
    const email = 'someone@example.com';
    // Real probe accepted first try; fake probe greylists once then accepts.
    const prober = scriptedProber(
        [{ result: 'accepted', code: 250, responseText: 'ok' }],
        [
            { result: 'temp_fail', code: 450, responseText: 'try again later' },
            { result: 'accepted', code: 250, responseText: 'ok' },
        ],
        email
    );
    const { isCatchAll } = await checkMailbox(['mx.example.com'], 'example.com', email, { prober, sleep: noSleep });
    assert.equal(isCatchAll, true);
});

test('fake catch-all probe falls back to domain sender on sender_rejected', async () => {
    const email = 'someone@example.com';
    // Real probe accepted; fake null-sender rejected, then domain-sender accepted.
    const prober = scriptedProber(
        [{ result: 'accepted', code: 250, responseText: 'ok' }],
        [
            { result: 'sender_rejected', code: 550, responseText: 'sender blocked', rejectionType: 'sender_blocked' },
            { result: 'accepted', code: 250, responseText: 'ok' },
        ],
        email
    );
    const { isCatchAll } = await checkMailbox(['mx.example.com'], 'example.com', email, { prober, sleep: noSleep });
    assert.equal(isCatchAll, true);
});

test('fake catch-all probe that stays rejected is NOT catch-all', async () => {
    const email = 'someone@example.com';
    const prober = scriptedProber(
        [{ result: 'accepted', code: 250, responseText: 'ok' }],
        [{ result: 'rejected', code: 550, responseText: 'no such user', rejectionType: 'mailbox_not_found' }],
        email
    );
    const { isCatchAll } = await checkMailbox(['mx.example.com'], 'example.com', email, { prober, sleep: noSleep });
    assert.equal(isCatchAll, false);
});

// ── Regression guards: the real-email probe retry still works after refactor ──

test('real probe still retries on greylist (temp_fail) then accepts', async () => {
    const email = 'someone@example.com';
    const prober = scriptedProber(
        [
            { result: 'temp_fail', code: 450, responseText: 'greylisted' },
            { result: 'accepted', code: 250, responseText: 'ok' },
        ],
        [{ result: 'rejected', code: 550, responseText: 'no such user', rejectionType: 'mailbox_not_found' }],
        email
    );
    const { smtpResult, isCatchAll } = await checkMailbox(['mx.example.com'], 'example.com', email, { prober, sleep: noSleep });
    assert.equal(smtpResult.result, 'accepted');
    assert.equal(isCatchAll, false);
});

// ── WS2: per-domain cache lets us skip a known-not-catch-all domain's fake probe ─

test('skipCatchAll option suppresses the fake catch-all probe', async () => {
    const email = 'someone@example.com';
    let fakeCalls = 0;
    const prober = (mxHosts, mailFrom, rcptTo, heloDomain, timeoutMs) => {
        if (rcptTo !== email) fakeCalls++;     // count fake-address probes only
        return Promise.resolve({ result: 'accepted', code: 250, responseText: 'ok' });
    };
    const { isCatchAll } = await checkMailbox(['mx.example.com'], 'example.com', email, { prober, sleep: noSleep, skipCatchAll: true });
    assert.equal(fakeCalls, 0, 'fake probe must NOT be called when skipCatchAll is set');
    assert.equal(isCatchAll, false);
});
