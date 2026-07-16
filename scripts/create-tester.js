#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// Creates / refreshes the unrestricted tester account.
//   • Agency plan (all features unlocked — including bot downloads)
//   • Effectively-unlimited credits (1 billion)
//   • Generates an active API key for the bot/desktop app
//
// Usage:  node scripts/create-tester.js
// Run on the VPS:  cd /opt/truesendy && node scripts/create-tester.js
// ─────────────────────────────────────────────────────────────────────────────

const path = require('path');
const store = require(path.join(__dirname, '..', 'db', 'store'));

const TESTER_EMAIL    = 'tester@truesendy.com';
const TESTER_USERNAME = 'tester';
const TESTER_PASSWORD = 'Testing123!';
const UNLIMITED       = 1_000_000_000;   // 1 billion — effectively unlimited

(async () => {
    try {
        // 1. Find or create the tester user
        let user = store.findUserByEmail(TESTER_EMAIL);
        if (!user) {
            const result = await store.createUser(TESTER_EMAIL, TESTER_PASSWORD, TESTER_USERNAME);
            if (result.error) {
                console.error('✗ Could not create tester:', result.error);
                process.exit(1);
            }
            user = result.user;
            console.log('✓ Created tester account');
        } else {
            console.log('✓ Tester account already exists — refreshing');
        }

        // 2. Verify the email (skip OTP)
        store.verifyUser(TESTER_EMAIL);

        // 3. Upgrade to Agency plan (unlocks bot download + API keys)
        store.upgradePlan(user.id, 'agency');

        // 4. Grant effectively-unlimited credits
        store.grantTokens(user.id, UNLIMITED);

        // 5. Generate an API key (so the bot/desktop works immediately)
        //    generateApiKey revokes old keys first, so this always gives a fresh active key.
        const keyResult = store.generateApiKey(user.id);
        const apiKey = keyResult.error ? null : keyResult;
        if (keyResult.error) {
            console.log('⚠ Could not generate API key:', keyResult.error);
        } else {
            console.log('✓ Generated fresh API key');
        }

        // 6. Confirm
        const credits = store.getUserCredits(user.id);
        console.log('');
        console.log('═══════════════════════════════════════════════════════════');
        console.log('  ✅  TESTER ACCOUNT READY');
        console.log('═══════════════════════════════════════════════════════════');
        console.log('  Email:    ' + TESTER_EMAIL);
        console.log('  Password: ' + TESTER_PASSWORD);
        console.log('  Username: ' + TESTER_USERNAME);
        console.log('  Plan:     agency (all features unlocked)');
        console.log('  Credits:  ' + credits.toLocaleString() + ' (unlimited)');
        if (apiKey && apiKey.key) {
            console.log('  API Key:  ' + apiKey.key);
        }
        console.log('  Bot DL:   https://truesendy.com/downloads (login as tester)');
        console.log('═══════════════════════════════════════════════════════════');
        console.log('');
    } catch (err) {
        console.error('✗ Failed:', err.message);
        console.error(err.stack);
        process.exit(1);
    }
})();
