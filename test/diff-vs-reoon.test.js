const test = require('node:test');
const assert = require('node:assert');
const { canon, detectColumns } = require('../tools/diff-vs-reoon');

test('canon maps Reoon vocabulary to canonical buckets', () => {
    assert.equal(canon('Valid'), 'valid');
    assert.equal(canon('Safe'), 'valid');
    assert.equal(canon('Role'), 'valid');
    assert.equal(canon('Catch All'), 'catch_all');
    assert.equal(canon('Invalid'), 'invalid');
    assert.equal(canon('Disabled'), 'invalid');
    assert.equal(canon('Unknown'), 'unknown');
    assert.equal(canon('Disposable'), 'valid');
    assert.equal(canon('Inbox Full'), 'valid');
    assert.equal(canon('Spam Trap'), 'spamtrap');
});

test('canon maps TrueSendy vocabulary to canonical buckets', () => {
    assert.equal(canon('safe'), 'valid');
    assert.equal(canon('valid'), 'valid');
    assert.equal(canon('catch_all'), 'catch_all');
    assert.equal(canon('invalid'), 'invalid');
    assert.equal(canon('unknown'), 'unknown');
    assert.equal(canon(''), 'unknown');
    assert.equal(canon(undefined), 'unknown');
});

test('detectColumns finds email + status columns across CSV formats', () => {
    assert.equal(detectColumns(['email', 'status']).emailCol, 'email');
    assert.equal(detectColumns(['email', 'status']).statusCol, 'status');
    assert.equal(detectColumns(['Email', 'Verification_Status']).emailCol, 'Email');
    assert.equal(detectColumns(['Email', 'Verification_Status']).statusCol, 'Verification_Status');
    // Reoon-style: email + result
    assert.equal(detectColumns(['email', 'result']).statusCol, 'result');
});
