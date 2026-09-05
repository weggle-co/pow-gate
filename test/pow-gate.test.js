'use strict';

/**
 * Tests for the properties that make this worth having: a token cannot be
 * forged, cannot be moved between flows, cannot be replayed, cannot be
 * backdated, and cannot be spent without doing the work.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const { createPowGate, createMemoryStore, normalisePurpose } = require('..');

const SECRET = 'a'.repeat(32);
/** Low difficulty so the suite stays fast; the property is the same at any level. */
const gate = () => createPowGate({ secret: SECRET, difficulty: 2 });

// ── the secret ──────────────────────────────────────────────────────────────

test('a gate cannot be built without a secret', () => {
  // A default secret in a library is a signing key every install shares.
  assert.throws(() => createPowGate({}), TypeError);
  assert.throws(() => createPowGate({ secret: '' }), TypeError);
  assert.throws(() => createPowGate({ secret: 'tooshort' }), TypeError);
  assert.throws(() => createPowGate({ secret: 12345678901234567890 }), TypeError);
});

test('an out-of-range difficulty is refused', () => {
  for (const d of [0, -1, 9, 1.5, 'five']) {
    assert.throws(() => createPowGate({ secret: SECRET, difficulty: d }), RangeError, `difficulty ${d}`);
  }
});

test('the token carries no secret', () => {
  const { token } = gate().issue('register');
  assert.ok(!token.includes(SECRET));
  // A random id, a base36 timestamp, a difficulty, a label, a 16-char tag.
  assert.equal(token.split('.').length, 5);
});

// ── the work actually has to be done ────────────────────────────────────────

test('a correct solution verifies', () => {
  const g = gate();
  const { token } = g.issue('register');
  const nonce = g.solve(token);
  const r = g.verify(token, nonce, { purpose: 'register' });
  assert.equal(r.ok, true);
  assert.equal(r.purpose, 'register');
});

test('a wrong nonce is refused', () => {
  const g = gate();
  const { token } = g.issue('register');
  const nonce = g.solve(token);
  assert.equal(g.verify(token, String(Number(nonce) + 1)).reason, 'proof of work failed');
  assert.equal(g.verify(token, '0').ok === true && nonce !== '0', false);
});

test('a missing nonce is refused', () => {
  const g = gate();
  const { token } = g.issue();
  for (const n of [null, undefined, '']) {
    assert.equal(g.verify(token, n).reason, 'missing fields');
  }
});

test('the difficulty in the token is what is enforced', () => {
  const easy = createPowGate({ secret: SECRET, difficulty: 1 });
  const hard = createPowGate({ secret: SECRET, difficulty: 4 });
  const { token } = hard.issue('x');
  // A nonce that satisfies 1 zero will almost never satisfy 4.
  const weak = easy.solve(easy.issue('x').token);
  assert.equal(hard.verify(token, weak).ok, false);
});

// ── forgery ─────────────────────────────────────────────────────────────────

test('a token signed with another key is refused', () => {
  const mine = gate();
  const theirs = createPowGate({ secret: 'b'.repeat(32), difficulty: 2 });
  const { token } = theirs.issue('register');
  const nonce = theirs.solve(token);
  assert.equal(mine.verify(token, nonce).reason, 'invalid signature');
});

test('editing any signed field invalidates the token', () => {
  const g = gate();
  const { token } = g.issue('register');
  const [rand, ts, diff, scope, sig] = token.split('.');

  const tampered = [
    [`${rand}.${ts}.${diff}.admin.${sig}`, 'purpose swapped'],
    [`${rand}.${ts}.1.${scope}.${sig}`, 'difficulty lowered'],
    [`${(BigInt('0x' + rand) + 1n).toString(16)}.${ts}.${diff}.${scope}.${sig}`, 'random id changed'],
    [`${rand}.${(Date.now() + 1).toString(36)}.${diff}.${scope}.${sig}`, 'timestamp moved'],
  ];
  for (const [bad, what] of tampered) {
    const nonce = g.solve(bad);
    assert.equal(g.verify(bad, nonce).reason, 'invalid signature', what);
  }
});

test('a malformed token is refused without throwing', () => {
  const g = gate();
  for (const bad of ['', 'nonsense', 'a.b.c', 'a.b.c.d.e.f', '....', null, undefined, 42, {}]) {
    const r = g.verify(bad, '1');
    assert.equal(r.ok, false, JSON.stringify(bad));
  }
});

// ── purpose binding ─────────────────────────────────────────────────────────

test('a challenge minted for one flow does not pay for another', () => {
  // This is the property that stops challenges harvested from an open
  // registration page being spent on a different guarded action.
  const g = gate();
  const { token } = g.issue('register');
  const nonce = g.solve(token);

  assert.equal(g.verify(token, nonce, { purpose: 'register' }).ok, true);
  assert.equal(g.verify(token, nonce, { purpose: 'password-reset' }).reason, 'wrong purpose');
});

test('the purpose is inside the hashed work, not only the check', () => {
  // So a caller who forgets to pass opts.purpose is still not transferring
  // solutions between flows: the nonce is bound to the whole token.
  const g = gate();
  const a = g.issue('register').token;
  const b = g.issue('register').token;
  const nonceA = g.solve(a);
  assert.equal(g.verify(b, nonceA).ok, false,
    'a solution for one token must not verify against another');
});

test('purposes are normalised to a safe label', () => {
  // The label sits in a dot-delimited signed payload, so a dot would move the
  // field boundaries.
  assert.equal(normalisePurpose('Register'), 'register');
  assert.equal(normalisePurpose('a.b.c'), 'abc');
  assert.equal(normalisePurpose('../../etc'), 'etc');
  assert.equal(normalisePurpose(''), 'default');
  assert.equal(normalisePurpose(null), 'default');
  assert.equal(normalisePurpose('!!!'), 'default');
});

test('a normalised purpose still matches its normalised form', () => {
  const g = gate();
  const { token } = g.issue('Password.Reset');
  const nonce = g.solve(token);
  assert.equal(g.verify(token, nonce, { purpose: 'PASSWORD.RESET' }).ok, true);
});

// ── replay ──────────────────────────────────────────────────────────────────

test('a solved challenge can only be spent once', () => {
  const g = gate();
  const { token } = g.issue('register');
  const nonce = g.solve(token);

  assert.equal(g.verifyAndConsume(token, nonce).ok, true);
  const second = g.verifyAndConsume(token, nonce);
  assert.equal(second.ok, false);
  assert.equal(second.reason, 'already used');
});

test('verify alone does not spend the token', () => {
  // The two are separate so a caller can check before committing to whatever
  // the challenge is guarding.
  const g = gate();
  const { token } = g.issue('register');
  const nonce = g.solve(token);
  assert.equal(g.verify(token, nonce).ok, true);
  assert.equal(g.verify(token, nonce).ok, true);
  assert.equal(g.consume(token), true, 'still unspent after two verifies');
});

test('an unverified token is never recorded by verifyAndConsume', () => {
  // Otherwise anyone could burn a challenge they had not solved, or fill the
  // store with arbitrary strings.
  const g = gate();
  const { token } = g.issue('register');
  g.verifyAndConsume(token, 'not-a-solution');
  assert.equal(g.store.has(token), false);

  const nonce = g.solve(token);
  assert.equal(g.verifyAndConsume(token, nonce).ok, true, 'the real solution still works');
});

// ── expiry and dwell ────────────────────────────────────────────────────────

test('an expired token is refused', () => {
  const g = createPowGate({ secret: SECRET, difficulty: 2, expiryMs: 1 });
  const { token } = g.issue('register');
  const nonce = g.solve(token);
  const deadline = Date.now() + 15;
  while (Date.now() < deadline) { /* let it lapse */ }
  assert.equal(g.verify(token, nonce).reason, 'expired');
});

test('dwell time is measured from the signed timestamp, not a client claim', () => {
  const g = createPowGate({ secret: SECRET, difficulty: 2, minAgeMs: 60_000 });
  const { token } = g.issue('register');
  const nonce = g.solve(token);
  const r = g.verify(token, nonce);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'too fast');
  assert.ok(r.age >= 0 && r.age < 60_000);
});

test('the dwell floor can be overridden per call', () => {
  const g = createPowGate({ secret: SECRET, difficulty: 2, minAgeMs: 60_000 });
  const { token } = g.issue('register');
  const nonce = g.solve(token);
  assert.equal(g.verify(token, nonce, { minAgeMs: 0 }).ok, true);
});

test('a token stamped in the future is refused', () => {
  const g = gate();
  const rand = crypto.randomBytes(16).toString('hex');
  const ts = (Date.now() + 10 * 60_000).toString(36);
  const payload = `${rand}.${ts}.2.register`;
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex').slice(0, 16);
  const token = `${payload}.${sig}`;
  const r = g.verify(token, g.solve(token));
  assert.equal(r.ok, false, 'a future timestamp must not pass as fresh');
});

test('age() reads the signed timestamp and is honest about garbage', () => {
  const g = gate();
  const { token } = g.issue('register');
  const a = g.age(token);
  assert.ok(a >= 0 && a < 5000);
  assert.equal(g.age('nonsense'), null);
  assert.equal(g.age(null), null);
});

// ── the optional attempt cap ────────────────────────────────────────────────

test('the rate limiter caps attempts per key', () => {
  const g = createPowGate({
    secret: SECRET, difficulty: 2,
    rateLimit: { max: 3, windowMs: 60_000 },
  });
  assert.equal(g.takeAttempt('1.2.3.4'), true);
  assert.equal(g.takeAttempt('1.2.3.4'), true);
  assert.equal(g.takeAttempt('1.2.3.4'), true);
  assert.equal(g.takeAttempt('1.2.3.4'), false, 'fourth attempt is over the cap');
  assert.equal(g.takeAttempt('5.6.7.8'), true, 'a different key is unaffected');
});

test('with no rateLimit configured, attempts are always allowed', () => {
  const g = gate();
  for (let i = 0; i < 100; i++) assert.equal(g.takeAttempt('1.2.3.4'), true);
});

// ── the store seam ──────────────────────────────────────────────────────────

test('a custom store is used instead of the built-in one', () => {
  const seen = [];
  const store = {
    add(token, expiresAt) { seen.push([token, expiresAt]); return true; },
    has() { return false; },
  };
  const g = createPowGate({ secret: SECRET, difficulty: 2, store });
  const { token } = g.issue('register');
  g.verifyAndConsume(token, g.solve(token));
  assert.equal(seen.length, 1);
  assert.equal(seen[0][0], token);
  assert.ok(seen[0][1] > Date.now());
});

test('a store that reports a duplicate makes the spend fail', () => {
  const g = createPowGate({
    secret: SECRET, difficulty: 2,
    store: { add: () => false, has: () => true },
  });
  const { token } = g.issue('register');
  assert.equal(g.verifyAndConsume(token, g.solve(token)).reason, 'already used');
});

test('the memory store prunes expired entries', () => {
  // add() prunes before it inserts, so the store stays bounded by the number
  // of challenges solved inside one expiry window rather than growing forever.
  const store = createMemoryStore();
  store.add('expired', Date.now() - 1);
  assert.equal(store.has('expired'), true, 'present until something prunes');

  store.add('live', Date.now() + 60_000);
  assert.equal(store.has('expired'), false, 'the expired entry is dropped on the next add');
  assert.equal(store.has('live'), true);
  assert.equal(store.size, 1);
  store.stop();
});

test('the memory store refuses a duplicate while it is still live', () => {
  const store = createMemoryStore();
  assert.equal(store.add('t', Date.now() + 60_000), true);
  assert.equal(store.add('t', Date.now() + 60_000), false);
  store.stop();
});

// ── issue() output ──────────────────────────────────────────────────────────

test('issue reports what the client needs to solve it', () => {
  const g = createPowGate({ secret: SECRET, difficulty: 3, expiryMs: 123456 });
  const c = g.issue('register');
  assert.equal(c.difficulty, 3);
  assert.equal(c.purpose, 'register');
  assert.equal(c.expiryMs, 123456);
  assert.equal(typeof c.token, 'string');
});

test('every challenge is unique', () => {
  const g = gate();
  const tokens = new Set(Array.from({ length: 200 }, () => g.issue('register').token));
  assert.equal(tokens.size, 200);
});

// ── a shared store, which answers asynchronously ────────────────────────────

/** Stands in for Redis SET NX: atomic, and it answers with a promise. */
function asyncStore() {
  const held = new Map();
  return {
    async add(token, expiresAt) {
      if (held.has(token)) return false;
      held.set(token, expiresAt);
      return true;
    },
    async has(token) { return held.has(token); },
    get size() { return held.size; },
  };
}

test('an async store still blocks a replay', async () => {
  const g = createPowGate({ secret: SECRET, difficulty: 2, store: asyncStore() });
  const { token } = g.issue('register');
  const nonce = g.solve(token);

  const first = await g.verifyAndConsume(token, nonce, { purpose: 'register' });
  assert.equal(first.ok, true);

  // The bug this guards: add() returns a promise, and a promise is truthy, so
  // a boolean test on it reports every replay as a fresh spend.
  const replay = await g.verifyAndConsume(token, nonce, { purpose: 'register' });
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, 'already used');
});

test('an async store does not swallow a failed verification', async () => {
  const g = createPowGate({ secret: SECRET, difficulty: 2, store: asyncStore() });
  const { token } = g.issue('register');
  // A wrong nonce must be refused before the store is ever asked, so this
  // result is plain rather than a promise.
  const result = g.verifyAndConsume(token, 'not-a-solution', { purpose: 'register' });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'proof of work failed');
});

test('a synchronous store stays synchronous', () => {
  // Callers written against the built-in store must not have to await, or the
  // replay check would silently pass for every one of them.
  const g = gate();
  const { token } = g.issue('register');
  const nonce = g.solve(token);

  const first = g.verifyAndConsume(token, nonce, { purpose: 'register' });
  assert.equal(first.ok, true, 'a sync store must return a plain result');
  assert.equal(g.verifyAndConsume(token, nonce, { purpose: 'register' }).reason, 'already used');
});

test('consume reports a duplicate through an async store too', async () => {
  const g = createPowGate({ secret: SECRET, difficulty: 2, store: asyncStore() });
  const { token } = g.issue('register');
  assert.equal(await g.consume(token), true);
  assert.equal(await g.consume(token), false);
});
