'use strict';

const crypto = require('crypto');

/**
 * Purpose-bound, single-use proof-of-work challenges.
 *
 * The token is stateless — an HMAC over `random.issuedAt.difficulty.purpose` —
 * so any process can mint one and any process can check the signature. That is
 * what makes it usable from a request handler with no store behind it.
 *
 * It is also why `consume` exists. A signature that verifies once verifies for
 * the whole expiry window, so without a record of what has already been spent,
 * one solved challenge pays for unlimited submissions inside that window. The
 * work is meant to be per-submission, not per-window.
 */

const DEFAULT_PURPOSE = 'default';
const MIN_DIFFICULTY = 1;
const MAX_DIFFICULTY = 8;

/**
 * Purposes are short labels chosen by the caller, never by the request. Kept to
 * a conservative character set because the label sits inside a dot-delimited
 * signed payload — a purpose containing a dot would move the field boundaries.
 */
function normalisePurpose(purpose) {
  const s = String(purpose == null ? DEFAULT_PURPOSE : purpose)
    .toLowerCase().replace(/[^a-z0-9_-]/g, '');
  return s || DEFAULT_PURPOSE;
}

/**
 * The default spent-token store: an in-process Map.
 *
 * An entry only has to outlive the token that created it, and a token is dead
 * after `expiryMs`, so the map is bounded by the number of challenges actually
 * solved in one window — not by anything a caller can inflate, because a token
 * is only recorded once its proof has verified.
 *
 * It is per-process. If you run more than one instance behind a load balancer,
 * pass a shared `store` instead (see the README) or a solved challenge can be
 * spent once per instance.
 */
function createMemoryStore({ sweepMs = 5 * 60 * 1000 } = {}) {
  const spent = new Map();

  const prune = (now = Date.now()) => {
    for (const [token, expiry] of spent) if (expiry <= now) spent.delete(token);
  };

  const timer = setInterval(() => prune(), sweepMs);
  if (typeof timer.unref === 'function') timer.unref();

  return {
    /** @returns {boolean} false if this token had already been spent. */
    add(token, expiresAt) {
      const now = Date.now();
      prune(now);
      if (spent.has(token)) return false;
      spent.set(token, expiresAt);
      return true;
    },
    has(token) { return spent.has(token); },
    get size() { return spent.size; },
    clear() { spent.clear(); },
    stop() { clearInterval(timer); },
  };
}

/**
 * A fixed-window per-key counter, used for the optional attempt cap.
 * Keys are whatever the caller passes — usually a client IP.
 */
function createMemoryRateLimiter({ max, windowMs, sweepMs = 60 * 60 * 1000 } = {}) {
  const log = new Map();

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [key, times] of log) {
      const fresh = times.filter(t => now - t < windowMs);
      if (!fresh.length) log.delete(key); else log.set(key, fresh);
    }
  }, sweepMs);
  if (typeof timer.unref === 'function') timer.unref();

  return {
    /** @returns {boolean} true if the key is under its cap; records the hit. */
    take(key) {
      const now = Date.now();
      const prev = (log.get(key) || []).filter(t => now - t < windowMs);
      if (prev.length >= max) return false;
      prev.push(now);
      log.set(key, prev);
      return true;
    },
    peek(key) {
      const now = Date.now();
      return (log.get(key) || []).filter(t => now - t < windowMs).length;
    },
    clear() { log.clear(); },
    stop() { clearInterval(timer); },
  };
}

/**
 * Build a gate.
 *
 * @param {object} options
 * @param {string} options.secret          HMAC key. Required — there is no default.
 * @param {number} [options.difficulty=5]  leading hex zeros required (1-8)
 * @param {number} [options.expiryMs]      token lifetime, default 10 minutes
 * @param {number} [options.minAgeMs=0]    reject a token solved faster than this
 * @param {object} [options.store]         spent-token store, default in-process
 * @param {object} [options.rateLimit]     { max, windowMs } for the optional attempt cap
 */
function createPowGate(options = {}) {
  const {
    secret,
    difficulty = 5,
    expiryMs = 10 * 60 * 1000,
    minAgeMs = 0,
    store = createMemoryStore(),
    rateLimit = null,
  } = options;

  // No fallback. A default secret in a library is a signing key every install
  // shares, which makes every token forgeable by anyone who has read the source.
  if (typeof secret !== 'string' || secret.length < 16) {
    throw new TypeError('createPowGate requires a `secret` of at least 16 characters');
  }
  if (!Number.isInteger(difficulty) || difficulty < MIN_DIFFICULTY || difficulty > MAX_DIFFICULTY) {
    throw new RangeError(`difficulty must be an integer between ${MIN_DIFFICULTY} and ${MAX_DIFFICULTY}`);
  }

  const limiter = rateLimit
    ? createMemoryRateLimiter({ max: rateLimit.max, windowMs: rateLimit.windowMs })
    : null;

  const sign = (payload) =>
    crypto.createHmac('sha256', secret).update(payload).digest('hex').slice(0, 16);

  /**
   * Mint a challenge.
   *
   * The token is `rand.issuedAt.difficulty.purpose.sig`, signed over everything
   * before the signature. Two of those fields are what make it a *form*
   * challenge rather than only a unit of work:
   *
   *   · `purpose` binds the token to the flow it was minted for, so a challenge
   *     issued for one form is not spendable on another.
   *   · `issuedAt` is the server's clock, under the signature, which is what
   *     lets the dwell check be server-authoritative.
   *
   * Nothing secret is in the token: a random id, a timestamp, a difficulty and
   * a label. The key never leaves the process. So it is safe in a hidden field,
   * which is the point — the client has to carry it back.
   */
  function issue(purpose = DEFAULT_PURPOSE) {
    const rand = crypto.randomBytes(16).toString('hex');
    const ts = Date.now().toString(36);
    const scope = normalisePurpose(purpose);
    const payload = `${rand}.${ts}.${difficulty}.${scope}`;
    return { token: `${payload}.${sign(payload)}`, difficulty, purpose: scope, expiryMs };
  }

  /** How long ago this token was minted, in ms, or null if it cannot be read. */
  function age(token) {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 5) return null;
    const issuedAt = parseInt(parts[1], 36);
    return Number.isNaN(issuedAt) ? null : Date.now() - issuedAt;
  }

  /**
   * Check a solution. Does NOT mark the token spent — call `consume` for that,
   * and only after this has returned ok.
   *
   * @param {string} token
   * @param {string|number} nonce
   * @param {object} [opts]
   * @param {string} [opts.purpose]  the flow this token must have been minted for
   * @param {number} [opts.minAgeMs] override the gate's dwell floor
   */
  function verify(token, nonce, opts = {}) {
    if (!token || nonce == null || nonce === '') return { ok: false, reason: 'missing fields' };

    const parts = String(token).split('.');
    if (parts.length !== 5) return { ok: false, reason: 'malformed token' };

    const [rand, ts, diffStr, scope, sig] = parts;

    // Signature first. It covers the purpose and the timestamp as well as the
    // random part, so neither can be edited by whoever is holding the token.
    const expected = sign(`${rand}.${ts}.${diffStr}.${scope}`);
    const sigBuf = Buffer.from(String(sig));
    const expBuf = Buffer.from(expected);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return { ok: false, reason: 'invalid signature' };
    }

    // A token minted for another flow is not valid here, even though its
    // signature is perfectly good.
    const wanted = opts.purpose === undefined ? null : normalisePurpose(opts.purpose);
    if (wanted && scope !== wanted) return { ok: false, reason: 'wrong purpose' };

    const issuedAt = parseInt(ts, 36);
    if (Number.isNaN(issuedAt)) return { ok: false, reason: 'malformed token' };
    const tokenAge = Date.now() - issuedAt;
    if (tokenAge > expiryMs) return { ok: false, reason: 'expired' };
    // A token stamped in the future is not one we minted on this clock.
    if (tokenAge < -60_000) return { ok: false, reason: 'malformed token' };

    // Server-authoritative dwell. The age comes from issuedAt, which is under
    // the signature, so it cannot be backdated by the client the way a hidden
    // "page loaded at" field can.
    const floor = opts.minAgeMs === undefined ? minAgeMs : opts.minAgeMs;
    if (floor && tokenAge < floor) return { ok: false, reason: 'too fast', age: tokenAge };

    const diff = parseInt(diffStr, 10);
    if (Number.isNaN(diff) || diff < MIN_DIFFICULTY || diff > MAX_DIFFICULTY) {
      return { ok: false, reason: 'invalid difficulty' };
    }

    // The whole token is hashed, so the purpose field is inside the work too:
    // a solution is not transferable between flows even if a caller forgot to
    // pass opts.purpose.
    const hash = crypto.createHash('sha256').update(token + String(nonce)).digest('hex');
    if (!hash.startsWith('0'.repeat(diff))) return { ok: false, reason: 'proof of work failed' };

    return { ok: true, issuedAt, age: tokenAge, purpose: scope, difficulty: diff };
  }

  /**
   * Record a verified token as spent.
   *
   * Call only after `verify` has said ok. Recording an unverified token would
   * let anyone fill the store with strings, and would let them burn a challenge
   * they had not solved.
   *
   * @returns {boolean} false if this token had already been spent.
   */
  function consume(token) {
    return store.add(token, Date.now() + expiryMs);
  }

  /**
   * verify + consume, which is what a request handler almost always wants.
   */
  function verifyAndConsume(token, nonce, opts = {}) {
    const result = verify(token, nonce, opts);
    if (!result.ok) return result;
    if (!consume(token)) return { ok: false, reason: 'already used' };
    return result;
  }

  /** Optional per-key attempt cap. Returns true while the key is under its cap. */
  function takeAttempt(key) {
    if (!limiter) return true;
    return limiter.take(String(key == null ? '' : key));
  }

  /**
   * Solve a challenge. Provided for tests and for a server-side client; a real
   * browser client should do this in a worker so the page stays responsive.
   */
  function solve(token, { maxIterations = 50_000_000 } = {}) {
    const parts = String(token).split('.');
    const diff = parseInt(parts[2], 10);
    if (Number.isNaN(diff)) return null;
    const target = '0'.repeat(diff);
    for (let nonce = 0; nonce < maxIterations; nonce++) {
      const hash = crypto.createHash('sha256').update(token + nonce).digest('hex');
      if (hash.startsWith(target)) return String(nonce);
    }
    return null;
  }

  return {
    issue, verify, consume, verifyAndConsume, age, solve, takeAttempt,
    normalisePurpose,
    difficulty, expiryMs, minAgeMs,
    store, limiter,
  };
}

module.exports = {
  createPowGate,
  createMemoryStore,
  createMemoryRateLimiter,
  normalisePurpose,
  DEFAULT_PURPOSE,
};
