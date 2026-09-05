# pow-gate

Purpose-bound, single-use proof-of-work challenges with a server-measured dwell time.

No dependencies. Node 18+.

```bash
npm install @weggle-co/pow-gate
```

## What it is for

You have a form that costs you something when a bot submits it — a registration, a password reset, a contact form, an invite request. You do not want a third-party CAPTCHA on it.

Proof of work makes each submission cost the *client* a fixed amount of CPU. It does not stop a determined attacker; nothing does. It changes the economics: a bot doing 100 registrations an hour has to spend real compute per attempt instead of firing requests for free.

This is small on purpose. It issues a token, checks a solution, and refuses to let the same solution be used twice.

## Quick start

```js
const { createPowGate } = require('@weggle-co/pow-gate');

const gate = createPowGate({
  secret: process.env.POW_SECRET,   // required, 16+ chars
  difficulty: 5,                    // leading hex zeros, 1-8
  minAgeMs: 1500,                   // reject forms submitted faster than this
});

// When you render the form:
app.get('/register', (req, res) => {
  const challenge = gate.issue('register');
  res.render('register', { challenge });   // put challenge.token in a hidden field
});

// When it comes back:
app.post('/register', (req, res) => {
  const result = gate.verifyAndConsume(req.body.powToken, req.body.powNonce, {
    purpose: 'register',
  });
  if (!result.ok) return res.status(400).send(`Rejected: ${result.reason}`);

  // ...create the account
});
```

Client side, in a worker so the page stays responsive:

```js
async function solve(token, difficulty) {
  const target = '0'.repeat(difficulty);
  for (let nonce = 0; ; nonce++) {
    const bytes = new TextEncoder().encode(token + nonce);
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    const hex = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
    if (hex.startsWith(target)) return String(nonce);
  }
}
```

Difficulty 5 is roughly 0.3–0.8s on current hardware. Measure on the slowest device you care about before raising it — the cost lands on real users too.

## The four properties

Most homegrown PoW gates get the hashing right and miss at least two of these.

**Purpose binding.** A token records the flow it was minted for, inside the signature *and* inside the hashed work. A challenge harvested from your open registration page cannot be spent on password reset. Add a new guarded flow later and it does not inherit a supply of pre-solved challenges.

```js
const { token } = gate.issue('register');
gate.verify(token, nonce, { purpose: 'password-reset' });  // → { ok: false, reason: 'wrong purpose' }
```

**Single use.** The token is stateless — an HMAC, no server storage — which is what makes it usable from a handler with no database. That is also the catch: a signature that verifies once verifies for the whole expiry window. Without a record of what has been spent, one solved challenge pays for unlimited submissions until it expires. `consume` keeps that record.

```js
gate.verifyAndConsume(token, nonce);   // → { ok: true }
gate.verifyAndConsume(token, nonce);   // → { ok: false, reason: 'already used' }
```

**Server-measured dwell.** The usual way to check "was this form open long enough" is a hidden field holding the page's load time. The client picks that value, so it is a claim the submitter makes about itself — subtract three seconds and the check passes. Here the issue time is inside the signed token, so the only way to make a form look old is for it actually to be old.

**No default secret.** `createPowGate` throws without one. A fallback secret in a library is a signing key every install shares, and anyone who has read the source can forge tokens for all of them.

## API

### `createPowGate(options)`

| Option | Default | Meaning |
|---|---|---|
| `secret` | **required** | HMAC key, 16+ characters |
| `difficulty` | `5` | leading hex zeros required (1–8) |
| `expiryMs` | `600000` | token lifetime (10 minutes) |
| `minAgeMs` | `0` | reject a token solved faster than this |
| `store` | in-process | spent-token store (see below) |
| `rateLimit` | `null` | `{ max, windowMs }` for the optional per-key attempt cap |

### Methods

| Method | Returns |
|---|---|
| `issue(purpose)` | `{ token, difficulty, purpose, expiryMs }` |
| `verify(token, nonce, opts)` | `{ ok, reason?, issuedAt?, age?, purpose?, difficulty? }` — does **not** spend the token |
| `consume(token)` | `boolean` — `false` if already spent (a promise, if the store is async) |
| `verifyAndConsume(token, nonce, opts)` | verify then consume; what a handler usually wants (a promise, if the store is async) |
| `age(token)` | ms since issue, or `null` |
| `solve(token)` | a valid nonce — for tests and server-side clients |
| `takeAttempt(key)` | `boolean` — the optional attempt cap |

`opts` accepts `purpose` and `minAgeMs` (overriding the gate default).

Rejection reasons: `missing fields`, `malformed token`, `invalid signature`, `wrong purpose`, `expired`, `too fast`, `invalid difficulty`, `proof of work failed`, `already used`.

Call `verify` before `consume` — never record a token that has not verified, or anyone can burn a challenge they did not solve and fill the store with arbitrary strings.

## Running more than one instance

The default store is an in-process `Map`. It is bounded (a token is only recorded once its proof verified, and entries are pruned at expiry) but it is **per process**. Behind a load balancer, a solved challenge can be spent once per instance.

Pass a shared store — anything with `add(token, expiresAt) → boolean` and `has(token) → boolean`, where `add` returns `false` if the token was already present. Either method may return a promise:

```js
const gate = createPowGate({
  secret: process.env.POW_SECRET,
  store: {
    async add(token, expiresAt) {
      const ttl = Math.ceil((expiresAt - Date.now()) / 1000);
      return (await redis.set(`pow:${token}`, '1', 'NX', 'EX', ttl)) === 'OK';
    },
    async has(token) { return (await redis.exists(`pow:${token}`)) === 1; },
  },
});
```

Redis `SET NX` is exactly the right primitive: it is atomic, so two instances racing on the same token cannot both win.

**Await the result when your store is asynchronous.** `verifyAndConsume` and `consume` answer in whatever form the store does — a plain value for the built-in store, a promise for one backed by a network call. Awaiting is safe in both cases, so a handler that always awaits works with either store:

```js
app.post('/register', async (req, res) => {
  const result = await gate.verifyAndConsume(req.body.powToken, req.body.powNonce, {
    purpose: 'register',
  });
  if (!result.ok) return res.status(400).send(`Rejected: ${result.reason}`);
  // ...create the account
});
```

Forgetting the `await` here is the one mistake worth guarding against: a promise is always truthy, so the replay check would pass every time and the single-use property would be lost without any error.

The same applies to `rateLimit`, which is also per-process. If you need a shared attempt cap, use your existing rate limiter rather than this one.

## What this is not

- **Not a CAPTCHA.** It costs CPU, not human attention. Someone willing to spend compute gets through.
- **Not a rate limiter.** The built-in `rateLimit` is a convenience for the per-IP case; it does not replace a proper limiter in front of your app.
- **Not abuse detection.** It says a client did some work. It says nothing about who they are or what they intend.

Use it as one layer. It pairs well with a request rate limit and ordinary server-side validation.

## Tests

```bash
npm test
```

34 tests, written against the properties rather than the happy path: tokens signed with another key, every signed field tampered with in turn, solutions moved between flows, replays, expiry, future timestamps, malformed input, and the store seam — synchronous and asynchronous alike.

## License

MIT
