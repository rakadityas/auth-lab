# Module 11 — Delivered OTPs, Magic Links & Passwordless Login

You already built **TOTP** in [Module 3](../03-sessions-mfa-recovery/README.md).
This module is about the *other* one-time passcode — the kind your server invents
and **sends**: the 6-digit code in an SMS, the code in an email, the "sign in with
a link" button. It is the most-used authentication factor on earth and the one
engineers most often ship wrong, because it looks trivial and isn't.

> **Where this sits:** conceptually this follows Module 3 (it is the other half of
> "second factors") and leans on Module 8 (risk) and Module 9 (notifications). It
> is numbered 11 because it was added after the original course; do it any time
> after Module 3.

### ELI5 — in simple words

TOTP is like you and the bank both owning the same magic clock: you each look at
your own clock and read the same number, and the number never travels anywhere.

A delivered OTP is different. The bank picks a random number, writes it on a
postcard, and mails it to your house. That means:

- **Anyone who can read your mail can log in.** The postcard is the whole secret.
- **The postcard must self-destruct fast**, because it sits in a mailbox.
- **The number is short** (people have to retype it), so a thief could just *guess*
  numbers until one works — unless you only let them guess a few times.
- **Mailing costs money.** A jerk can make you mail ten thousand postcards to
  strangers, and you pay for every one.

Those four sentences are the entire module. Everything below is how to hold each
one down in code.

---

## 1. Delivered OTP is not TOTP

| | TOTP (Module 3) | Delivered OTP (this module) |
|---|---|---|
| Where the secret lives | Shared secret on both devices | Server invents it per attempt |
| Does it travel? | **No** — both sides compute it | **Yes** — over email/SMS, a channel you don't control |
| Attacker needs | The enrolled device / the secret | Access to the inbox or the phone number |
| Guessable? | Yes but pointless (30s window, same 10⁶) | Yes — this is a live attack class |
| Costs money to use? | No | **Yes**, per send |
| Works without connectivity? | Yes | No |
| Common failure | Clock drift, lost device | Brute force, bombing, toll fraud, SIM swap |

The single biggest conceptual mistake is treating a delivered OTP as "TOTP but by
SMS". The threat model is *not* the same, and neither is the code you write.

### Where delivered OTP is legitimately the right tool

Practitioners like to dismiss SMS OTP entirely. That's too glib — know the honest
case for it:

- **Phone number *is* the account identity** (ride-hailing, delivery, messaging
  apps across most of Asia, LatAm, Africa). There is no password to fall back to.
- **Reach.** It works on a feature phone, with no app install, no biometrics, no
  browser support question. For a consumer product in an emerging market this
  routinely beats every "better" factor on completion rate.
- **Bootstrapping.** Something has to authenticate the very first login on a new
  device before a passkey exists.

The engineering position to hold in a design review is not "never use SMS", it's:
**SMS OTP as a primary factor is a deliberate reach-vs-security trade, it must
never be a silent downgrade path around a stronger factor, and it must be built
with the four controls in §3.**

---

## 2. The threat model, concretely

**a. Brute force.** A 6-digit code is 10⁶ possibilities. That sounds like a lot
until you notice HTTP is fast. The lab measures it: one serial `curl` loop manages
~80 guesses/second; a few hundred parallel connections cover half the space inside
the code's own 5-minute lifetime. **Code length is not the control** — adding two
digits buys 100×, and an attacker buys 100× connections for pocket change.

**b. Enumeration.** In a passwordless system the identifier list *is* the user
list. If `/otp/start` answers differently (status, body, or latency) for a known
vs unknown address, you have shipped an account-enumeration API on your front door.

**c. OTP bombing (SMS/email flooding).** Many sources, one victim. The attacker
never guesses anything — the *harassment is the attack*, and its real purpose is
usually MFA fatigue: bury the victim until they approve something to make it stop.

**d. Toll fraud / SMS pumping (revenue-share fraud).** One source, many victim
numbers — numbers on a premium range the fraudster gets a cut of. They are not
attacking an account at all. They are using your signup form as a money pump, and
you find out on the telecom invoice. This has cost individual companies millions.

**e. SIM swap and SS7.** The phone number is not a cryptographic identity; it is a
customer-service decision at a carrier. Someone who social-engineers a port-out
receives every code you send.

**f. Real-time phishing relay.** A proxy site asks the victim for the code and
replays it within its 5-minute life. **OTPs of every kind are phishable** —
including TOTP. Only origin-bound credentials (passkeys, Module 6) are not.

**g. Leakage in the datastore.** See §4 — hashing a 6-digit code the way you'd hash
a password does approximately nothing.

---

## 3. The four controls, and what each one actually stops

Implemented in [otp.go](lab/otp.go):

| Control | Stops | The subtle part |
|---|---|---|
| **Attempt cap + burn** (5, then delete the request) | brute force (a) | Count the attempt **before** comparing, and destroy the request on overflow rather than rejecting one guess — otherwise the attacker keeps the request alive and keeps drawing. |
| **Short TTL + single use** | replay, forwarded/stale codes | Spend the code on the *first successful* verify, not at session end. |
| **Send quotas — per identifier AND per source** | bombing (c) and toll fraud (d) | These are two different attacks and each quota only catches one. Rotating IPs walks straight through a per-IP limit; fresh victim numbers walk straight through a per-identifier limit. You need both. |
| **Uniform responses** | enumeration (b) | Same status, same body, same shape — including the *rejections*. A 403 for "this number is rate-limited" is itself an oracle. |

### Resend is a security decision, not a UX detail

Users tap "resend". If a resend leaves the previous code valid, four taps means
four live codes and you have quadrupled the attacker's guessing surface for free.
The lab's `Resend` **overwrites** the stored digest — one live code per request,
always — and resets the attempt counter with it (which is also why the resend
itself must be quota'd and cooloff-throttled, or resetting attempts becomes the
brute-forcer's escape hatch).

---

## 4. Storing an OTP: why "just hash it" is wrong

Reflex says *hash it like a password*. Watch what that buys you:

```
SHA-256 of a 6-digit code. Attacker steals the datastore.
They enumerate all 1,000,000 inputs and match. Cost: microseconds.
```

Password hashing works because passwords have enough entropy that a slow KDF makes
the search infeasible. A 6-digit code has ~20 bits. **No hash function fixes 20
bits of entropy.** What fixes it is a key the attacker doesn't have:

```go
// otp.go — HMAC-SHA256 under a server-side pepper, over requestID || code
func (s *OTPStore) digest(requestID, code string) string {
	m := hmac.New(sha256.New, s.pepper)   // pepper lives outside the datastore
	m.Write([]byte(requestID))            // binds the code to ONE request
	m.Write([]byte{0})
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}
```

Two properties, both load-bearing:

1. **Keyed** — the pepper is held in the app's config/KMS ([Module 10](../10-key-management/README.md)),
   not in Redis. A datastore leak alone yields nothing enumerable.
2. **Request-bound** — the code mailed for request A cannot be spent on request B.
   Without this, an attacker with a concurrently-open request for their *own*
   identifier can try the victim's code against their own request.

And compare in constant time (`hmac.Equal`). A byte-wise comparison that returns
early leaks how many leading digits matched, which collapses 10⁶ into 10×6.

### Generate with a CSPRNG

`math/rand` here is not a nitpick — it's a one-guess attack. Observe a handful of
codes, recover the seed, predict every future code. Use `crypto/rand` (the lab
draws uniformly with `rand.Int`, which also avoids the modulo bias you'd get from
`rand.Int63() % 1000000`).

---

## 5. Magic links: the same primitive with the entropy fixed

A magic link is an OTP the user doesn't have to retype — so it can carry 256 bits
instead of 20. That removes brute force *entirely*: no attempt cap needed, and a
plain SHA-256 at rest is sufficient (256 bits is not enumerable).

What it does **not** remove, and what [magic.go](lab/magic.go) addresses:

- **Email is still the channel.** Inbox compromise is account compromise. Magic
  links make email your single point of failure, loudly.
- **Links get prefetched.** Corporate mail scanners, link-safety services, and
  chat clients fetch URLs to preview them. A link consumed on read is a link the
  user can never use. Mitigations: consume on a **POST** from a confirmation page,
  or accept the GET but require the same-browser cookie (below).
- **Links get forwarded**, and open in the wrong browser. The lab drops a random
  **`magic_nonce` cookie on the device that requested the link** and requires it
  back at redemption. A forwarded or intercepted link then doesn't log anyone in.
  (Real cost: request on your laptop, open mail on your phone → it fails. Many
  products therefore show a "confirm this login" page instead, or fall back to a
  code the user types into the original tab. Know the trade.)
- **Single use must be atomic.** Read-then-delete races. `DEL` returns the number
  of keys it actually removed, so the caller that gets `1` is the unique winner:

```go
if n, _ := m.rdb.Del(ctx, magicKey(tok)).Result(); n != 1 {
	return "", errNotFound // someone (or a scanner) redeemed it first
}
```

Same reasoning as the refresh-token rotation in Module 3: the winner is decided by
an atomic operation in the datastore, never by application logic.

---

## 6. Passwordless as a *system*, not a feature

Turning on email OTP login without thinking through the graph is how accounts get
taken over. Ask these in the design review:

- **Does the new factor bypass the old one?** If an account has TOTP enabled and
  "email me a code" logs in without it, you have built a password-strength
  bypass. Email OTP as a *recovery* path must be at least as strong as the factor
  it replaces — or must not exist.
- **Is the identifier verified and owned?** Passwordless makes the email/phone the
  credential. Address change must then be treated as a credential change:
  step-up, notify the old address, and cool off (Module 4).
- **What happens on identifier reuse?** Carriers recycle phone numbers, and
  companies recycle `@company.com` addresses after an employee leaves. Whoever
  gets the number next can log in. This is why phone numbers need a
  "last verified" timestamp and re-verification, not a one-time check.
- **Is a code request an authentication event?** Yes. Feed it to the risk engine
  (Module 8) and the audit log (Module 9). A spike of `/otp/start` for one
  identifier is a bombing incident; a spike across many is toll fraud.

### The pragmatic ladder

```
passkey  >  app push w/ number matching  >  TOTP  >  email OTP / magic link  >  SMS OTP
└─ unphishable ─┘                        └────────── phishable, still >> password alone ──────────┘
```

Ship the lower rungs where reach demands it, instrument them, and drive enrollment
up the ladder over time. "SMS or nothing" is a real choice a lot of the world makes.

### Grit you'll hit in production

- **Deliverability**, not security, is the top support driver: carrier filtering,
  aggregator outages, 30–90s delays. Budget for a second provider and failover.
- **Autofill.** iOS/Android parse `Your code is 123456` heuristically; the web has
  `autocomplete="one-time-code"` and the SMS **origin-bound one-time code** format
  (`@example.com #123456`), which ties the code to a domain and kills a whole
  class of phishing relay. Cheap, underused, worth naming in an interview.
- **Never put the code in the email *subject*** — it renders on lock screens and
  in notification previews.
- **Don't say "we've sent a code to j•••@gmail.com"** unless you've decided the
  partial disclosure is acceptable; it's an enumeration and recon leak.

---

## Lab

A passwordless account service: email/SMS OTP login, magic-link login, send
quotas, and a `MODE=unsafe` switch that turns the controls off so you can run the
attacks and watch them succeed.

### Start it

```bash
cd 11-otp-passwordless/lab
podman compose up --build        # add -d to background it
```

- App: <http://localhost:8080>
- **Mailpit** (the inbox — open this): <http://localhost:8025>
- SMS is a fake metered carrier: sends are logged and billed to `/metrics`.

Send quotas are hourly windows in Redis, so the bombing demo picks fresh
identifiers and a fresh attacker IP on every run; `podman compose down -v` clears
the counters entirely.

### Endpoints

| Method | Path | What it does |
|---|---|---|
| POST | `/otp/start` | `{identifier, channel}` → `{request_id}`; delivers a code |
| POST | `/otp/resend` | new code for the same request, old one invalidated |
| POST | `/otp/verify` | `{request_id, code}` → session |
| POST | `/magic/start` | emails a single-use link, sets the same-browser cookie |
| GET | `/magic/consume?token=` | redeems it once |
| GET | `/me` | who the bearer session belongs to |
| GET | `/metrics` | mode, SMS count, simulated telecom bill |

In `MODE=unsafe`, `/otp/start` additionally returns `code_leaked_for_demo` — the
plaintext code — so the attack demos can show you what they are searching for
without going to the inbox. A real attacker has no such field; it exists purely so
the brute-force run can prove it found the right answer.

`/metrics` deliberately does **not** report how much of your own send quota is
left: an endpoint that tells a caller their remaining budget is a probe for
locating the limit. That number belongs on your dashboard, not in the API.

### Guided demos

```bash
./demo-otp-login.sh        # happy path, code read from the real inbox, replay rejected
./demo-magic-link.sh       # link login, wrong-browser rejected, second click rejected
./demo-otp-bombing.sh      # both quota attacks + the bill
./demo-otp-bruteforce.sh   # 5 guesses and the request is burned

# now break it — controls off, code shrunk so the attack finishes while you watch
MODE=unsafe OTP_DIGITS=4 podman compose up -d --build
OTP_DIGITS=4 ./demo-otp-bruteforce.sh unsafe   # ~30s to guess the code
./demo-otp-bombing.sh                          # all 50 sends land
podman compose up -d --build                   # back to safe
```

### Exercises

1. **Feel the cap.** In safe mode, run `/otp/verify` six times with wrong codes.
   The sixth answer is different from the first five — explain precisely why
   burning the request beats rejecting the guess.
2. **Escape hatch.** Delete the cooloff/quota checks from `Resend` (leave the
   attempt reset). Now brute-force in safe mode by resending every 5 guesses.
   How many guesses per minute do you get? This is a real bug pattern.
3. **Rainbow the plaintext.** In unsafe mode, `podman exec -it lab-redis-1
   redis-cli KEYS 'otp:req:*'` and read a code straight out of the store. Then
   in safe mode do the same and confirm what you see is useless without the pepper.
4. **Break the request binding.** Remove `requestID` from `digest()`. Open two
   requests (yours and a victim's), then spend your code on their request. Explain
   what you just demonstrated.
5. **Timing.** Replace `hmac.Equal` with `==` on the raw code in unsafe mode and
   measure whether you can detect a leading-digit match over many requests. (Go's
   `==` on strings is length-then-memcmp; the point is to reason about *why* you
   don't want to have to think about that.)
6. **Enumeration audit.** Diff the full HTTP response — status, headers, body, and
   timing — for a known vs unknown identifier. Find anything that differs.
7. **Prefetch race.** Fetch a magic link twice concurrently (`curl ... & curl ... &`)
   and confirm exactly one wins. Then make `Consume` read-then-delete and race it
   again.
8. **Design.** Write the paragraph you'd put in an ADR arguing whether your product
   should offer email-OTP login *alongside* passwords. Cover the bypass question
   from §6.

### Tear down

```bash
podman compose down -v
```

---

## Self-check quiz

<details>
<summary>1. Why is SMS OTP a different threat model from TOTP, in one sentence?</summary>

TOTP is computed independently on both sides and never transmitted; a delivered
OTP is created by the server and sent over a channel the server doesn't control,
so it can be read, guessed, or made expensive to send.
</details>

<details>
<summary>2. You store OTPs as SHA-256 hashes. Is that adequate? Why not?</summary>

No. A 6-digit code has ~20 bits of entropy, so an attacker with the datastore
enumerates all 10⁶ hashes in microseconds. You need a **keyed** hash (HMAC under a
pepper stored outside the datastore) — no unkeyed hash function can compensate for
20 bits.
</details>

<details>
<summary>3. Which control actually stops OTP brute force, and why isn't it code length?</summary>

The attempt cap (plus burning the request). Length scales linearly against an
attacker who scales connections linearly and cheaply; two extra digits buys 100×,
which they buy back with 100 more connections. Five draws from 10⁶ is fixed no
matter what they buy.
</details>

<details>
<summary>4. Why must the attempt counter increment before the comparison?</summary>

Otherwise any early return on the error path — a panic, a timeout, a
misordered branch — hands the attacker a free, uncounted guess. Charge first,
compare second.
</details>

<details>
<summary>5. Distinguish OTP bombing from toll fraud, and name the quota that stops each.</summary>

Bombing: many sources → one victim number, to harass or induce MFA fatigue;
stopped by the **per-identifier** quota (rotating IPs defeats a per-IP limit).
Toll fraud: one source → many premium-rate numbers, to earn revenue share;
stopped by the **per-source** quota (fresh numbers defeat a per-identifier limit).
</details>

<details>
<summary>6. Why is "resend" a security-relevant endpoint?</summary>

If it leaves the old code valid it multiplies live codes; if it resets the attempt
counter without its own throttle it becomes the brute-forcer's way to buy
unlimited guesses. One live code per request, and quota the resend itself.
</details>

<details>
<summary>7. Magic links need no attempt cap. Why, and what do they need instead?</summary>

256 bits of entropy makes guessing infeasible, so there is nothing to cap. They
need atomic single-use consumption (prefetching scanners), binding to the
requesting device, a short TTL, and the acceptance that email compromise is now
total account compromise.
</details>

<details>
<summary>8. Why `DEL`-and-check-the-count rather than read-then-delete?</summary>

Read-then-delete has a race: two concurrent redemptions can both read a valid
token. `DEL` returns how many keys it removed, so exactly one caller sees `1` —
the datastore, not the application, picks the winner. Same pattern as refresh
rotation.
</details>

<details>
<summary>9. Your product has TOTP. You add "email me a code" for convenience. What did you break?</summary>

You may have created a bypass: an attacker with the email account skips TOTP
entirely, so the account's real strength dropped to the weakest enabled factor.
Alternative factors must be at least as strong as what they bypass, or be gated
behind the stronger factor rather than replacing it.
</details>

<details>
<summary>10. Are OTPs phishable? Which factor isn't, and why?</summary>

All of them are — SMS, email, and TOTP alike — because a proxy can ask the victim
for the code and relay it inside its lifetime. WebAuthn/passkeys aren't: the
signature is bound to the origin, so a credential produced for `evil.com` is
worthless at `bank.com`.
</details>

---

## References

- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — §5.1.3 out-of-band
  authenticators; the restricted-authenticator language on PSTN/SMS
- [RFC 4226 — HOTP](https://datatracker.ietf.org/doc/html/rfc4226) ·
  [RFC 6238 — TOTP](https://datatracker.ietf.org/doc/html/rfc6238) (contrast)
- [WHATWG — origin-bound one-time codes in SMS](https://wicg.github.io/sms-one-time-codes/)
- [OWASP — Forgot Password / Authentication cheat sheets](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP — Credential Stuffing & MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- Module [3](../03-sessions-mfa-recovery/README.md) (TOTP, recovery),
  [6](../06-passkeys-webauthn/README.md) (the unphishable endgame),
  [8](../08-abuse-risk/README.md) (risk scoring the send),
  [9](../09-audit-security-events/README.md) (notifying on it)
