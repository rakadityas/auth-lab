# Module 3 — Session Management, MFA & Account Recovery at Scale

> The "after you're logged in" playbook: keeping tens of millions of sessions
> straight, proving it's really you a second time, and getting you back in when
> you lose your key — all without opening a door for attackers.

**Time:** ~2h reading, ~2h lab, ~1h quiz.
**Prerequisites:** Modules 0–2. This module assumes you know sessions vs tokens,
the refresh-token grant, and JWT verification.

This is the module closest to the day-to-day work of an accounts/identity team.
It also contains the course's central design decision, written up as an ADR
(Architecture Decision Record) at the end — the exact artifact you'd produce in
the job.

### ELI5 — in simple words

You are already logged in. Now what?

- **Sessions at scale.** One server can remember you in its own memory. But big
  companies run hundreds of servers. If server #7 remembers you and your next
  click goes to server #23, you look like a stranger. Fix: all servers share one
  fast memory (Redis).
- **Refresh token rotation.** Your app has a long-life "renewal ticket" to get
  new short-life tickets. Every time it is used, we give a **new** one and destroy
  the old. So if a thief copies your ticket and tries to use it *after* you
  already used it, we see the same ticket used twice — that means somebody
  copied it. We then cancel **all** the tickets for that login. You must log in
  again (small annoyance), but the thief is locked out (big win).
- **MFA (second factor).** A password is *something you know*. It can be stolen.
  So we ask for a second, different thing: *something you have* (a phone showing
  a 6-digit code that changes every 30 seconds). Now a stolen password alone is
  not enough.
- **Account recovery.** This is the "I forgot my password" door. Attackers love
  this door because it is often weaker than the front door. If recovery is easy
  to abuse, your MFA is just decoration.

At the end you write an **ADR** — a short document that says "we chose design B,
here is why, and here is what it costs us." Being able to write and defend that
is a big part of the job.

---

## 1. Distributed session stores

At small scale a session lives in one server's memory. That dies the moment you
run two servers: a request routed to the other one has no session. The fixes, in
order of how much you'll regret them:

- **Sticky sessions** (load balancer pins a user to one server). Fragile: a deploy
  or a crash logs everyone on that node out, and it fights autoscaling. Avoid.
- **Shared session store** — a fast central store (Redis) all app servers read.
  This is the standard answer. The lab uses it.
- **Client-side/stateless** — put the state in a signed token (Module 2). No store
  to scale, but revocation becomes the problem (see the ADR).

### Why Redis specifically

- In-memory, sub-millisecond reads on the hot path of every authenticated request.
- Native **TTL** per key: sessions expire on their own, no cleanup job.
- Atomic primitives (`SETNX`, `INCR`, `SADD`, transactions) that map exactly onto
  session creation, throttling, and the session inventory.

At real scale you run Redis Cluster (sharded) or a managed equivalent, with
replicas per region. The data model in this lab is what runs there; only the
deployment topology changes.

### Two expirations, not one

- **Idle timeout** (sliding): the session dies after N minutes of inactivity. Each
  request refreshes the TTL.
- **Absolute lifetime** (hard cap): the session dies M hours after creation no
  matter how active. This bounds how long a stolen session can live.

Module 0's lab had only the sliding one — a deliberate gap. A real session needs
both. (Exercise 4 wires the absolute cap in.)

---

## 2. Refresh token rotation + reuse detection

This is the lab's headline implementation and a very common interview deep-dive.

**The problem.** Refresh tokens are long-lived and powerful — one mints access
tokens for hours or days. If one is stolen, you want to (a) limit the damage and
(b) *detect* the theft. A static refresh token gives you neither.

**Rotation.** Every time a client uses a refresh token, it gets a brand-new one
and the old one is immediately invalidated. Refresh tokens form a **chain** within
a **family** (all descendants of one login).

**Reuse detection — the clever part.** Because each token is single-use, a used
token should never appear again. If a *previously rotated* token is presented, two
parties hold the same token: the legitimate client and a thief. The server can't
tell which is which, so it **revokes the entire family**, forcing everyone back to
a fresh login.

```
login ──► RT1 ──rotate──► RT2 ──rotate──► RT3     (normal client, walking the chain)
            │
            └── thief also has RT1, replays it ──► REUSE DETECTED
                                                   └─► kill RT1, RT2, RT3, the whole family
```

Yes, this logs the *real* user out too. That is the correct trade: a forced
re-login is a minor annoyance; a thief silently minting tokens forever is an
account takeover. Say that out loud in a review — interviewers want to hear you
choose the conservative failure mode deliberately.

**Storage hygiene** (in the lab's [refresh.go](lab/refresh.go)): the client token
is `<id>.<secret>`, and Redis stores only a **hash** of the secret. A database dump
therefore doesn't hand an attacker working tokens — the same principle as password
storage, applied to tokens.

Run it:

```bash
cd 03-sessions-mfa-recovery/lab
podman compose up --build -d
./demo-refresh-reuse.sh
```

You'll watch a token rotate, then watch a replay of the old token revoke the whole
family.

---

## 3. Token revocation & distributed logout

"Log out" must mean the token stops working — everywhere, fast. How hard that is
depends entirely on your token design:

| Design | How you revoke | Revocation delay |
|---|---|---|
| Opaque token + server store | Delete the key | **Instant** |
| Signed JWT, no denylist | You can't, really | Until it expires |
| Signed JWT + denylist | Add `jti` to a denylist all validators check | Instant, but reintroduces shared state |
| Short-TTL JWT + long refresh | Revoke the refresh; access dies on its own | = access-token TTL |

Distributed twist: at multi-region scale, a revocation in one region must reach the
others. A denylist must replicate; an opaque-token store must be reachable (or
cached, and the cache TTL becomes your revocation delay). There is no design where
revocation is both instant *and* free — the ADR is about choosing which cost you pay.

---

## 4. MFA — the second factor

A factor is *something you know* (password), *something you have* (phone, security
key), or *something you are* (biometric). MFA requires two of different kinds.

Ranked worst to best in 2026:

| Method | Phishing-resistant? | Notes |
|---|---|---|
| **SMS OTP** | ❌ | SIM-swap, SS7 interception, deliverability/cost issues (see §7). A fallback, not a primary. |
| **TOTP** (authenticator app) | ❌ (code can be phished in real time) | No connectivity needed, cheap, no telecom. The lab implements this. |
| **Push** (approve on phone) | Partly (fatigue attacks exist — use number-matching) | Good UX; beware "MFA bombing". |
| **WebAuthn / Passkeys** | ✅ | The industry direction. Credentials are bound to the origin, so a phishing site literally cannot use them. |

### TOTP mechanics (RFC 6238), as built in [mfa.go](lab/mfa.go)

- A shared secret is generated at enrollment and shown as a QR code
  (`otpauth://` URI) for the authenticator app to scan.
- Every 30 s, both sides compute `HMAC-SHA1(secret, current_time_step)` and
  truncate to 6 digits. Nothing but those 6 digits crosses the wire per login.
- **Verification window (skew):** accept the adjacent time steps (±30 s) so a
  slightly wrong device clock still works.
- **Enroll-then-activate:** the secret isn't enforced until the user proves one
  valid code, so a botched enrollment can't lock them out.
- **Replay guard:** a 6-digit code is valid for up to ~90 s. A code captured by a
  phishing proxy could be reused in that window, so each accepted code is **burned**
  for its remaining validity. The lab demonstrates the second use being rejected.

### Why passkeys are the endgame (concept only in this lab)

WebAuthn uses public-key crypto bound to the website's origin. The private key
never leaves the device (often a secure enclave). Because the browser only releases
an assertion to the *exact* origin that registered it, a look-alike phishing domain
gets nothing — which defeats the attack TOTP and SMS can't. Building WebAuthn
requires browser APIs and an attestation flow beyond a headless lab, but you must
be able to explain *why* it's phishing-resistant and TOTP isn't.

---

## 5. Account recovery — the real front door for attackers

Your recovery flow is as strong as your weakest reset path. Attackers don't pick
the lock; they use the "forgot password" door.

- **Security questions are deprecated.** Mother's maiden name, first pet — all
  findable or guessable. Don't use them.
- **Standard flow:** rate-limited email (or SMS) with a **single-use,
  time-limited, high-entropy token**. The reset link expires fast (minutes to an
  hour) and dies on first use.
- **Don't leak existence:** the "we sent a reset link" response must be identical
  for real and unknown addresses (Module 0's enumeration lesson).
- **Invalidate sessions on password change** — otherwise resetting the password
  doesn't evict an attacker who already has a live session.
- **Recovery codes** for MFA: one-time, shown once, stored hashed. The lab issues
  ten at activation and enforces single use.
- **Notify on sensitive changes:** email the user when the password, email, or MFA
  settings change, so a takeover is at least visible.
- **Beware the recovery-MFA interaction:** if "forgot password" bypasses MFA, MFA
  is theatre. A password reset should still require the second factor (or step-up).

---

## 6. Step-up and re-authentication (`acr`, `amr`, `max_age`)

Covered mechanically in Module 2; here's the *when*. Not all actions deserve equal
trust:

- **Low stakes** (view profile): the existing session is fine.
- **Sensitive** (change email/password, add a payee, disable MFA): demand a fresh
  authentication even mid-session — `prompt=login` / `max_age=0`, and check
  `auth_time`.
- **High assurance** (large transfer): require a specific `acr` (e.g. MFA), and
  verify `amr` shows the method you demanded actually happened.

The mistake to avoid: authenticating strongly at login and then trusting that
forever. A session captured hours later shouldn't be able to change the recovery
email without re-proving identity.

---

## 7. Internationalisation & real-world grit

Auth systems serve real humans with messy data. Points that separate a toy from
production:

- **E.164 phone formatting** (`+60123456789`): store phone numbers canonically or
  you'll fail to match, mis-send OTPs, and double-count users.
- **SMS in Southeast Asia** (and generally): OTP SMS is *expensive*, deliverability
  is inconsistent across carriers, and delays are common — reasons to prefer TOTP /
  passkeys and treat SMS as a costly fallback. SIM-swap risk compounds it.
- **Unicode names & case-folding:** don't assume ASCII; don't uppercase naively
  (the Turkish dotless-i problem). Normalise carefully; store what the user typed.
- **Email normalisation:** decide a policy for case and for provider aliases
  (Gmail dots/`+tags`) and apply it **identically** at signup and login, or you
  create either duplicate accounts or an account-takeover bug. Being *consistent*
  matters more than which policy you pick.

---

## 8. THE ADR — stateful vs stateless tokens

This is the central design tension of an accounts role, and the deliverable that
demonstrates you can reason about it. Below is a worked example in the standard ADR
format. Read it, then redo it for your own assumed constraints — that's the
exercise.

---

### ADR-001: Access token strategy for the accounts platform

**Status:** Accepted (example) · **Date:** 2026-09-02 · **Deciders:** Identity team

**Context.**
We issue access tokens consumed by ~40 internal services across 3 regions, serving
an interactive web/mobile audience. Requirements, ranked:
1. A compromised or logged-out token must stop working quickly (target: ≤ 5 min).
2. Token validation must not add material latency to the request hot path.
3. The design must survive a regional outage of any single component.
4. Operable by a small team.

The two candidate designs:

- **Option A — Opaque access token + introspection.** Random token, state in
  Redis. Resource servers validate by calling an introspection endpoint
  (RFC 7662), with a short-lived local cache. *(This is what the lab implements.)*
- **Option B — Short-TTL signed JWT + refresh + denylist.** Access token is a
  ~5-min RS256 JWT validated locally via JWKS. Long-lived rotating refresh token.
  Optional `jti` denylist for pre-expiry revocation.

**Decision drivers & comparison.**

| Driver | A: Opaque + introspection | B: Short JWT + denylist |
|---|---|---|
| Revocation latency | **Instant** (delete the key) | = access TTL (~5 min), or instant *if* denylist is consulted |
| Hot-path validation | Network call, mitigated by cache | **Local**, signature only — fastest |
| Shared-state dependency | **Every request** needs the store (or cache) | Only refresh + denylist need it |
| Regional outage blast radius | Store/cache down → auth down (unless cached) | JWTs keep validating; only refresh/revocation degrade |
| Token size on the wire | Small | Larger (claims + signature) |
| Revealing data at rest | Nothing useful in the token | Claims readable (base64) — no secrets allowed |
| Operational complexity | Introspection service + cache | JWKS + key rotation + denylist replication |

**The crux.** Neither is free. Option A buys instant revocation at the cost of a
shared-state dependency on the hot path (softened, but not removed, by caching —
and the cache TTL then *becomes* a small revocation delay). Option B buys fast,
outage-resilient local validation at the cost of a revocation window equal to the
access-token TTL — unless you add a denylist, which drags back the shared state you
were trying to avoid, now on every request.

**Decision (for this example's constraints).**
**Option B — short-TTL JWT + rotating refresh token, *without* a per-request
denylist**, accepting a ≤ 5-minute revocation window for the access token, while
refresh-token **reuse detection** (built in this module) gives immediate,
guaranteed revocation of the long-lived credential. Rationale: driver 3 (outage
resilience) and driver 2 (latency) are weighted highest here, the 5-minute window
satisfies driver 1, and avoiding a per-request denylist satisfies driver 4. For
genuinely high-value operations we don't wait out the window — we require step-up
re-authentication at the point of action.

**Consequences.**
- (+) Fast, locally-validated hot path; survives Redis/region hiccups for reads.
- (+) Simple to operate; no introspection fleet.
- (−) Up to 5 minutes where a stolen *access* token still works. Mitigated by short
  TTL + step-up on sensitive actions + refresh reuse detection.
- (−) We own JWKS key rotation correctly (Module 2) — non-negotiable.
- If driver 1 tightened to "instant, no exceptions," we'd revisit toward Option A
  or add a denylist and accept its cost.

> **Note the lab implements Option A** (opaque + introspection) so you can *feel*
> instant revocation and the per-request lookup. The ADR then argues for B under a
> specific set of weights. Building one and arguing for the other on stated
> constraints is exactly the muscle this module trains — the "right" answer is
> whichever your constraints justify, defended explicitly.

---

## Lab

An account service combining refresh rotation, TOTP MFA, session inventory, and
opaque-token introspection.

### Start it

```bash
cd 03-sessions-mfa-recovery/lab
podman compose up --build -d
curl -s localhost:8080/healthz
```

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/signup` | create account |
| POST | `/login` | password step; returns tokens, or an `mfa_ticket` if MFA is on |
| POST | `/login/mfa` | second factor: `{ticket, code}` |
| POST | `/token/refresh` | rotate refresh → new access + new refresh |
| POST | `/introspect` | resource-server token check (RFC 7662) |
| GET | `/me` | requires `Authorization: Bearer` |
| POST | `/mfa/enroll` / `/mfa/activate` | TOTP setup |
| GET | `/sessions` | device/session inventory |
| POST | `/sessions/logout-all` | log out everywhere |

### Guided demos

```bash
./demo-refresh-reuse.sh    # rotation + the reuse kill switch (curl + jq)
./demo-mfa.sh              # TOTP enroll, 2-step login, replay guard  (needs oathtool)
```

`brew install oath-toolkit` for the MFA demo, or drive it from any authenticator
app using the `otpauth://` URL that `/mfa/enroll` returns.

### Exercises

1. **Reuse detection.** Run `demo-refresh-reuse.sh`. Then modify it: rotate three
   times, then replay the *middle* token. Confirm the whole family dies, not just
   the descendants. Explain why partial revocation would be unsafe.

2. **Instant revocation.** Log in, call `/me` (works), `/sessions/logout-all`,
   then `/me` again (401 immediately). Compare with what a plain JWT would do —
   there's no waiting for expiry here. This is Option A's whole selling point.

3. **Introspection cache = revocation delay.** The lab introspects live. Add a
   1-minute in-memory cache to `handleIntrospect`'s callers and observe that a
   revoked token now works for up to a minute. You just re-derived the ADR's
   central trade-off by hand.

4. **Absolute session lifetime.** The access record stores `CreatedAt` but only
   the sliding TTL is enforced. Add a hard cap: reject in `requireAccess` if
   `time.Since(rec.CreatedAt) > 12h`, regardless of TTL.

5. **`RevokeAllForUser`.** It's a stub. Implement it: maintain a `user→families`
   index in `RefreshStore.Issue`/`mint`, and revoke every family in
   `/sessions/logout-all`. Right now logout-all kills access tokens but leaves
   refresh families alive — a real bug. Fix it.

6. **MFA can't be bypassed by reset.** Sketch (or implement) a password-reset flow
   and ensure it still requires the second factor. Show why skipping MFA on reset
   makes MFA pointless.

7. **Step-up.** Add a `POST /account/email` endpoint that requires the token's
   session to be younger than 5 minutes (`CreatedAt`), returning 401 with
   `reauth_required` otherwise. This is step-up without a full IdP.

### Tear down

```bash
podman compose down -v
```

---

## Self-check quiz (10 questions)

<details>
<summary>1. Why are sticky sessions a poor scaling strategy?</summary>

They pin a user to one server, so a deploy, crash, or scale-in logs everyone on
that node out, and they fight autoscaling and even load distribution. Use a shared
store (Redis) or stateless tokens instead.
</details>

<details>
<summary>2. A rotated refresh token is presented again. What must happen and why?</summary>

Revoke the entire token family and force re-login. A reused single-use token means
two parties hold it — a theft — and the server can't distinguish victim from
attacker, so it fails conservatively toward a forced re-login over a silent
takeover.
</details>

<details>
<summary>3. Why store only a hash of the refresh token's secret?</summary>

So a database/Redis dump doesn't yield working tokens. Same principle as password
storage: never store the live credential, only something you can verify against.
</details>

<details>
<summary>4. Rank SMS OTP, TOTP, and passkeys by phishing resistance, with the reason.</summary>

Passkeys (WebAuthn) > TOTP > SMS. Passkeys are origin-bound public-key credentials
a phishing site can't use. TOTP and SMS both yield a code the user can be tricked
into relaying in real time; SMS additionally suffers SIM-swap and interception.
</details>

<details>
<summary>5. Why burn a TOTP code after one use?</summary>

A 6-digit code stays valid up to ~90 s with the skew window. Without single-use
enforcement, a code captured by a real-time phishing proxy could be replayed within
that window. Burning it closes the replay.
</details>

<details>
<summary>6. Why is enroll-then-activate the right MFA onboarding flow?</summary>

The secret isn't enforced until the user produces one valid code, proving it
transferred to their device. Otherwise a mistyped/failed enrollment could lock the
user out of their own account.
</details>

<details>
<summary>7. Give two revocation delays and the token design each implies.</summary>

Instant → opaque token + server store (delete the key), or JWT + denylist consulted
per request. Delay = access-token TTL → short-TTL JWT with no denylist (you wait for
expiry, or revoke the refresh token and let access die on its own).
</details>

<details>
<summary>8. Why must a password reset invalidate existing sessions?</summary>

Otherwise an attacker who already holds a live session keeps it after the victim
"recovers" the account — the reset evicts nobody. Kill all sessions (and refresh
families) on password change.
</details>

<details>
<summary>9. Why is inconsistent email normalisation a security bug, not just a UX one?</summary>

If signup and login normalise differently (case, Gmail dots/aliases), you can end
up with two records for one address or let one user's login resolve to another's
account — an account-takeover vector. Consistency across all flows matters more
than the specific policy.
</details>

<details>
<summary>10. State the opaque-vs-JWT trade-off in one sentence, then say what breaks it.</summary>

Opaque tokens give instant revocation at the cost of a shared-state lookup on every
request; short-TTL JWTs give fast, outage-resilient local validation at the cost of
a revocation window — and adding a per-request denylist to the JWT design drags the
shared-state cost back in, collapsing the distinction.
</details>

---

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [RFC 6238 — TOTP](https://datatracker.ietf.org/doc/html/rfc6238) ·
  [RFC 4226 — HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [RFC 6819 — OAuth Threat Model](https://datatracker.ietf.org/doc/html/rfc6819) ·
  [RFC 9700 §refresh tokens](https://datatracker.ietf.org/doc/html/rfc9700)
- [RFC 7009 — Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009) ·
  [RFC 7662 — Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) ·
  [FIDO Alliance — Passkeys](https://fidoalliance.org/passkeys/)
- [E.164 phone number format](https://en.wikipedia.org/wiki/E.164) — and Google's
  `libphonenumber` for real parsing
- [ADR format (Michael Nygard)](https://github.com/joelparkerhenderson/architecture-decision-record)

**Previous:** [Module 2 — OIDC, SAML & SSO](../02-oidc-saml-sso/README.md) ·
**Back to:** [Course home](../README.md)
