# Module 0 — AuthN vs AuthZ Fundamentals

> Authentication is showing your ID at the door. Authorization is the bouncer
> checking whether that ID gets you into the VIP room.

Everything in later modules (OAuth, OIDC, SSO, MFA) is built on the ideas here.
If you only half-understand sessions and password storage, OAuth will feel like
magic instead of engineering. Do not skip this module.

**Time:** ~2h reading, ~2h lab, ~1h quiz.

---

## 1. AuthN vs AuthZ

| | Authentication (AuthN) | Authorization (AuthZ) |
|---|---|---|
| Question it answers | *Who are you?* | *What are you allowed to do?* |
| Happens | Once, at the start of a session | On **every** protected request |
| Typical output | A session ID or a token | An allow/deny decision |
| Failure code | `401 Unauthorized` (misnamed — it means unauthenticated) | `403 Forbidden` |
| Owned by | The identity provider / login service | The resource server / application |

The two HTTP status codes are named backwards from their meanings, and this trips
up everyone. Memorise it: **401 = I don't know who you are. 403 = I know exactly
who you are, and no.**

A third concept sits next to them and is worth naming early:

- **Identification** — the claim ("I am alice@example.com").
- **Authentication** — the proof (password, passkey, OTP).
- **Authorization** — the decision (alice may read invoice 42).
- **Accounting/Audit** — the record (alice read invoice 42 at 09:14 UTC).

Together: AAA. In interviews and design reviews, being precise about which layer
a bug lives in is half the value you add.

### Authorization models you will hear named

- **RBAC** (role-based): user → roles → permissions. Simple, coarse, ubiquitous.
- **ABAC** (attribute-based): decide from attributes (department, region, time of
  day, device posture). Flexible, harder to reason about.
- **ReBAC** (relationship-based): "can Alice edit doc X because she owns folder Y?"
  Google Zanzibar popularised this; OpenFGA and SpiceDB are open implementations.
- **Scopes vs permissions**: an OAuth scope limits what a *client application* may
  ask for. It does **not** grant the *user* anything. A token with
  `scope=invoices.write` for a user who is not an admin must still be denied.
  Scope is a ceiling, not a grant. This confusion causes real vulnerabilities.

---

## 2. Password storage

### The threat model

Assume your database will leak. Everything about password storage is designed for
the day after the breach: how long does it take an attacker with the dump to
recover plaintext passwords?

### Why plain SHA-256 is not enough

SHA-256 is designed to be **fast**. That is exactly wrong for passwords. A modern
GPU rig does on the order of 10^10 SHA-256 hashes per second. Every 8-character
lowercase-alphanumeric password falls in minutes.

Three separate defects, three separate fixes:

1. **Too fast.** → Use a *deliberately slow* function (bcrypt, scrypt, Argon2id).
2. **No salt.** Identical passwords produce identical hashes, so one crack breaks
   every account that shares it, and precomputed rainbow tables apply. → A unique
   random **salt** per password (bcrypt/Argon2 do this for you and store it in the
   hash string).
3. **GPU-friendly.** SHA-256 needs almost no memory, so attackers parallelise
   massively. → Use a **memory-hard** function (Argon2id, scrypt) that forces the
   attacker to buy RAM per parallel guess.

There is a fourth, optional layer: a **pepper** — a secret key held outside the
database (in a KMS/HSM), mixed into the hash. If the DB leaks but the KMS does not,
the hashes are useless. Argon2's `secret` parameter or an HMAC-before-hash gives
you this. The cost is key rotation complexity.

### What to actually use, in 2026

| Algorithm | Verdict | Baseline parameters (OWASP) |
|---|---|---|
| **Argon2id** | First choice | m=19 MiB, t=2, p=1 (or m=47 MiB, t=1, p=1) |
| **scrypt** | Fine if Argon2 unavailable | N=2^17, r=8, p=1 |
| **bcrypt** | Acceptable, everywhere, well understood | cost ≥ 10, target ≥ 12 |
| PBKDF2 | Only when FIPS compliance forces it | 600,000 iterations HMAC-SHA-256 |
| MD5 / SHA-1 / SHA-256 / SHA-512 alone | **Never** | — |

**bcrypt's famous trap:** it silently truncates input at **72 bytes**. If you
pre-hash to get around that, do it deliberately (`bcrypt(base64(sha256(pw)))`,
base64 because bcrypt also stops at the first NUL byte).

Tune parameters to your hardware: pick the highest cost where verification stays
under roughly 250–500 ms at your peak login rate. Then **re-tune yearly** — and
build the upgrade path *now*, because you can only re-hash a password at the
moment the user logs in and hands you the plaintext. See `needsRehash` in
[lab/password.go](lab/password.go).

### The PHC string format

```
$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
 └ algo   └ ver └ parameters      └ salt      └ derived key
```

Everything a verifier needs travels with the hash. That is what lets you raise
parameters without invalidating old hashes.

---

## 3. NIST SP 800-63B — the modern password policy

The 2017 revision (reaffirmed in the 2024/2025 updates) overturned twenty years
of received wisdom. Know these by heart; you will be asked to defend them against
a stakeholder who wants "at least one uppercase, one number and one symbol":

**Do:**
- Require a minimum of **8 characters**; 15+ for privileged accounts.
- Accept at least **64 characters**, all printable ASCII, Unicode, and spaces.
- Screen new passwords against a **breached-password list**.
- Allow paste (password managers depend on it).
- Offer a "show password" toggle.

**Do NOT:**
- Impose composition rules (upper/lower/digit/symbol). They push users to
  `Password1!` and measurably reduce entropy.
- Force periodic rotation. Rotate **only on evidence of compromise**. Forced
  90-day rotation produces `Summer2026!` → `Autumn2026!`.
- Use password hints or knowledge-based "security questions" (your mother's maiden
  name is on a public genealogy site).
- Truncate passwords silently.

### Breached-password checking without leaking the password

HaveIBeenPwned's Pwned Passwords **range API** uses *k-anonymity*:

1. Compute `SHA-1(password)` → e.g. `21BD1...C3D2E`.
2. Send only the **first 5 hex characters** (`21BD1`) to
   `https://api.pwnedpasswords.com/range/21BD1`.
3. Get back ~800 hash suffixes with breach counts.
4. Match the remaining 35 characters **locally**.

The service never sees the password, never sees the full hash, and cannot tell
which of the ~800 candidates you were asking about. Add the `Add-Padding: true`
header so the response size does not leak anything either. Implemented in
`isPwned` in [lab/main.go](lab/main.go).

SHA-1 is used here only as a lookup index against a public corpus — it is not
protecting anything. That is fine.

---

## 4. Sessions vs tokens — the central trade-off

This tension recurs in every module of this course, and it is the single design
question you are most likely to be asked to write down and defend.

### Server-side session + cookie (stateful)

```
POST /login  →  server mints random 256-bit ID
             →  stores {user, ip, created_at} in Redis under that ID
             →  Set-Cookie: sid=<random>; HttpOnly; Secure; SameSite=Lax
Every request →  cookie sent automatically → server looks up Redis
```

- The cookie value is an opaque **reference**. It carries no data.
- **Revocation is instant and total**: `DEL sess:<id>`.
- Requires a shared, fast, highly available store (Redis) and adds a network hop
  per request (~1 ms, and a cache in front removes most of it).
- Cross-domain use is awkward; cookies are bound to a domain.

### Self-contained token / JWT (stateless)

```
POST /login  →  server signs a JWT containing {sub, exp, scope, ...}
Every request →  Authorization: Bearer <jwt> → server verifies signature only
```

- The token is a **value**: it carries its own claims, verified by signature.
- No lookup needed → scales horizontally with zero shared state, works across
  domains and services, ideal for service-to-service and mobile.
- **Revocation is the problem.** A signed JWT is valid until it expires. To kill
  it early you need a denylist — which reintroduces the shared state you removed.
- Bigger (hundreds of bytes to a few KB, on every request) and the payload is
  **base64, not encrypted** — anyone holding it can read the claims.

### How mature systems resolve it

Short-lived access token (5–15 min, stateless, cheap to verify) **plus** a
long-lived refresh token (stateful, stored, rotated, revocable). You get stateless
verification on the hot path and real revocation on the cold path, at the cost of
a revocation window equal to the access-token lifetime. Whether that window is
acceptable is a business decision, not a technical one — write it down explicitly.

Module 3 builds exactly this and compares it against the alternative (opaque token
+ introspection endpoint + cache).

**A rule worth internalising:** for a first-party browser app, a plain
`HttpOnly` session cookie is usually the *better* choice, and "we used JWTs" is
often cargo cult. Reach for tokens when you have a genuine cross-service,
cross-domain, or third-party-client problem.

---

## 5. Cookie flags

```
Set-Cookie: sid=abc123; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1800
```

| Flag | What it does | Why it matters |
|---|---|---|
| `HttpOnly` | JavaScript cannot read the cookie | An XSS payload cannot exfiltrate the session |
| `Secure` | Only sent over HTTPS | Prevents plaintext interception |
| `SameSite=Lax` | Not sent on cross-site POST/iframe/XHR; **is** sent on top-level GET navigation | The CSRF baseline. Browser default today |
| `SameSite=Strict` | Never sent cross-site at all | Safest, but breaks "click a link in an email and be logged in" |
| `SameSite=None` | Always sent cross-site — **requires `Secure`** | Needed for third-party/embedded contexts, e.g. some SSO iframes |
| `Path` / `Domain` | Scope | `Domain=.example.com` shares the cookie with **every** subdomain, including one an attacker might control |
| `__Host-` prefix | Browser enforces Secure + Path=/ + no Domain | Free hardening; use it |

`Max-Age`/`Expires` absent → *session cookie*, dies with the browser. Note that
"restore tabs on startup" means browsers often keep these alive anyway; never rely
on it for security. Enforce lifetime **server-side**.

---

## 6. XSS vs CSRF — different bugs, different defences

People blur these constantly. Keep them apart.

### XSS — Cross-Site Scripting

Attacker gets **their JavaScript running on your origin**. Once that happens they
are you: they can read the DOM, call your APIs with the user's cookies, and read
anything JS can read (which is why `localStorage` is a poor place for tokens).

Defences: contextual output encoding, a strict **Content-Security-Policy**,
framework auto-escaping (React/Go `html/template`), avoid `innerHTML` and
`dangerouslySetInnerHTML`, sanitise rich text with a vetted library.

**Important honesty:** `HttpOnly` does not *stop* XSS. It stops token theft. An
attacker with XSS can still make authenticated requests from the victim's browser.
XSS is game over; `HttpOnly` just limits the blast radius beyond the session.

### CSRF — Cross-Site Request Forgery

Attacker makes **the victim's browser** send a request to your site. They cannot
read the response — they just want the side effect (transfer money, change email).
It works because cookies are attached automatically.

Defences, in order of preference:
1. **`SameSite=Lax` cookies** — now the browser default, and covers most cases.
2. **Anti-CSRF token** — synchroniser token (server-side, per session) or
   **double-submit** (a random value in a JS-readable cookie that must be echoed in
   a header; same-origin policy stops an attacker reading it). Implemented in
   `checkCSRF` in [lab/main.go](lab/main.go).
3. **Origin/Referer checking** on state-changing requests.
4. Re-authentication or step-up for genuinely sensitive actions.

**Token-in-header auth (`Authorization: Bearer`) is naturally CSRF-immune**,
because the browser does not attach that header automatically. That is a genuine
argument in favour of tokens — but it costs you `HttpOnly`, so you trade CSRF risk
for XSS risk. There is no free option; pick your poison deliberately.

Also: `GET` must never change state. A `GET /delete-account` is CSRF-able with a
single `<img>` tag.

---

## 7. User enumeration

If an attacker can determine *whether an account exists*, they have your customer
list — valuable on its own, and the first step of a credential-stuffing campaign.

Three leaks, all of which must be closed:

**1. Different response bodies.**
- ❌ "No account with that email" vs "Incorrect password"
- ✅ Both: `invalid email or password`
- Signup: ❌ "Email already registered" → ✅ `202 Accepted`, "if this address can be
  registered, a confirmation email has been sent" — and tell the *existing* owner by
  email that someone tried to sign up with their address.
- Password reset: ✅ always "if that account exists, a reset link has been sent."

**2. Different timing.** This is the leak people forget. If a missing user returns
in 5 ms and an existing user returns in 300 ms (because you ran Argon2id), your
identical response bodies are worthless. Fixes: hash against a dummy hash on the
miss path, *and* pad every credential endpoint to a fixed floor. See `pad` in
[lab/main.go](lab/main.go).

**3. Different side channels.** HTTP status codes, response length, rate-limit
headers, the presence of a `Set-Cookie`, whether the "resend verification" button
appears. Diff the *entire* response, not just the JSON body.

**The honest caveat:** if signup rejects duplicate addresses at all — and it must,
somewhere — a determined attacker can still learn membership via the confirmation
email flow. The goal is to make enumeration slow and expensive, not to claim it is
impossible. Say that out loud in a design review rather than overclaiming.

---

## 8. Lockout vs throttling

Naive answer: "lock the account after 5 failed attempts." That answer is a
**denial-of-service vulnerability**: I can lock any user I can name out of their
account, forever, by failing to log in as them. At scale, an attacker locks out
your entire user base with a script — and now your support desk is the outage.

Do this instead, layered:

- **Exponential backoff / throttling** per account and per source IP. Slow down,
  do not stop. (Both dimensions matter: per-IP alone is defeated by a botnet,
  per-account alone lets one IP spray across many accounts.)
- **Global anomaly detection**: a spike in failures across many accounts from one
  ASN is credential stuffing; respond at the network layer.
- **Progressive friction**: CAPTCHA, then proof-of-work, then email verification —
  escalate before you ever block.
- **Temporary** lockout with automatic expiry (15–30 min) if you must lock at all,
  never permanent.
- **Never leak lockout state** to an unauthenticated caller — "this account is
  locked" is user enumeration.
- Rate-limit the *reset* and *MFA* endpoints too; attackers go around the front door.
- NIST allows up to 100 consecutive failed attempts before you must intervene,
  which is far more permissive than most teams assume.

---

## Lab

A Go service implementing everything above, backed by Redis.

### Run it

```bash
cd 00-authn-vs-authz/lab
podman compose up --build        # or: podman-compose up --build
```

Service on `http://localhost:8080`, Redis on `localhost:6379`.

### Endpoints

| Method | Path | Notes |
|---|---|---|
| POST | `/signup` | `{"email","password"}` — always the same 202 |
| POST | `/login` | Sets `sid` + `csrf` cookies |
| GET | `/me` | Requires session cookie |
| GET | `/sessions` | Device/session inventory |
| POST | `/sessions/revoke-others` | "Log out all other devices" (needs CSRF header) |
| POST | `/logout` | Destroys the server-side session (needs CSRF header) |
| POST | `/password-reset` | Always the same 202 |

### Walkthrough

```bash
# 1. Sign up
curl -si localhost:8080/signup -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'

# 2. Sign up again with the SAME address. Compare the two responses byte for byte.
#    Status, body and headers are identical. That is enumeration prevention.

# 3. Log in, keeping the cookie jar
curl -si -c jar.txt localhost:8080/login -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
#    Read the Set-Cookie line: HttpOnly, SameSite=Lax, Path=/. Note csrf_token in the body.

# 4. Authenticated call
curl -s -b jar.txt localhost:8080/me

# 5. Log out WITHOUT the CSRF header -> 403. Then with it -> 200.
curl -si -b jar.txt -X POST localhost:8080/logout
curl -si -b jar.txt -X POST localhost:8080/logout -H "X-CSRF-Token: <token from step 3>"

# 6. Reuse the same cookie after logout -> 401. The session is gone server-side,
#    not merely cleared in the browser. This is what a JWT cannot do for free.
curl -s -b jar.txt localhost:8080/me
```

### Exercises

1. **Timing.** Comment out the `defer pad(start)` in `handleLogin`, rebuild, then:
   ```bash
   for i in $(seq 20); do curl -so /dev/null -w '%{time_total}\n' localhost:8080/login \
     -H 'content-type: application/json' -d '{"email":"nobody@example.com","password":"x"}'; done
   ```
   Compare against a real account. Restore `pad` and repeat. You have just
   demonstrated and then fixed a timing oracle.

2. **Hash cost.** Set `HASH_ALG` to `bcrypt`, then `sha256`, and time `/signup`
   each way. Feel the three orders of magnitude, and think about what that means
   for both your login latency budget *and* an attacker's cracking rate.

3. **Inspect Redis.** `podman exec -it lab_redis_1 redis-cli` then `KEYS *`,
   `GET sess:<id>`, `TTL sess:<id>`. Watch the TTL refresh when you call `/me` —
   that is sliding expiration. What is missing? (Answer: an *absolute* lifetime.
   Add one.)

4. **Breach check.** Set `HIBP_ENABLED=true`, restart, and try to sign up with
   `password123`. Then run `tcpdump`/inspect the code to confirm only 5 hex
   characters left the process.

5. **Multi-device.** Log in from three separate cookie jars, `GET /sessions`, then
   `POST /sessions/revoke-others`. Confirm the other two jars now 401. This is the
   data model Module 3 builds on.

6. **Break it, then fix it.** Add `SameSite=None` to the session cookie and write a
   tiny HTML page on a different port that auto-POSTs to `/logout`. Show the CSRF
   token still blocks it. Then remove the token check and show the attack lands.

---

## Self-check quiz (10 questions)

<details>
<summary>1. A user gets a 403. Were they authenticated?</summary>

Yes. 403 means the server knows who they are and is refusing anyway. 401 is the
unauthenticated case, despite being named "Unauthorized".
</details>

<details>
<summary>2. Why is salted SHA-256 still unacceptable for passwords?</summary>

Salting defeats rainbow tables and identical-hash correlation, but does nothing
about speed. SHA-256 is fast and GPU-friendly, so brute-force against a leaked
salted hash is still cheap. You need a deliberately slow, memory-hard KDF.
</details>

<details>
<summary>3. What is a pepper and where does it live?</summary>

A secret value mixed into every hash, stored **outside** the database (KMS/HSM/app
config). If the DB leaks alone, the hashes cannot be attacked. Its cost is that
rotation is hard.
</details>

<details>
<summary>4. Your CISO wants 90-day password rotation. Respond.</summary>

NIST SP 800-63B says rotate only on evidence of compromise. Forced rotation drives
predictable increments (`Summer2026!`→`Autumn2026!`), lowering real entropy, and
increases help-desk load. Offer instead: breached-password screening at set time,
MFA, and anomaly-triggered forced reset.
</details>

<details>
<summary>5. Give the single biggest advantage of each: server session vs JWT.</summary>

Session: instant, complete revocation. JWT: stateless verification — no shared
store on the request path, so it scales and crosses service/domain boundaries.
</details>

<details>
<summary>6. Which cookie flag stops XSS from stealing the session, and what does it not stop?</summary>

`HttpOnly`. It does not stop XSS itself — an attacker running JS on your origin can
still issue authenticated requests from the victim's browser. It limits
exfiltration, not exploitation.
</details>

<details>
<summary>7. Why is Bearer-token auth naturally CSRF-resistant, and what does that cost?</summary>

Browsers do not attach an `Authorization` header automatically, so a cross-site
request cannot carry credentials. The cost: the token must be stored somewhere JS
can reach, which forfeits `HttpOnly` and raises XSS exposure.
</details>

<details>
<summary>8. Signup returns 202 for both new and existing addresses. Enumeration solved?</summary>

Not by itself. Timing must match, all headers and status codes must match, and the
downstream email flow can still reveal membership. It raises cost substantially;
it does not make enumeration impossible.
</details>

<details>
<summary>9. Why is "lock the account after 5 failures" dangerous?</summary>

It hands any attacker a denial-of-service primitive against any user they can
name — no credentials required. Throttle with exponential backoff on both account
and IP, escalate friction, and only ever lock temporarily.
</details>

<details>
<summary>10. You raised Argon2id memory from 19 MiB to 47 MiB. How do existing users migrate?</summary>

You cannot re-hash without the plaintext, so you upgrade opportunistically: on each
successful login, check the stored parameters, and if they are below current policy
re-hash the just-supplied password and overwrite. Old hashes stay verifiable
because their parameters are embedded in the PHC string.
</details>

---

## References

- [NIST SP 800-63B — Digital Identity Guidelines, Authentication](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Pwned Passwords range API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [RFC 6265bis — Cookies (SameSite, `__Host-`)](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)

**Next:** [Module 1 — OAuth 2.0 Deep Dive](../01-oauth2/README.md)
