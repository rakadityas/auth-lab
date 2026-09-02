# Module 1 — OAuth 2.0 Deep Dive

> OAuth is a hotel key card. You get a limited-access card (a token) instead of
> handing your actual house key (your password) to every service.

**Time:** ~3h reading, ~1h lab, ~1h quiz.

The single most important sentence in this module:

> **OAuth 2.0 is an *authorization* framework, not an authentication protocol.**

An access token tells a resource server *what the bearer may do*. It does not
reliably tell you *who the user is* — that is Module 2's job (OIDC). Systems that
used a raw OAuth access token as proof of identity produced a well-known class of
account-takeover bugs. Know this distinction cold; it is the most common interview
question in this space.

---

## 1. The four roles

```
   ┌───────────────┐                         ┌────────────────────────┐
   │ Resource      │  1. "may this app…?"    │ Authorization Server   │
   │ Owner  (you)  │◄───────────────────────►│ (issues tokens)        │
   └───────────────┘                         └────────────────────────┘
          ▲                                        ▲            │
          │ uses                                   │ 2. code    │ 3. tokens
          ▼                                        │  exchange  ▼
   ┌───────────────┐                         ┌────────────────────────┐
   │ Client        │ ──── 4. Bearer token ──►│ Resource Server        │
   │ (the app)     │                         │ (the API holding data) │
   └───────────────┘                         └────────────────────────┘
```

| Role | Is | Example |
|---|---|---|
| **Resource Owner** | The human who owns the data | You |
| **Client** | The app wanting access | A photo-printing web app |
| **Authorization Server (AS)** | Authenticates the owner, issues tokens | Your company's login service, Keycloak, Auth0 |
| **Resource Server (RS)** | The API that holds the data and accepts tokens | The photo storage API |

AS and RS are often the same deployment early on, and separating them later is a
common migration. Design as if they are separate from day one — it forces you to
be honest about what is in the token.

### Confidential vs public clients

- **Confidential** client can keep a secret: a server-side backend. It
  authenticates to the token endpoint (client secret, `private_key_jwt`, or mTLS).
- **Public** client cannot: SPAs, mobile apps, desktop apps, CLIs. Anything shipped
  to a user can be decompiled or read in devtools. A "secret" in a mobile binary is
  not a secret.

**Public clients must use PKCE.** So must confidential ones, per RFC 9700.

---

## 2. Grant types

### Authorization Code + PKCE — the modern default

Use this for **every** interactive user login: web apps, SPAs, mobile, desktop.

```
User        Client                      Authorization Server            Resource Server
 │            │                                  │                            │
 │ click login│                                  │                            │
 ├───────────►│ verifier = random(43-128)        │                            │
 │            │ challenge = BASE64URL(SHA256(v)) │                            │
 │◄───────────┤ 302 to /authorize?               │                            │
 │            │   response_type=code             │                            │
 │            │   &client_id&redirect_uri&scope  │                            │
 │            │   &state&nonce                   │                            │
 │            │   &code_challenge&method=S256    │                            │
 │────────────────────────────────────────────► │ stores challenge            │
 │  login + consent (password never touches the client)                       │
 │◄────────────────────────────────────────────┤ 302 redirect_uri?code=…&state│
 ├───────────►│ verify state matches             │                            │
 │            │ POST /token                      │                            │
 │            │   grant_type=authorization_code  │                            │
 │            │   code, redirect_uri, client_id  │                            │
 │            │   code_verifier=<the secret>     │                            │
 │            ├─────────────────────────────────►│ SHA256(verifier)==challenge?│
 │            │◄──── access + refresh (+ id) ────┤                            │
 │            ├────── Authorization: Bearer ─────────────────────────────────►│
```

**Why the two-legged dance at all?** The code travels through the *front channel*
(the browser: URL bar, history, `Referer` headers, proxy logs). The token travels
only through the *back channel* (a direct server-to-server POST). Splitting them
means a leaked code alone is not a leaked token.

**Why PKCE (RFC 7636) on top?** Because on mobile, a malicious app could register
the same custom URI scheme and intercept the redirect — stealing the code. PKCE
binds the code to the client instance that started the flow:

- `code_verifier`: 43–128 random unreserved characters. Never leaves the client.
- `code_challenge = BASE64URL(SHA256(verifier))`. Public; sent up front.
- At the token endpoint, the client presents the verifier; the AS re-hashes and
  compares. A thief with the code but not the verifier gets nothing.

Always `code_challenge_method=S256`. `plain` sends the verifier itself and is
useless. PKCE was originally for mobile; **RFC 9700 now requires it for all
clients, confidential ones included**, because it also defeats code injection.

### Client Credentials — service-to-service

No user, no browser, no redirect, no refresh token. The client authenticates as
itself and gets a token representing *the application*. Use for cron jobs,
backend→backend calls, machine identities. If your "user" is a service account
with a human's credentials, you have done this wrong.

### Device Authorization Grant (RFC 8628) — input-constrained devices

TVs, consoles, CLIs, IoT. The device shows a short `user_code` and a URL; the user
completes login on their phone; the device polls the token endpoint until approval.
Respect `interval` and back off on `slow_down`. The security caveat is real: users
are trained to type a code into a site, so phishing with a fake device code is a
live attack — hence short lifetimes and clear consent text naming the device.

### Refresh Token

Not really a grant for getting *initial* access — it is how a client obtains a new
access token when the short-lived one expires, without dragging the user through
login again. For public clients, refresh tokens **must** be rotated (a new one
issued on every use, the old one invalidated) with reuse detection. That is
Module 3's implementation project.

### Deprecated — know why, so you can push back

| Grant | Why it is dead |
|---|---|
| **Implicit** (`response_type=token`) | Returns the access token in the URL **fragment**: it lands in browser history, `Referer` headers, and any script on the page. No client authentication, no way to bind the token. It existed only because CORS was not universal in 2012. That reason is gone. Use Auth Code + PKCE. |
| **Resource Owner Password Credentials** (`grant_type=password`) | The user types their password *into the client*. That is precisely the thing OAuth was invented to stop. It cannot support MFA, federation, or step-up, and it trains users to be phished. |

Both are formally deprecated by **RFC 9700 (BCP 240, January 2025)**.

---

## 3. RFC 9700 — cite this, not RFC 6749 alone

RFC 6749 (2012) is the base spec, and following it *alone* leaves you with an
insecure system. **RFC 9700, "Best Current Practice for OAuth 2.0 Security"
(BCP 240, January 2025)** is the baseline you cite in design docs and reviews.

What it requires:

- PKCE for **all** clients using the authorization code flow.
- **Exact string matching** of redirect URIs — no wildcards, no prefix matching,
  no "anything under this path".
- Implicit and ROPC grants **must not** be used.
- Sender-constrained refresh tokens, or rotation with reuse detection.
- Defence against **mix-up attacks** (below): use the `iss` parameter in the
  authorization response (RFC 9207) when a client talks to multiple ASes.
- Access tokens must be audience-restricted and scoped to a resource.

**OAuth 2.1** is an Internet-Draft that consolidates 6749 + PKCE + these BCPs into
one document. It is not yet an RFC. In writing, cite **RFC 9700**; mention 2.1 as
the direction of travel.

---

## 4. Attacks you must be able to name

**Redirect URI manipulation / open redirect.** If the AS accepts
`redirect_uri=https://app.example.com/cb?next=https://evil.com` or matches by
prefix, an attacker redirects the code to themselves. Fix: exact matching,
registered per client, and no open redirectors anywhere on the client's domain
(the attacker will chain through them).

**Authorization code interception.** A malicious app claims your mobile URI scheme
and receives the code. Fix: PKCE, and on mobile use Universal Links / App Links
rather than custom schemes.

**CSRF on the redirect.** An attacker gets *their* code delivered to *your*
session, silently linking your account to their identity. Fix: the `state`
parameter, bound to the user's session and verified on return. State is
mandatory, not optional.

**Mix-up attack.** A client that supports several ASes is tricked into sending a
code issued by AS-A to AS-B (attacker-controlled), leaking it. Fix: RFC 9207 `iss`
in the authorization response, and per-AS redirect URIs.

**Token leakage via `Referer`/logs.** Never put tokens in query strings. Use the
`Authorization` header. Scrub tokens from logs — including the `code`.

**Confused deputy / audience confusion.** Service A accepts a token minted for
service B and honours it. Fix: **always validate `aud`**. A resource server that
does not check the audience will accept any token your AS ever issued.

**Consent phishing.** The attack that needs no bug: a legitimately registered app
with a plausible name asks for `mail.readwrite`, and the user clicks Allow. Fix:
app-verification/publisher checks, admin consent policies for sensitive scopes,
and clear consent UI that names the actual capability.

---

## 5. Scopes vs claims vs audience

- **Scope** — what the *client* is permitted to request. Coarse capability strings
  (`invoices.read`). A ceiling, not a grant: still enforce the user's own
  permissions server-side.
- **Claims** — statements about the subject inside a token (`sub`, `email`,
  `roles`, `department`).
- **Audience (`aud`)** — *which resource server* the token is for. The RS must
  reject tokens not addressed to it.

Design guidance: keep scopes few and coarse; keep authorization decisions in the
resource server. A token with 200 fine-grained scopes is a token you cannot fit in
a header and cannot reason about. Resist putting per-object permissions in tokens.

---

## 6. Token lifetimes

| Token | Typical | Why |
|---|---|---|
| Authorization code | 30–60 s, **single use** | Front-channel exposure; replay must fail |
| Access token | 5–15 min | Bounds the damage of a leak; sets your revocation delay |
| Refresh token (public client) | Hours–days, **rotated on each use** | Rotation gives you theft detection |
| Refresh token (confidential) | Days–months | Client authentication does the heavy lifting |
| ID token | Minutes | It is a login receipt, not an API credential |

Shorter access tokens = smaller revocation window, more token-endpoint traffic.
That is the dial you tune. Write the chosen number and its justification into the
design doc; "15 minutes" with no reasoning is not an answer.

---

## 7. Sender-constrained tokens — beyond bearer

A **bearer** token is like cash: whoever holds it can spend it. The whole security
model rests on TLS and on nobody ever logging the thing.

Sender-constraining binds the token to a key the client holds, so a stolen token
is inert:

- **DPoP (RFC 9449)** — Demonstrating Proof of Possession. The client generates a
  key pair and sends a signed `DPoP` header on every request, covering the method,
  URL, a nonce, and a hash of the access token. The token carries `cnf.jkt` (a
  thumbprint of the public key). Application-layer, works for SPAs and mobile,
  no infrastructure changes. This is the practical option today.
- **mTLS-bound tokens (RFC 8705)** — the token is bound to the client's TLS client
  certificate (`cnf.x5t#S256`). Stronger and simpler conceptually, but needs PKI
  and TLS termination that preserves the client cert. Common in banking/open finance.

Expect "should we do DPoP?" in a real design review. The honest answer is usually:
worthwhile for high-value APIs and public clients; measurable complexity cost;
requires the resource servers to actually verify the proof (many don't).

---

## 8. Two more specs worth knowing by name

**Token Exchange (RFC 8693).** Service A holds a user's token and must call
service B *on that user's behalf*, without impersonating them blindly. It exchanges
its token for a new one scoped to B, carrying `act` (actor) and `may_act` claims so
the audit trail records *delegation*, not impersonation. This is the correct
answer to "how does our gateway call the downstream service as the user?" — much
better than forwarding the original token everywhere (which makes every downstream
service a replay risk) or using a god-mode service account (which destroys the
audit trail).

**Pushed Authorization Requests (PAR, RFC 9126).** The client POSTs the
authorization parameters to the AS over the back channel first and receives a
`request_uri`; the browser redirect then carries only that opaque handle. Benefits:
parameters cannot be tampered with in the front channel, nothing sensitive appears
in the URL, and you sidestep URL-length limits. Increasingly mandatory in
regulated profiles (FAPI 2.0).

---

## Lab

### Start the authorization server

```bash
cd 01-oauth2/lab
podman compose up -d          # or: podman-compose up -d
# Wait ~30s, then confirm:
curl -s localhost:8081/realms/authlab/.well-known/openid-configuration | jq .issuer
```

- Keycloak admin console: <http://localhost:8081> — `admin` / `admin`
- Realm: `authlab`, test user: `alice` / `password123`
- Clients: `demo-web` (public + PKCE), `demo-web-nopkce` (weak, for the exercise),
  `svc-backend` (confidential, secret `svc-backend-secret`), `device-cli`

### A. Trace the flow with curl — the core exercise

```bash
./trace-pkce.sh
```

Read every step of the output. It performs discovery, generates a PKCE pair, builds
the authorization URL, authenticates, exchanges the code, decodes the token, calls
a protected endpoint, then **replays the code** and **retries with a wrong
verifier** so you see both rejections. Do not move on until steps 1, 5 and 9 make
sense together.

### B. See it in a browser

```bash
./run-client.sh          # http://localhost:9000
```

Click through the flow. Open devtools → Network → preserve log, and identify:
the 302 to `/authorize`, the login POST, the 302 back with `?code=`, and the
XHR-invisible back-channel POST to `/token` (it happens server-side — that is the
point). The page prints the decoded tokens.

### C. The other grants

```bash
./other-grants.sh
```

Client credentials, introspection, revocation, and an interactive device-code flow.

### Exercises

1. **Break PKCE.** Run `./run-client.sh --no-pkce`. Complete a login, copy the
   `code` from the callback URL before the client redeems it (set a breakpoint by
   stopping the client after the redirect), and redeem it yourself with curl.
   With PKCE, repeat — the same theft fails. Write down, in one sentence, what
   PKCE actually protects.

2. **Break redirect URI matching.** In the admin console, change `demo-web`'s
   redirect URI to `http://localhost:9000/*`. Now try
   `redirect_uri=http://localhost:9000/callback/../evil`. Then set it back to the
   exact URI. Wildcards are how codes get stolen.

3. **Drop `state`.** Edit `handleLogin` to omit `state` and the check. Explain out
   loud what an attacker can now do (hint: they log *you* into *their* account).

4. **Audience.** Decode an access token from `svc-backend` and one from `demo-web`.
   Compare `aud`, `azp`, `sub`, and `scope`. Note the service token's `sub` is a
   service account, not a person.

5. **Lifetime.** Set the realm's access-token lifespan to 60 seconds
   (Realm settings → Tokens). Log in, wait, call `/userinfo` again with the old
   token, then refresh. Observe whether Keycloak returns a *new* refresh token —
   is rotation on?

6. **Read a discovery document from a real provider.** Fetch
   `https://accounts.google.com/.well-known/openid-configuration` and compare
   `grant_types_supported` and `code_challenge_methods_supported` against your
   local realm. Note what a large provider does and does not support.

### Tear down

```bash
podman compose down -v
```

---

## Self-check quiz (12 questions)

<details>
<summary>1. Why is an OAuth access token not proof of identity?</summary>

It is an authorization artifact: it says the bearer may access certain resources.
It has no required, verifiable statement about *who* authenticated, may be opaque,
and may have been minted for a different client. Using one as a login credential
enables token-substitution attacks. Use an OIDC ID token, or call `/userinfo`.
</details>

<details>
<summary>2. Explain PKCE to a backend engineer in three sentences.</summary>

The client invents a random secret (the verifier) and sends only its SHA-256 hash
when starting the flow. When it redeems the authorization code it must present the
original secret, which the server re-hashes and compares. So an attacker who steals
the code out of the browser redirect cannot exchange it.
</details>

<details>
<summary>3. Why is `code_challenge_method=plain` pointless?</summary>

It sends the verifier itself in the front channel, so anyone who can steal the code
has also stolen the verifier. Only `S256` provides the binding.
</details>

<details>
<summary>4. Front channel vs back channel — one line each, and why it matters.</summary>

Front channel: through the user's browser via redirects — visible in URLs, history,
and Referer headers. Back channel: a direct server-to-server HTTPS call — invisible
to the browser. Codes may cross the front channel; tokens must not.
</details>

<details>
<summary>5. What does `state` protect against, and how does it differ from `nonce`?</summary>

`state` is CSRF protection for the redirect: it binds the callback to the browser
session that started the flow, blocking an attacker injecting their code. `nonce`
is OIDC replay protection: it is echoed inside the ID token and verified there.
State lives in the URL; nonce lives in the token.
</details>

<details>
<summary>6. Why must redirect URIs be matched exactly?</summary>

Any flexibility (wildcards, prefixes, path traversal, unmatched query params) lets
an attacker steer the authorization code to a URL they control, often chained
through an open redirector on the legitimate domain. Exact matching is required by
RFC 9700.
</details>

<details>
<summary>7. Which grant for a smart-TV app, and what is its main risk?</summary>

Device Authorization Grant (RFC 8628). Main risk: users are conditioned to type a
code into a website, so attackers phish by presenting their own device code and
capturing the resulting authorization. Mitigate with short lifetimes and consent
screens that name the requesting device.
</details>

<details>
<summary>8. Your team wants ROPC "just for our own mobile app". Respond.</summary>

It puts the user's password in the app, which is what OAuth exists to prevent; it
cannot do MFA, federation, step-up, or CAPTCHA; it is deprecated by RFC 9700; and
it trains users to enter credentials into arbitrary UIs. Use Authorization Code +
PKCE in an in-app browser tab (ASWebAuthenticationSession / Custom Tabs), never a
raw WebView.
</details>

<details>
<summary>9. What does a resource server absolutely have to validate on a JWT access token?</summary>

Signature against the AS's JWKS (with the right `alg`), `iss`, `aud` (it must be
*this* server), `exp`/`nbf` with a small clock-skew allowance, token type/`typ`
per RFC 9068, and then scopes plus the user's own permissions. Missing `aud` is the
classic confused-deputy hole.
</details>

<details>
<summary>10. Bearer vs DPoP-bound token, in one line.</summary>

A bearer token is cash — whoever holds it spends it. A DPoP-bound token requires a
per-request signature from a private key the client holds, so a stolen token alone
is useless.
</details>

<details>
<summary>11. Gateway holds a user's token and must call three downstream services. Options?</summary>

Best: RFC 8693 token exchange, minting a per-audience token with `act`/`may_act`
preserving the delegation chain. Acceptable: audience-restricted tokens requested
up front. Bad: forwarding the same token everywhere (each service becomes a replay
vector). Worst: a shared service account (audit trail destroyed).
</details>

<details>
<summary>12. Which document is the security baseline you cite in a design doc, and why not OAuth 2.1?</summary>

RFC 9700 / BCP 240 (January 2025). OAuth 2.1 is still an Internet-Draft — it
consolidates the same guidance but is not yet an RFC, so cite 9700 and mention 2.1
as the direction of travel.
</details>

---

## References

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 6750 — Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8628 — Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [**RFC 9700 — OAuth 2.0 Security Best Current Practice (BCP 240)**](https://datatracker.ietf.org/doc/html/rfc9700)
- [RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 8705 — mTLS Client Authentication and Certificate-Bound Tokens](https://datatracker.ietf.org/doc/html/rfc8705)
- [RFC 8693 — Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 9126 — Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [RFC 9207 — Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [oauth.net](https://oauth.net/2/) — Aaron Parecki's maintained index
- Aaron Parecki, *OAuth 2.0 Simplified* — the readable book-length treatment

**Previous:** [Module 0 — Fundamentals](../00-authn-vs-authz/README.md) ·
**Next:** [Module 2 — OIDC, SAML & SSO](../02-oidc-saml-sso/README.md)
