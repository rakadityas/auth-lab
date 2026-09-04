# Module 2 — OpenID Connect (OIDC), SAML & SSO

> If OAuth is the key card, OIDC is the ID photo printed on it. OAuth got you a
> token that says what you may do; OIDC adds a verifiable statement of *who you
> are*, and that is what makes one login work across many apps.

**Time:** ~2h reading, ~2h lab, ~1h quiz.
**Prerequisite:** Module 1. OIDC is a thin layer on the OAuth Authorization Code
flow — if that flow is fuzzy, go back.

### ELI5 — in simple words

In Module 1, the hotel gave the app a **key card** (a token). The key card says
what doors you can open. But it does **not** have your photo on it — so it does
not prove *who you are*.

**OIDC** adds the photo. It gives the app a second thing: an **ID token**, which
is like a small signed note from Google saying *"this person is alice, she logged
in at 9:00, and she used a fingerprint."*

Two important ideas:

- **A signed note (JWT).** Anyone can *read* the note (it is not secret!), but
  nobody can *fake* it, because it has a signature. The app must check the
  signature carefully. This module shows you how to fake a note badly and watch
  the checks catch you.
- **SSO (Single Sign-On).** You log in once at Google. Now App A and App B both
  work without typing your password again. Why? Because Google remembers *you*
  with its own cookie. When App B asks Google "who is this?", Google already
  knows and answers immediately — no password needed.

The hard part is **logging out**. Logging in once is easy. Logging out of
*everything at once* is difficult, because there are three separate memories:
Google's, App A's, and App B's. You will build the solution that actually works
(back-channel logout).

---

## 1. OIDC in one paragraph

OpenID Connect adds three things to OAuth 2.0:

1. An **ID token** — a signed JWT that is a *login receipt*, asserting who
   authenticated, when, and how.
2. A **`/userinfo` endpoint** — an API returning claims about the user, callable
   with the access token.
3. **Standardized discovery and scopes** (`openid`, `profile`, `email`, …) so any
   OIDC client can talk to any OIDC provider without custom code.

The magic word is the **`openid` scope**. Add it to an OAuth authorization request
and you get an ID token back; leave it out and you are doing plain OAuth.

Vocabulary shift from OAuth: the **Authorization Server** is now called the
**OpenID Provider (OP)** or **Identity Provider (IdP)**, and the **Client** is
called the **Relying Party (RP)**.

---

## 2. ID token vs access token — do not mix them up

| | ID token | Access token |
|---|---|---|
| Audience (`aud`) | The **client** (RP) that logged the user in | The **resource server** (API) |
| Answers | *Who is this user, and how did they log in?* | *May the bearer call this API?* |
| Consumed by | The RP, once, at login | The API, on every request |
| Format | Always a JWT (spec requires it) | JWT **or** opaque — your choice |
| Sent to APIs? | **Never.** It is not an API credential | Yes, as `Authorization: Bearer` |

The number-one OIDC mistake: sending the ID token to your APIs as if it were an
access token, or accepting an access token as proof of identity. They have
different audiences on purpose. An API that accepts an ID token is trusting a
token minted for a different party.

### Core ID token claims

| Claim | Meaning | Why you check it |
|---|---|---|
| `iss` | Issuer — who minted it | Must equal the provider you trust |
| `sub` | Subject — **stable, unique** user id at this issuer | Your primary key for the user; never use `email` (it changes) |
| `aud` | Audience — your client id | Reject tokens minted for someone else |
| `exp` / `iat` | Expiry / issued-at | Reject stale or future-dated tokens |
| `nonce` | Ties the token to your auth request | Replay defence |
| `auth_time` | When the user actually authenticated | `max_age` / step-up decisions |
| `acr` / `amr` | Auth context class / methods (e.g. `mfa`, `pwd`) | "Was MFA used?" for sensitive actions |
| `sid` | The IdP session id | The join key for back-channel logout |

**`sub` + `iss` together** identify a user globally. `sub` alone is only unique
within one issuer.

---

## 3. JWT structure and verification

A JWT (JWS compact serialization) is three base64url parts joined by dots:

```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9 . eyJzdWIiOiJhbGljZSIsImV4cCI6MTco…} . SIGNATURE
└────────── header ──────────────────┘ └──────────── payload ───────────┘ └── signature ──┘
{"alg":"RS256","kid":"abc"}            {"sub":"alice","iss":"…","exp":…}
```

**base64 is not encryption.** The payload is readable by anyone. Never put a
secret in a JWT. The signature is the only thing that makes it trustworthy — and
only if you actually verify it.

### Verification, in the exact order it must happen

The lab implements every step in
[lab/internal/oidc/verify.go](lab/internal/oidc/verify.go). Read the failure paths.

1. Parse the header. **Reject `alg: none`** outright.
2. **Check `alg` against your own allowlist** (`RS256`, `ES256`). Never let the
   token's header choose the algorithm — that is the confusion attack.
3. Fetch the public key by `kid` from the issuer's **JWKS endpoint**; verify the
   signature over `header.payload`.
4. Check `iss` equals your expected issuer.
5. Check `aud` contains your client id (and `azp` if there are multiple audiences).
6. Check `exp`/`nbf`/`iat` with a **small** clock-skew leeway (≤ 60 s).
7. For an ID token from the code flow, check `nonce` matches what you sent.
8. If you demanded freshness (`max_age`), check `auth_time`.

### JWKS and key rotation

The provider publishes its public keys at a **JWKS URI** (found in the discovery
doc). Each key has a `kid`. The provider rotates keys periodically:

1. It publishes the new key alongside the old one.
2. It starts signing new tokens with the new `kid`.
3. It keeps the old key until every token signed with it has expired, then drops it.

Your RP must: cache the JWKS, look up keys by the token's `kid`, and **refetch on
an unknown `kid`** — but rate-limited, or an attacker sends garbage `kid`s to make
you hammer the JWKS endpoint (a DoS amplifier). See `KeySet.Key` in the lab.

---

## 4. JWT attack classes (and the checks that stop them)

| Attack | What the attacker does | Defence |
|---|---|---|
| **`alg: none`** | Sets `alg` to `none`, strips the signature | Reject `none` before anything else |
| **RS256 → HS256 confusion** | Switches `alg` to HS256 and signs with your *public* key (which is public) as the HMAC secret | Algorithm **allowlist**; the server decides `alg`, not the token |
| **Missing `aud`/`iss`** | Reuses a token minted for another client of the same issuer | Always validate both |
| **Expired-token replay** | Uses a captured token forever | Check `exp`; keep leeway tiny |
| **`kid` injection / path traversal** | Points `kid` at an attacker-controlled key or a file | Only load keys from the trusted JWKS, never a URL/path from the token |
| **Weak/`none` signature accepted by a lax library** | Relies on a library that verifies loosely | Use a vetted library; pin algorithms; write tests that assert forgeries are rejected |

Run these yourself:

```bash
cd 02-oidc-saml-sso/lab
go run ./cmd/jwtool --issuer http://localhost:8081/realms/authlab --aud app-a forge-none  <a-real-token>
go run ./cmd/jwtool --issuer http://localhost:8081/realms/authlab --aud app-a forge-hs256 <a-real-token>
go run ./cmd/jwtool --issuer http://localhost:8081/realms/authlab --aud app-a tamper      <a-real-token>
```

Each prints the forged token and then the verifier's rejection.

### Why an IdP signs asymmetrically (RS256/ES256), never HS256

- **Asymmetric (RS256/ES256):** the IdP holds the *private* key; every RP verifies
  with the *public* key. RPs can check tokens but cannot forge them.
- **Symmetric (HS256):** the same secret signs *and* verifies. Every RP would need
  the signing secret — so any RP (or anyone who leaks it) could mint tokens for
  every other RP. Unusable for federation.

`HS256` is only ever acceptable when one service both issues and verifies its own
tokens and shares the secret with no one.

---

## 5. Discovery — never hardcode endpoints

Every OIDC provider serves a metadata document (RFC 8414):

```
GET https://<issuer>/.well-known/openid-configuration
```

It returns `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`,
`jwks_uri`, `end_session_endpoint`, supported scopes, signing algorithms, and more.
Fetch it at startup and cache it; never paste endpoint URLs into config. **Verify
the `issuer` field in the document matches the issuer you requested** — otherwise a
hijacked discovery response can silently repoint you at an attacker's endpoints.

---

## 6. SSO — how one login covers many apps

The insight that trips up beginners: **SSO does not mean the apps share a session.
Three separate sessions exist.**

```
                       ┌──────────────────────────┐
                       │  IdP session (the SSO     │
                       │  session — a cookie on    │
                       │  the IdP's own domain)    │
                       └──────────────────────────┘
                          ▲                     ▲
             login via    │                     │  login via
             code flow    │                     │  code flow
                ┌─────────┴──────┐     ┌────────┴────────┐
                │ App A session  │     │ App B session   │
                │ (cookie on A)  │     │ (cookie on B)   │
                └────────────────┘     └─────────────────┘
```

First login to App A: no IdP session yet, so the user types their password; the
IdP creates its SSO session and App A creates its own. Now the user visits App B
and is redirected to the IdP — but the IdP already has a session cookie, so it
issues a code **without prompting**, and App B creates its own session. That
silent second login *is* SSO.

You will see this directly in the lab: log into app-a, then click "Log in" on
app-b and watch it complete with no password prompt.

---

## 7. Single logout — where SSO designs fail

Logging in is easy. Logging *out* everywhere is the hard part, because now you must
tear down three sessions across different domains. There are three specced
mechanisms; know all three by name.

**RP-Initiated Logout.** The user clicks "log out" in an RP. The RP redirects them
to the IdP's `end_session_endpoint` with an `id_token_hint`. The IdP ends its SSO
session. This handles the *current* app and the IdP — but not the *other* RPs.

**Front-Channel Logout.** The IdP renders hidden `<iframe>`s pointing at each RP's
logout URL, so the browser clears each RP's cookie. **This is increasingly broken:**
browsers now block third-party cookies by default, so the iframe request often
arrives without the RP's session cookie and clears nothing. Do not rely on it.

**Back-Channel Logout.** The IdP sends a direct **server-to-server POST** to each
RP's registered logout endpoint, carrying a signed **Logout Token** (a JWT with
`sid`/`sub` and an `events` claim, and — a spec rule people forget — **no `nonce`**).
No browser, no cookies, no third-party-cookie problem. **This is what you will
actually build**, and it is the one that works across domains today.

The lab implements back-channel logout end to end. Log into both apps, log out of
one, and watch the *other* app's server log print that it received a back-channel
logout token from the IdP and destroyed its session.

Hard parts back-channel logout still leaves you: the RP must map the IdP's `sid` to
its own session(s) (you need that index — see Module 0's session inventory), it
must handle the POST being retried or arriving out of order, and a token still in
flight can outlive the logout by its remaining lifetime.

---

## 8. Step-up authentication and `max_age`

Not every action deserves the same assurance. Reading your profile is low stakes;
changing your recovery email or moving money is not. **Step-up** re-authentication
forces a fresh, possibly stronger login for sensitive actions:

- `prompt=login` — force re-authentication even if an SSO session exists.
- `max_age=0` (or a small number) — the token's `auth_time` must be within that
  window, or the IdP re-prompts.
- `acr_values` — request a specific assurance level (e.g. require MFA); check the
  returned `acr`/`amr` to confirm you actually got it.

The lab's "Step-up re-authentication" button sends `prompt=login&max_age=0`; watch
the IdP re-prompt even though you are already logged in.

---

## 9. SAML 2.0 — the enterprise incumbent

SAML predates OIDC by a decade and still dominates **enterprise B2B SSO**. You will
meet it whenever a business customer says "we use Okta/Entra/Ping and want to log
into your product with it." A B2B portal often must speak *both* OIDC (for its own
users) and SAML (for enterprise customers' workforce SSO).

| | OIDC | SAML 2.0 |
|---|---|---|
| Era / built on | 2014, JSON + REST + OAuth | 2005, XML + SOAP-era |
| Token | Compact JWT | Verbose XML assertion |
| Signatures | JWS | XML-DSig (notoriously fragile — canonicalization bugs) |
| Transport | Redirects + JSON APIs | Browser POST of a base64 XML blob |
| Mobile/SPA friendly | Yes | Painful |
| Roles | OP / RP | IdP / SP (Service Provider) |
| Discovery | `.well-known` document | Exchange XML metadata files |
| Logout | RP/front/back-channel specs | SAML SLO (even more fragile) |

**Signature wrapping (XSW)** is SAML's signature-verification pitfall: the XML is
restructured so a signed element validates while the processor reads an unsigned,
attacker-controlled one. It is the SAML analogue of the JWT `alg` attacks — the
lesson is identical: verify signatures rigorously over exactly the element you act
on, using a hardened, current library and never a hand-rolled XML parser.

Rule of thumb: **new integrations → OIDC. Enterprise customers who mandate it →
SAML.** Do not build SAML by hand; use a vetted library or your IdP's SP support.

(No SAML code in this lab — the XML tooling would triple its size for a protocol
you should never hand-roll. The concepts and the comparison are the deliverable.)

---

## 10. `RFC 9068` — JWT access tokens

When your access tokens *are* JWTs, RFC 9068 defines a standard profile: a `typ` of
`at+jwt` so a resource server can tell an access token from an ID token, plus
required claims (`iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`, `scope`).
Adopt it so your resource servers validate access tokens consistently and can't be
tricked into accepting an ID token in their place.

---

## Lab

Two relying parties (app-a, app-b) sharing one Keycloak IdP, with working SSO,
step-up, and back-channel logout — plus a `jwtool` CLI for decoding, verifying, and
forging tokens.

### Start it

```bash
cd 02-oidc-saml-sso/lab
podman compose up -d                 # Keycloak IdP on :8081
# wait ~30s
curl -s localhost:8081/realms/authlab/.well-known/openid-configuration | jq .issuer
./run-apps.sh                        # app-a :9000, app-b :9001 (leave running)
```

User: `alice` / `password123`.

### Walkthrough

1. **SSO.** Open <http://localhost:9000>, log in as alice (you type the password).
   Then open <http://localhost:9001> and click "Log in" — it completes with **no
   password prompt**. Read both server logs: one full login, one silent.

2. **Inspect verification.** app-a's home page prints the full ID-token
   verification trace and the decoded claims. Note `sub`, `aud`, `sid`, `auth_time`.

3. **Back-channel logout.** With both apps logged in, click "RP-initiated logout"
   on app-a. Refresh app-b — you are logged out there too. In app-b's server log
   you will see `BACK-CHANNEL LOGOUT received from IdP ... destroyed 1 local
   session`. That POST came from Keycloak directly, not your browser. For a
   headless, scripted version of this whole sequence (login → SSO → single
   logout), run `./demo-sso-logout.sh`.

4. **Step-up.** Log in again, then click "Step-up re-authentication" on app-a.
   Keycloak re-prompts for the password **even though the SSO session is still
   valid**, because `max_age=0` demands fresh authentication.

### `jwtool` exercises

Grab a real ID token first: log in at <http://localhost:9000>, and copy the
`id_token` value printed under "ID token claims" on app-a's page. Then:

```bash
cd 02-oidc-saml-sso/lab
TOKEN=<paste an id_token>
ISS=http://localhost:8081/realms/authlab

go run ./cmd/jwtool decode "$TOKEN"                          # base64 only
go run ./cmd/jwtool --issuer $ISS --aud app-a verify "$TOKEN" # every check, in order
go run ./cmd/jwtool --issuer $ISS --aud app-a forge-none  "$TOKEN"
go run ./cmd/jwtool --issuer $ISS --aud app-a forge-hs256 "$TOKEN"
go run ./cmd/jwtool --issuer $ISS --aud app-a tamper      "$TOKEN"
go run ./cmd/jwtool --issuer $ISS --aud wrong-app verify  "$TOKEN"  # watch aud fail
```

### Exercises

1. **Break a check, watch it matter.** In `verify.go`, comment out the `aud` check
   and re-run `verify` with `--aud wrong-app`. It now passes — you have recreated
   the confused-deputy bug. Restore it.

2. **Rotate keys.** In the Keycloak admin console (Realm settings → Keys →
   Providers) add a new RSA key and make it active. Log in again and watch the RP
   fetch the new `kid` from the JWKS on demand. Then verify an *old* token still
   validates against the retained old key.

3. **`sid` and multi-device.** Log in from two browsers, then back-channel-logout
   one. Reason about what the RP needs to only kill the right session (hint: the
   `sid` index — this is Module 0's session inventory again).

4. **Front vs back channel.** Explain, in writing, why Keycloak here uses
   back-channel logout and not the hidden-iframe front-channel variant. (Answer:
   third-party cookie blocking + cross-origin.)

5. **Read a real provider's discovery doc.** Fetch Google's and Microsoft's
   `.well-known/openid-configuration`. Find their `jwks_uri`, note how many keys
   they publish (rotation in action), and their `id_token_signing_alg_values_supported`.

### Tear down

```bash
podman compose down -v      # stop Keycloak; Ctrl-C the run-apps.sh terminal
```

---

## Self-check quiz (12 questions)

<details>
<summary>1. What single scope turns an OAuth request into an OIDC login?</summary>

`openid`. Without it, no ID token is issued and you are doing authorization only.
</details>

<details>
<summary>2. Your API accepts an ID token as a Bearer credential. What is wrong?</summary>

The ID token's `aud` is your login client, not the API. It is a login receipt, not
an API credential; accepting it means trusting a token minted for a different
party. Use the access token, and validate its `aud` is the API.
</details>

<details>
<summary>3. Why key a user record on `sub`, not `email`?</summary>

`sub` is stable and unique per issuer; email addresses change and get reassigned.
Use `iss`+`sub` as the identity, and treat email as mutable profile data.
</details>

<details>
<summary>4. Walk through the two JWT `alg` attacks and their single shared defence.</summary>

`alg:none` strips the signature; RS256→HS256 signs with the public key as an HMAC
secret. Both exploit a verifier that lets the token's header choose the algorithm.
Defence: an algorithm allowlist enforced by the server, plus rejecting `none`.
</details>

<details>
<summary>5. Why does an IdP sign with RS256/ES256 rather than HS256?</summary>

Asymmetric signing lets every RP verify with a public key while only the IdP can
sign with the private one. HS256 would require sharing the signing secret with
every RP, so any RP could forge tokens for all the others.
</details>

<details>
<summary>6. What is a JWKS and how does key rotation work through it?</summary>

The provider's published set of public signing keys, each tagged with a `kid`. To
rotate, it publishes the new key, starts signing with it, and retains the old key
until all tokens signed with it expire. RPs look up keys by `kid` and refetch
(rate-limited) on an unknown one.
</details>

<details>
<summary>7. SSO is working. How many sessions exist for a user in two apps, and where?</summary>

Three: one at the IdP (the SSO session, a cookie on the IdP domain) and one at each
RP (a cookie on each app's domain). The apps do not share a session.
</details>

<details>
<summary>8. Name the three logout mechanisms and say which one you would build.</summary>

RP-Initiated, Front-Channel, Back-Channel. Build Back-Channel: it is a direct
server-to-server signed POST, immune to third-party cookie blocking, and works
across domains. Front-channel (hidden iframes) is broken by cookie policies.
</details>

<details>
<summary>9. What must a back-channel Logout Token contain and must NOT contain?</summary>

Must: `iss`, `aud`, `iat`, `jti`, `sid` and/or `sub`, and an `events` claim naming
the backchannel-logout event. Must NOT: a `nonce`. It is verified like any JWT,
against the IdP's JWKS.
</details>

<details>
<summary>10. How do you force MFA for a sensitive action mid-session?</summary>

Step-up: send `prompt=login` (and/or `max_age`) with `acr_values` requesting the
MFA assurance level, then verify the returned `acr`/`amr` and `auth_time` actually
reflect a fresh, MFA-backed authentication before allowing the action.
</details>

<details>
<summary>11. When would you still choose SAML over OIDC in 2026?</summary>

When an enterprise customer's workforce IdP only speaks SAML for B2B SSO. New
first-party integrations should use OIDC; SAML is the compatibility path for
enterprise federation.
</details>

<details>
<summary>12. Why validate the `issuer` field inside the discovery document?</summary>

So a hijacked or spoofed discovery response cannot silently repoint you at an
attacker's authorization, token, or JWKS endpoints. The document's `issuer` must
match the issuer you asked for.
</details>

---

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519) ·
  [RFC 7517 — JWK](https://datatracker.ietf.org/doc/html/rfc7517) ·
  [RFC 7515 — JWS](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 8414 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [jwt.io](https://jwt.io) — interactive decoder (paste a token; do not paste production tokens)
- [OWASP JWT for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) — the checks generalise to any language

**Previous:** [Module 1 — OAuth 2.0](../01-oauth2/README.md) ·
**Next:** [Module 3 — Sessions, MFA & Recovery at Scale](../03-sessions-mfa-recovery/README.md)
