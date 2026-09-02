# Auth Lab — A Crash Course in Accounts, Identity & SSO

A hands-on course that takes you from **zero** to job-ready on the concepts an
**accounts / identity / authentication** team works with every day: passwords and
sessions, OAuth 2.0, OpenID Connect, SSO, JWTs, MFA, and token lifecycle at scale.

Every module pairs a written lecture with a **runnable lab** you drive locally
with **Podman Compose** — real Go services and a real Keycloak identity provider,
not slideware. You will build a login backend, trace an OAuth flow byte by byte,
verify and *forge* JWTs to watch the checks catch them, and implement refresh-token
rotation and TOTP MFA.

> Built from a role's competency map for an accounts/identity engineer. Product
> names have been intentionally left out; this is the transferable depth.

---

## Who this is for

You have **little or no background** in auth/SSO/OIDC and want to walk into an
identity-focused engineering role able to hold your own in design reviews. You can
read code and run a terminal; you don't need prior security knowledge. Go
familiarity helps but isn't required — the code is heavily commented and the point
is the *concepts*, which transfer to any language.

---

## The four modules

Work them **in order** — each builds on the last.

| # | Module | You'll build | Core ideas |
|---|--------|--------------|-----------|
| **0** | [AuthN vs AuthZ Fundamentals](00-authn-vs-authz/README.md) | Password + session-cookie login in Go, backed by Redis | Argon2id/bcrypt, salting, NIST SP 800-63B, cookies (HttpOnly/Secure/SameSite), CSRF vs XSS, user-enumeration & timing, throttling vs lockout |
| **1** | [OAuth 2.0 Deep Dive](01-oauth2/README.md) | Trace a live Authorization Code + PKCE flow against Keycloak | The 4 roles, grant types, PKCE, RFC 9700, redirect/mix-up attacks, DPoP, token exchange, PAR |
| **2** | [OIDC, SAML & SSO](02-oidc-saml-sso/README.md) | Two apps sharing one IdP, with SSO + back-channel logout; a JWT decode/verify/forge CLI | ID vs access token, JWT + JWKS + rotation, discovery, SSO sessions, single logout, JWT attacks, SAML comparison |
| **3** | [Sessions, MFA & Recovery at Scale](03-sessions-mfa-recovery/README.md) | Refresh-token rotation with reuse detection + TOTP MFA + session inventory | Distributed sessions, revocation, MFA methods, recovery flows, step-up, i18n, **the stateful-vs-stateless ADR** |

**Suggested pace:** one module per focused day (~4–5h each with the lab), or spread
across two weeks part-time. Do the exercises and answer the quizzes out loud — the
job is 50% being able to *explain* these decisions.

---

## Prerequisites

Everything below is already required by the labs. Versions shown are what the
course was built and tested against.

- **Podman** + **podman-compose** (or `podman compose`) — runs every lab
- **Go 1.23+** — a couple of labs run helper binaries on the host
- **curl** and **jq** — the flow-tracing scripts
- **openssl**, **python3** — used by `trace-pkce.sh`
- **oathtool** (optional, `brew install oath-toolkit`) — for the MFA demo; any
  authenticator app works too

Quick check:

```bash
podman --version && podman-compose --version && go version && jq --version
```

Each lab is self-contained in its own `lab/` directory with its own
`podman-compose.yml`. Nothing is installed globally; `podman compose down -v`
removes everything a module created.

---

## How to use a module

1. Read the module `README.md` top to bottom (the lecture).
2. `cd <module>/lab && podman compose up --build` (or `-d` to background it).
3. Run the walkthrough and the demo scripts; watch the server logs.
4. Do the **Exercises** — most ask you to *break* something and see the failure.
5. Answer the **Self-check quiz** (answers are in collapsible sections).
6. `podman compose down -v` to clean up.

### `podman compose` vs `podman-compose`

Recent Podman ships a built-in `podman compose` (note the space). Older setups use
the separate `podman-compose` (hyphen). Both work with these files; use whichever
your machine has. If images pull slowly the first time, that's normal —
subsequent runs are cached.

---

## What you will be able to do afterwards

- Explain AuthN vs AuthZ, sessions vs tokens, and defend a choice between them.
- Store passwords correctly and argue password policy from NIST, not folklore.
- Trace, and reason about the security of, an OAuth 2.0 / OIDC login end to end.
- Verify a JWT properly and name the attacks each check prevents.
- Design SSO and (the hard part) single logout across multiple apps.
- Implement refresh-token rotation, reuse detection, and TOTP MFA.
- Write the stateful-vs-stateless token ADR for a real system — and defend it.

---

## A note on the code

The labs deliberately **hand-roll** things you'd normally take from a library
(JWT verification, the OAuth client, refresh rotation). That's a teaching choice:
you can't debug — or securely configure — a library whose internals you've never
seen, and every real auth vulnerability lives in exactly these details. In
production, use vetted libraries (`golang.org/x/oauth2`, `coreos/go-oidc`,
`golang-jwt`, your IdP's SDK) and a real IdP (Keycloak, Auth0/Okta, Entra ID). The
concepts you learn here are what let you use those tools *correctly*.

Start with **[Module 0](00-authn-vs-authz/README.md)**.
