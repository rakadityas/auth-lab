# Module 6 — Passkeys & WebAuthn, Hands-On

> Module 3 called passkeys "the endgame" and then only *described* them. This
> module makes you run the real thing: register a passkey with your actual
> fingerprint/face/security key in a browser, log in with a cryptographic
> signature instead of a password, and see why this is the first widely deployed
> login that phishing simply cannot beat.

**Time:** ~1.5h reading, ~1.5h lab, ~1h quiz.
**Prerequisites:** Module 0 (why passwords are hard), Module 3 (MFA, the passkey
concept). Module 2 helps (public-key signatures, challenges) but isn't required.
**Hardware:** a device with a platform authenticator (Touch ID, Windows Hello,
Android) **or** a FIDO2 security key, and a current browser. The ceremony runs in
the browser at `http://localhost:8080` — it can't be done from `curl`.

Everything up to now authenticated with a **shared secret**: the user and server
both know the password (or the TOTP seed). Shared secrets can be phished, leaked,
reused, and stolen from the server. Passkeys break that model. The user's device
holds a **private key that never leaves it**; the server stores only the matching
**public key**. Login is a signed challenge. There is nothing on the server to
steal and nothing the user can be tricked into typing into a fake site.

---

## 1. WebAuthn in one paragraph

**WebAuthn** (the browser API) + **CTAP** (the authenticator protocol) together
are **FIDO2**; a **passkey** is a FIDO2 credential, usually a *discoverable*
(resident) one that syncs across your devices (iCloud Keychain, Google Password
Manager). Three parties: the **authenticator** (Touch ID, a YubiKey — holds the
private key), the **client** (your browser — mediates and enforces origin), and
the **relying party** (this server — the "RP", holds the public key). Registration
creates a keypair bound to your account *and* to the RP's identity; authentication
proves possession of the private key by signing a fresh server challenge.

---

## 2. The two ceremonies

Both are a **begin / finish** pair. The server code is in
[lab/ceremonies.go](lab/ceremonies.go); the browser half is in
[lab/static/index.html](lab/static/index.html), which narrates each step in an
on-page log.

### Registration — `navigator.credentials.create()`

```
browser ── POST /register/begin ──► server invents a random CHALLENGE,
                                     returns options (rp id, user handle, algs)
browser ── navigator.credentials.create(options)
             └─► authenticator makes a NEW keypair, stores the private key,
                 signs an attestation over (challenge, rp id, origin)
browser ── POST /register/finish (attestation) ──► server verifies + stores the
                                                    PUBLIC KEY only
```

### Authentication — `navigator.credentials.get()`

```
browser ── POST /login/begin ──► fresh CHALLENGE + which credentials are allowed
browser ── navigator.credentials.get(options)
             └─► authenticator signs (challenge, rp id hash, origin) with the
                 private key — after a user gesture (touch/face/PIN)
browser ── POST /login/finish (assertion) ──► server verifies the signature with
                                              the STORED PUBLIC KEY
```

The **challenge** is what makes each ceremony a one-time, un-replayable proof: a
captured assertion is worthless because the next challenge differs.

---

## 3. Why passkeys are unphishable — the load-bearing detail

This is the single most important idea in the module, and the usual interview
question. Two bindings the *browser* enforces, that the user cannot be socially
engineered around:

- **The credential is bound to the RP ID** (here, `localhost`). When
  `navigator.credentials.get()` runs, the browser only offers credentials whose
  RP ID matches the site's origin. A phishing page on `evil-localhost.com` cannot
  make the browser produce a `localhost` passkey — there is no "type your passkey
  into the wrong box" failure mode, because the user never types anything.
- **The origin is signed and checked.** The authenticator signs over the real
  origin the browser reports; the server checks it against `RPOrigins`. A
  proxy/man-in-the-middle relaying the login can't fix up the origin — the
  signature would break.

Compare the things this defeats that MFA doesn't:

| Attack | Password | TOTP (Module 3) | Passkey |
|---|---|---|---|
| Phishing (fake login page) | ✗ stolen | ✗ code relayed in real time | ✅ browser won't release it to the wrong origin |
| Server DB breach | ✗ hashes to crack | ✗ seeds to reuse | ✅ only public keys — useless to steal |
| Replay of a captured login | ✗ | partly (30s window) | ✅ one-time challenge |
| Credential reuse across sites | ✗ | n/a | ✅ unique keypair per RP |

Real-time phishing proxies (Evilginx and friends) reliably defeat TOTP/push MFA
by relaying the one-time code. They **cannot** defeat WebAuthn, because there is
no code to relay and the origin binding breaks under the proxy. That's why this is
"the endgame."

---

## 4. Details the lab makes concrete

- **The user handle is random, not the email.** `user.go` generates a random 16-
  byte `WebAuthnID`. The spec forbids deriving it from PII because it can be stored
  on the authenticator and synced across devices. Your username is a *label*; the
  handle is the identity.
- **Attestation vs assertion.** Registration returns an *attestation* (proof a
  genuine authenticator made the key, optionally identifying its model);
  authentication returns an *assertion* (proof of possession). Most consumer RPs
  don't verify attestation strictly (privacy + friction); enterprises that must
  mandate specific keys do.
- **The signature counter / clone detection.** Each authenticator keeps a counter
  that must strictly increase across logins. If the server sees it stall or go
  backwards, two copies of the private key may exist — a *cloned* authenticator.
  `handleLoginFinish` rejects on `CloneWarning`. (Synced passkeys complicate this;
  many RPs treat it as a signal, not a hard block.)
- **Discoverable credentials = usernameless login.** A resident key lets the
  authenticator show you your accounts without the site naming them first — the
  "just tap to sign in" experience. This lab requests them as *preferred*.

---

## 5. The hard part nobody mentions: recovery

A passkey lives on a device. Lose every device that holds it and you're locked
out — passkeys move the whole security problem to **account recovery** (Module 3's
"real front door for attackers"). The mitigations, none free:

- **Register more than one** (phone + security key) so losing one isn't fatal.
- **Platform sync** (iCloud/Google) recovers passkeys to a new device — but now
  the security rests on that cloud account, which had better also be strong.
- **A fallback method** (a recovery code, a second factor) — which is also the
  weakest link an attacker will target. The recovery flow, not the passkey, is
  where these systems get broken.

There is no "reset my passkey" email that isn't itself a phishable recovery
channel. Designing recovery that doesn't undo the passkey's phishing resistance is
an open, genuinely hard problem — and a great thing to be able to discuss in a
design review.

---

## Lab

One container: the Go RP server, which also serves the browser page.

### Start it

```bash
cd 06-passkeys-webauthn/lab
podman compose up --build        # -d to background
```

Then **open http://localhost:8080 in a browser** (Chrome, Safari, or Edge). The
`curl`-able server half is available too:

```bash
./demo-ceremony.sh               # shows the challenge the browser is handed
```

### Do the ceremony

1. Click **Register a passkey**; approve with Touch ID / Windows Hello / your key.
2. Click **Log in with passkey** — no password, a signed challenge.
3. Click **Who am I?** to see the authenticated session.

Watch the on-page log: it prints each step (begin → `create`/`get` → finish) so
you can match the UI to `ceremonies.go`.

> **Why plain HTTP is OK here:** WebAuthn requires a "secure context", but
> `http://localhost` is explicitly exempt so you can develop locally. Anywhere
> else, it's HTTPS only.

### Endpoints

| Method + path | Ceremony step |
|---|---|
| `POST /register/begin?user=` | issue registration challenge |
| `POST /register/finish?user=` | verify attestation, store public key |
| `POST /login/begin?user=` | issue login challenge |
| `POST /login/finish?user=` | verify assertion signature, start session |
| `GET /whoami` / `POST /logout` | inspect / end the session |

### Exercises

1. **Prove the origin binding.** With the app running on `localhost:8080`, add a
   line to your hosts file mapping `127.0.0.1 notlocalhost.test`, and browse to
   `http://notlocalhost.test:8080`. Registration/login will fail — the browser's
   reported origin won't match `RPOrigins`, and even a made credential wouldn't be
   offered on a different RP ID. This is the anti-phishing property, demonstrated.
2. **Break the challenge, watch it reject.** In `index.html`'s `login()`, tamper
   with `opts.challenge` (flip a byte before calling `.get()`). `FinishLogin`
   rejects: the signature no longer matches the expected challenge.
3. **Register two passkeys, then remove one.** Register on your platform
   authenticator, then again (same username) on a phone or second browser profile.
   Confirm either logs you in. This is the recovery mitigation from §5 in action.
4. **Find the clone check.** Read `handleLoginFinish` and the `CloneWarning`
   handling. Explain what server-observable event would trip it and why a synced
   passkey makes the counter unreliable.
5. **Attestation none vs direct.** Read where `BeginRegistration` sets
   conveyance. Argue when a consumer app should *not* demand attestation (privacy,
   friction) and when an enterprise must.

### Tear down

```bash
podman compose down
```

---

## Self-check quiz (10 questions)

<details>
<summary>1. What does the server store for a passkey, and why is a DB breach less dangerous?</summary>

Only the **public key** (plus a credential ID, the random user handle, and a
signature counter). There is no shared secret — no password hash to crack, no TOTP
seed to reuse. A stolen database yields public keys, which are useless for
impersonation: you can't forge a signature without the private key, which never
left the user's authenticator.
</details>

<details>
<summary>2. Explain, mechanically, why WebAuthn resists phishing where TOTP does not.</summary>

The credential is bound to the RP ID and the authenticator signs over the real
origin, both enforced by the browser. A phishing site on a different domain can't
make the browser release the credential (wrong RP ID) and can't fake the origin in
the signature. TOTP has no origin binding — the user reads a code off their app
and can be tricked into typing it into a fake page, which a real-time proxy relays
to the real site within the validity window.
</details>

<details>
<summary>3. What is the challenge for, and what breaks if you reuse one?</summary>

The challenge is a fresh random value the server issues per ceremony; the
authenticator signs it, proving the response is live and made now. Reusing a
challenge would make captured assertions replayable — an attacker who recorded one
login could resubmit it. Single-use challenges make each proof valid exactly once.
</details>

<details>
<summary>4. Why must the user handle (WebAuthnID) not be the email or username?</summary>

The handle can be stored on the authenticator and synced across the user's
devices, so treating it as an identifier that leaks PII is a privacy problem, and
a mutable identifier (email changes) would break the credential binding. The spec
requires a stable, opaque, random handle; the human-readable username is a
separate display label.
</details>

<details>
<summary>5. Attestation vs assertion — what's the difference?</summary>

Attestation is produced at **registration**: a statement (optionally signed by the
authenticator's manufacturer) about the newly created key and the device that made
it — used to prove it's a genuine/approved authenticator. Assertion is produced at
**authentication**: a signature over the challenge proving possession of the
private key. Registration attests; login asserts.
</details>

<details>
<summary>6. What is the signature counter and what does a regression indicate?</summary>

A counter the authenticator increments on each use; the server checks it strictly
increases across logins. If it stalls or goes backward, two artifacts may be
signing with the same private key — i.e. the authenticator was cloned. It's a
tamper signal. (Synced passkeys share a key across devices by design, so many RPs
treat the counter as advisory rather than a hard reject.)
</details>

<details>
<summary>7. Why is plain HTTP acceptable for this lab but nowhere else?</summary>

WebAuthn requires a secure context; browsers make a specific exception for
`http://localhost` so developers can build without certificates. Any other host
must be HTTPS, because without transport security the origin the ceremony binds to
can't be trusted.
</details>

<details>
<summary>8. What is a "discoverable" (resident) credential and what UX does it enable?</summary>

One the authenticator stores fully, so it can present the user's accounts without
the server first telling it which credential IDs to allow. That enables
usernameless / "just tap to sign in" login. A non-discoverable credential needs
the server to supply the credential ID in `allowCredentials` first.
</details>

<details>
<summary>9. Passkeys eliminate the password. What problem do they make bigger?</summary>

Account recovery. A passkey lives on device(s); lose them all and you're locked
out, so recovery becomes the critical (and most-attacked) flow. Any recovery
channel — email reset, backup codes, a support process — is a potential bypass of
the passkey's phishing resistance, so recovery is where these systems actually get
broken and is the hard design problem.
</details>

<details>
<summary>10. A real-time phishing proxy (Evilginx) beats push/OTP MFA. Why not passkeys?</summary>

The proxy sits on a different origin than the real site. WebAuthn signs over the
origin and binds the credential to the RP ID, so the browser won't release a
credential to the proxy's origin, and even a relayed assertion would carry the
wrong origin and fail verification. There is no human-transcribable secret for the
proxy to capture and forward, which is exactly how it beats OTP.
</details>

---

## References

- [WebAuthn Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/) — the spec
- [FIDO Alliance — Passkeys](https://fidoalliance.org/passkeys/) and [passkeys.dev](https://passkeys.dev/) (developer guidance)
- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) — the library this lab uses
- [OWASP Authentication Cheat Sheet — WebAuthn/FIDO](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Evilginx / real-time phishing and why FIDO2 stops it](https://www.yubico.com/blog/aitm-phishing-and-why-fido-based-mfa-is-the-answer/)
