# Module 10 — Key & Secret Management

> The keys under everything. A JWT is only as trustworthy as the key that signed
> it, and encrypted PII is only as safe as the key that encrypts it. This module
> answers the three questions an identity team must get right: **where the signing
> key lives**, **how to rotate it with zero downtime**, and **how to encrypt PII at
> rest so you can rotate the master key without re-encrypting everything.**

**Time:** ~1.5h reading, ~1.5h lab, ~1h quiz.
**Prerequisites:** Module 2 (JWT structure, JWKS, `kid`, asymmetric signing —
this module is the operational other half). Basic familiarity with public-key
crypto helps.

Every earlier module *used* keys — signing JWTs, hashing tokens, encrypting
cookies. None asked the operational questions that decide whether those keys are
actually safe. A leaked signing key lets an attacker forge any identity; a lost
encryption key destroys data; a rotation done wrong logs everyone out. This is
where those go right or wrong.

---

## 1. Where does the signing key live?

The wrong answer, and an extremely common one: **in the application** — a PEM file
on disk, an env var, a config value. Then every app server, every backup, every
crash dump, every developer with prod access, and anyone who compromises the
process can read the private key and **forge tokens for any user**. There is no
recovering from a leaked signing key except rotating it and invalidating
everything.

The right answer: a **Key Management Service** (AWS KMS, GCP KMS, HashiCorp Vault)
or an **HSM**. The defining property — the entire point — is:

> The application asks the key service to **sign**; the private key never leaves
> the service.

[lab/kms.go](lab/kms.go) models exactly this boundary. The `kms` type holds the
private keys in unexported fields; the rest of the program only calls
`sign()`/`verify()`/`wrapDEK()` and **never receives private key bytes**. In this
lab the boundary is a Go type; in production it's a network or hardware boundary —
but the call sites are identical, which is the point: *your code shouldn't know or
care where the key physically is, and it should be impossible for your code to
exfiltrate it.* Compromising the app server then yields the ability to *request*
signatures (bad, but revocable and rate-limitable) rather than the key itself
(catastrophic and permanent).

---

## 2. Zero-downtime signing-key rotation

You must rotate signing keys — on a schedule, and immediately on suspected
compromise. The naïve "swap the key" breaks every token signed by the old key the
instant you switch. Zero-downtime rotation rests on three things, all from Module
2, used together:

- **`kid` (key ID) in every token header** — says *which* key signed this token.
- **JWKS** — the public endpoint publishing all *currently valid* verification
  keys, by `kid`.
- **Retire-then-remove**, never remove-immediately.

The sequence (see `rotateSigning` and the demo):

```
1. Steady state:        sign with K1;   JWKS = {K1}
2. Rotate:              sign with K2;   JWKS = {K1(retired), K2}   ← overlap window
     • new tokens carry kid=K2
     • tokens still in the wild carry kid=K1 and KEEP verifying against JWKS
3. Wait out max token lifetime (every K1 token has now expired)
4. Remove K1:           sign with K2;   JWKS = {K2}
```

The **overlap window** is the whole trick: for one max-token-lifetime, both keys
verify, so no valid token is ever rejected and no relying party needs a
coordinated flag-day deploy — they just re-fetch JWKS and see both keys. The demo
issues a token under K1, rotates, and shows that token **still verifying** against
the retired key, while new tokens use K2 — then removes K1 only after its tokens
would have expired.

The failure mode to internalize (Exercise 2): **remove the old key too early** and
every unexpired token it signed instantly becomes invalid — a self-inflicted mass
logout. Retirement, not removal, on rotation.

---

## 3. Encrypting PII at rest — envelope encryption

You must encrypt sensitive PII (national IDs, payment data, sometimes emails) at
rest. Two naïve approaches both fail at scale:

- **Encrypt everything directly with one master key.** Now that key is used on
  every record, is constantly in memory, and — the killer — **rotating it means
  decrypting and re-encrypting your entire dataset**, terabytes, offline-ish.
- **A key per record, stored in the clear.** Defeats the purpose.

**Envelope encryption** (the industry standard, what KMS is built for) uses two
levels — see [lab/envelope.go](lab/envelope.go):

- **DEK (Data-Encryption-Key):** a fresh random key **per record**, used to
  AES-GCM encrypt that record's data. Fast, symmetric.
- **KEK (Key-Encryption-Key):** the master, lives in the KMS. It's used only to
  **wrap (encrypt) the DEKs** — never the data directly.

Each stored record is `{kek_version, wrapped_dek, ciphertext}`. The plaintext DEK
exists only transiently in memory during encrypt/decrypt; at rest you have a
KEK-wrapped DEK next to the ciphertext, and the KEK stays in the KMS.

### Why this makes master-key rotation cheap

Rotating the KEK does **not** touch the ciphertext. You **rewrap**: unwrap each
record's small DEK under the old KEK, re-wrap it under the new KEK, store it back.
The data — the terabytes — is never decrypted or re-encrypted. The demo proves it:
after a KEK rotation and rewrap, the record's **ciphertext is byte-for-byte
identical**; only the tiny `wrapped_dek` changed. Old KEK versions are retained so
records not yet rewrapped still decrypt (same retire-don't-delete discipline as
signing keys), and you rewrap lazily or in a background sweep.

---

## 4. Secrets in config vs a vault (the quick version)

- **Don't** bake secrets into images, commit them, or pass long-lived ones as
  plain env vars — they leak via source control, layers, logs, and `/proc`.
- **Do** fetch secrets at runtime from a secrets manager (Vault, cloud secrets
  manager, or KMS for keys), ideally short-lived/dynamically-issued and scoped to
  the workload's identity.
- **Best** for signing/encryption keys: don't fetch the secret at all — keep it in
  the KMS/HSM and call *operations* on it (§1), so there's no secret in your
  process to leak.

---

## Lab

A single Go binary — **no database or KMS container**, because the KMS is modeled
*in-process* precisely so the trust boundary is visible in the code (`kms.go`).
Swap the type for AWS KMS / Vault and the handlers don't change.

### Start it

```bash
cd 10-key-management/lab
podman compose up --build       # -d to background
```

### The two demos

```bash
./demo-rotation.sh    # zero-downtime signing-key rotation via kid + JWKS
./demo-envelope.sh    # envelope-encrypt PII, rotate the KEK, rewrap (data untouched)
```

### Endpoints

| Method + path | Purpose |
|---|---|
| `POST /token` `{sub}` | issue a JWT signed via the KMS (header carries `kid`) |
| `POST /verify` `{token}` | verify by the token's `kid` (works for retired keys) |
| `GET /.well-known/jwks.json` | public keys, by kid — the overlap window is visible here |
| `GET /keys` / `POST /keys/rotate` / `POST /keys/remove` | signing-key lifecycle |
| `POST /pii/encrypt` / `POST /pii/decrypt` | envelope encryption |
| `POST /pii/rewrap` | re-wrap a record's DEK under the current KEK |
| `GET /kek` / `POST /kek/rotate` | KEK lifecycle |

### Exercises

1. **See the kid do its job.** Issue a token, decode its header
   (`cut -d. -f1 | base64 -d`), and find the `kid`. Rotate, issue another, compare
   the kids. Then verify both — each is checked against its own key.
2. **Cause the mass logout, then avoid it.** Rotate, then **immediately**
   `/keys/remove` the retired kid (skip the wait). Verify a pre-rotation token —
   it now fails. That's what removing a key too early does to every unexpired
   token. Restart to reset and do it the right way (wait out the lifetime).
3. **Prove rewrap doesn't touch ciphertext.** Encrypt a value, save its
   `ciphertext`. Rotate the KEK, rewrap, and diff the `ciphertext` before/after —
   identical. Explain why that's what makes master-key rotation feasible at scale.
4. **Retain-then-retire KEKs.** After rotating the KEK, decrypt an *un-rewrapped*
   record — it still works via the old version. Now imagine deleting the old KEK
   version before rewrapping: which records become permanently unrecoverable?
5. **Argue the boundary.** In `kms.go`, the private key is an unexported field.
   Describe precisely what an attacker who pops the app process can and cannot do
   in this design vs. one where the PEM is loaded into the app. Why is
   "can request signatures" so much better than "has the key"?

### Tear down

```bash
podman compose down
```

---

## Self-check quiz (10 questions)

<details>
<summary>1. What is the defining property of a KMS/HSM, vs. keeping a key in the app?</summary>

The private key never leaves the service — the application requests *operations*
(sign, unwrap) and receives results, never the key material. An in-app key is
readable by every process, backup, crash dump, and anyone who compromises the
server; a KMS-held key is not, so a server compromise yields the ability to
request signatures (revocable, auditable, rate-limitable) rather than the key
itself (catastrophic, permanent).
</details>

<details>
<summary>2. Why is a leaked signing key uniquely catastrophic?</summary>

It lets an attacker forge valid tokens for *any* identity — the signature is the
whole basis of trust in a JWT, so a forged-but-correctly-signed token is
indistinguishable from a real one. There's no partial mitigation: you must rotate
the key and invalidate every token signed by it, logging everyone out.
</details>

<details>
<summary>3. What three mechanisms make zero-downtime signing-key rotation possible?</summary>

A `kid` in each token header (identifying its signing key), a JWKS endpoint
publishing all currently-valid public keys by kid, and a retire-then-remove
discipline that keeps the old key verifiable during an overlap window. Together
they let new and old tokens both verify while relying parties simply re-fetch
JWKS.
</details>

<details>
<summary>4. What is the "overlap window" and how long must it last?</summary>

The period after rotation during which both the new and the retired key are
published in JWKS and both verify. It must last at least one maximum token
lifetime, so that by the time you remove the old key, every token it signed has
already expired and nothing valid is rejected.
</details>

<details>
<summary>5. What happens if you remove the old signing key immediately on rotation?</summary>

Every unexpired token signed by that key instantly fails verification — a
self-inflicted mass logout / outage. That's why rotation *retires* the key
(keeps it verifiable, stops signing new tokens with it) and removal waits until
its tokens have expired.
</details>

<details>
<summary>6. In envelope encryption, what are the DEK and KEK and how are they used?</summary>

The DEK (Data-Encryption-Key) is a fresh random key per record that encrypts that
record's data. The KEK (Key-Encryption-Key) is the master key, held in the KMS,
used only to encrypt ("wrap") the DEKs — never the data directly. Each record
stores its ciphertext plus its KEK-wrapped DEK and the KEK version.
</details>

<details>
<summary>7. Why does envelope encryption make master-key rotation cheap?</summary>

Rotating the KEK only requires re-wrapping the small per-record DEKs (unwrap under
the old KEK, wrap under the new), not decrypting and re-encrypting the actual
data. The ciphertext stays byte-identical, so rotating the master key over a huge
dataset is a lightweight metadata operation instead of a full re-encryption.
</details>

<details>
<summary>8. Why must old KEK versions be retained after rotation?</summary>

Because records encrypted before the rotation still have their DEKs wrapped under
the old KEK version; until they're rewrapped, only the old KEK can unwrap them.
Deleting the old version before every record referencing it is rewrapped makes
those records permanently undecryptable. Retain, rewrap, then retire.
</details>

<details>
<summary>9. Why store the KEK version alongside each encrypted record?</summary>

So decryption knows which KEK version to use to unwrap that record's DEK. With
multiple KEK versions coexisting during/after rotation, the version tag is what
lets each record be unwrapped correctly regardless of which was current when it
was written — the same role `kid` plays for signing keys.
</details>

<details>
<summary>10. Best practice for the signing key: fetch it from a secrets manager, or something better?</summary>

Better: don't fetch it at all. Keep it in the KMS/HSM and call sign/verify
operations on it, so there is no secret key material in your process to leak. A
secrets manager is right for credentials you must *have* (a DB password); for
signing/encryption keys, the goal is that the app can *use* the key without ever
*holding* it.
</details>

---

## References

- [AWS KMS — envelope encryption & how it works](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping)
- [Google Cloud KMS — key rotation](https://cloud.google.com/kms/docs/key-rotation) and [envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption)
- [RFC 7517 — JSON Web Key (JWK) & JWKS](https://datatracker.ietf.org/doc/html/rfc7517) and [RFC 7515 — JWS (`kid`)](https://datatracker.ietf.org/doc/html/rfc7515)
- [HashiCorp Vault — transit secrets engine (sign/encrypt without exposing keys)](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) and [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
