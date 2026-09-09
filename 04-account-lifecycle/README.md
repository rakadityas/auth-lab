# Module 4 — Account Lifecycle, Data Model & Identity Linking

> Everything the first four modules skipped: what an *account* actually **is**.
> The row(s) in the database, the states it moves through from signup to erasure,
> and the single most-exploited seam in real products — attaching a second way to
> log in to an account that already exists.

**Time:** ~2h reading, ~2h lab, ~1h quiz.
**Prerequisites:** Module 0 (passwords, sessions, enumeration). Modules 1–2 help
for the linking section (you should know what an `id_token`/assertion is and that
it carries an `email` and a `sub`), but aren't strictly required.

Modules 0–3 taught **how to log a user in** and **how to keep the session alive**.
None of them defined the account the login points at. That's this module. It is
the part of the job an accounts/identity team owns outright and the part
interviewers probe when they want to know if you've actually run a user system,
not just read the RFCs.

### ELI5 — in simple words

So far we learned how to open the door. But **what is an account, actually?**
It is rows in a database, and a life story:

```
born  ->  confirmed  ->  alive  ->  sleeping  ->  in the trash  ->  erased
(sign up) (click email) (normal)  (deactivated) (soft deleted)   (purged)
```

Three simple rules this module teaches:

1. **Never use email as the account's ID.** People change their email. If your
   orders, files and logs all point to "alice@old.com", everything breaks the day
   she changes it. Instead give every person a random permanent number (UUID).
   The email is just a *label* on the account, not the account itself.
2. **Deleting is not one action.** First mark it deleted (so the person can
   change their mind, and support can still investigate). Later, really erase the
   personal data — but keep an empty "ghost row" so other tables that point to
   this person do not break.
3. **The dangerous one: connecting a second login method.** Alice has a password
   account with `alice@corp.com`. Later she wants "Sign in with Google".

   A thief can create a Google account and *type* `alice@corp.com` as their email.
   If your code says "same email = same person, log them in!", the thief just
   took over Alice's account **without knowing her password**.

   The fix: only trust the identity provider's permanent user ID
   (`provider + sub`), never the email. To connect a new login method, the person
   must first prove they own the old one (log in with the password).

You will run this attack yourself and watch it succeed, then flip one setting and
watch it be refused.

---

## 1. Why `users` is not one table

The instinct is a single `users(email, password_hash, google_id, …)` table. It
falls apart the first time someone wants two ways to log in, or you need to keep a
deleted user's foreign keys valid. The durable shape separates three concerns:

```
  One table  ──►  breaks the first time anything changes.

    users(email PK, password_hash, google_id, github_id, totp_secret, …)
              ▲            ▲                                   ▲
              │            │                                   │
      email changes    a second password?           a second passkey?
      → every order    a passkey too?               a fourth column?
        row is orphaned   no room                     no room


  Three tables  ──►  each answers exactly one question.

    ┌─ users ────────────────┐   who exists
    │ id  UUID  ◄────────────┼── everything in the product points HERE
    │ email (an attribute!)  │   and nothing points at the email
    │ status                 │
    └───────────┬────────────┘
                │ user_id                     user_id │
    ┌───────────▼────────────┐   ┌────────────────────▼─────────────┐
    │ credentials            │   │ identities                       │
    │ how they prove it      │   │ who else vouches for them        │
    │ password / totp /      │   │ (provider, subject) per IdP      │
    │ passkey — many rows    │   │ google+108…, okta+abc — many rows│
    └────────────────────────┘   └──────────────────────────────────┘

  the rule: a UUID is forever, an email is a label someone can change.
```

| Table | Answers | Holds |
|-------|---------|-------|
| `users` | **who exists** | the stable ID, the lifecycle status, the canonical email |
| `credentials` | **how they prove it** (something they know/have) | password hash, later TOTP secret, passkey |
| `identities` | **who else vouches** (federation) | `(provider, subject)` per linked IdP |

See [lab/schema.sql](lab/schema.sql) — read it before the lab; it is half the
lecture. The comments there justify every column.

### The one rule that prevents the most pain: never key on email

The `users.id` is a UUID and **nothing user-facing ever depends on the email**.
Emails change, get recycled by providers (a company reassigns a departed
employee's address), and compare equal in surprising ways (case, dots, plus-tags).
If orders, documents, and audit rows point at the email, all of that breaks the
day the email changes. They point at the UUID instead. The email is *an attribute*
of the user, not its identity.

Uniqueness on email is still enforced — but only among **live** rows, via a
partial unique index (`WHERE deleted_at IS NULL`). A deleted account must not
squat on its address forever.

---

## 2. The lifecycle state machine

An account is a small state machine. Getting the transitions right — especially
which are reversible — is most of the design:

```
                signup
                  │
                  ▼
        pending_verification
                  │ verify email (click magic link)
                  ▼
   ┌──────────► active ◄──────────┐
   │              │               │ login again
   │ deactivate   │ delete        │
   │              ▼               │
   └──────── deactivated      soft_deleted
                                  │ retention window elapses (cron)
                                  ▼
                               purged        (PII erased, row kept as tombstone)
```

- **pending_verification → active** — the account is inert until the email is
  proven. Login is refused with a distinct message; the *credential* is correct
  but the *account* isn't usable yet. This is a lifecycle gate, not an auth check.
- **active ⇄ deactivated** — reversible by design. Deactivation is a user saying
  "hide me for a while." This lab reactivates on next successful login; some
  products require an explicit un-deactivate. Either is fine — **decide and
  document it**, because it changes your enumeration surface (a deactivated email
  is still "taken").
- **soft_deleted → purged** — the one-way door. Soft-delete marks the row,
  **immediately revokes every session**, and starts a retention clock (grace
  period for "I changed my mind" + support/legal holds). A retention **cron job**
  later purges: erases PII, keeps a tombstone row.

### Why purge instead of `DELETE`

GDPR's right to erasure requires removing **personal data**, not blowing away
referential integrity. `DELETE FROM users` cascades into every table that
references the user — orders you must keep for tax law, an audit trail you must
keep for security. So `purgeUser` (in [lab/lifecycle.go](lab/lifecycle.go))
deletes credentials/identities/tokens, **nulls the PII** on the users row, and
sets `status = 'purged'`. Foreign keys stay valid; the human is gone from the
data.

---

## 3. Verification & change flows — the token pattern

Signup verification, email change, and password reset are the same primitive: a
**single-use, expiring, hashed token** delivered out-of-band.

Four properties, every time:

1. **Hashed at rest.** Store `sha256(token)`, mail the raw token. A read-only DB
   leak (a backup, a replica, a SQL-injection `SELECT`) then yields nothing
   usable — the same reason you never store passwords in plaintext.
2. **Single-use.** Redemption is an atomic `UPDATE … SET used_at = now() WHERE
   used_at IS NULL` — the row can only be claimed once, even under a double-click
   or a race.
3. **Expiring.** A leaked link is worthless after the TTL (this lab: 1h).
4. **Bound to a purpose.** A `verify_email` token can't be replayed against the
   `change_email` endpoint.

### Email change is a privilege escalation in disguise

Changing the email changes the **recovery channel** — whoever controls the email
can reset the password and owns the account. So the change flow (see
`handleEmailChange`) does three things a naive `UPDATE users SET email=?` skips:

- **Step-up:** re-prompt for the password even though there's a valid session. A
  hijacked cookie shouldn't be enough to seize the account.
- **Verify the new address** before it takes effect — the confirmation link goes
  to the *new* email, proving the user controls it (and that it's real).
- **Notify the old address** *after* the change, with a "wasn't me? revert" path.
  If an attacker did drive the change, this mail is the victim's only alarm. It is
  the single most important line in the whole flow — **never skip the notify**.

Password reset (Module 0 stubbed it) is the same shape and is left as Exercise 3.

---

## 4. Account linking — the takeover you'll actually ship

Here's the scenario that breaks real products. A user has a normal password
account, `alice@corp.com`. Later, "Sign in with Google" is added. Alice clicks it;
Google asserts `sub=g-alice, email=alice@corp.com`. There's no `identities` row
yet. **Do you attach this Google identity to the existing local account?**

The tempting answer — "the emails match, so yes, link them and log her in" — is a
textbook **account-takeover (ATO) primitive**, sometimes called *pre-account
takeover*:

1. Attacker creates a Google account and sets its profile email to
   `alice@corp.com` (Google won't stop you from *entering* an address you don't
   own; whether it marks it `email_verified` is a separate question you must not
   rely on).
2. Attacker clicks "Sign in with Google" on your site.
3. Your code sees `email=alice@corp.com` matching Alice's local account, auto-links
   the attacker's Google identity to it, and issues a session.
4. The attacker is now logged into Alice's account **having never known her
   password**.

`handleFederatedLogin` in [lab/linking.go](lab/linking.go) implements the whole
decision tree, with the dangerous branch behind `LINK_MODE`:

```
  THE TAKEOVER (LINK_MODE=unsafe) — no password is ever guessed:

   1. victim has a normal account          users: alice@corp.com  (password)
   2. attacker registers alice@corp.com at some IdP that lets them
      self-assert an address, or that verifies it weakly
   3. attacker clicks "Sign in with that IdP" on your product
   4. IdP sends you:  { sub: "attacker-999", email: "alice@corp.com" }
   5. your code: "I know that email!"  ──►  links the new identity
                                             to the victim's account
   6. attacker is now inside alice's account, permanently, with their own
      login. no password reset, no email to alice, nothing to notice.

  The safe branch — the only two things that may attach an identity:

     login arrives from IdP
              │
              ▼
     does (provider, sub) already match a link?
              │ yes ──────────────────────────► log in.        ✔ safe
              │ no
              ▼
     is the email owned by nobody?
              │ yes ──────────────────────────► new account.   ✔ safe
              │ no  ── it matches a local user
              ▼
     REFUSE. send them to password login; once the SESSION proves
     they own that account, let them link it from settings.
              └── the session is proof. an `email` claim is only
                  the IdP's opinion — even email_verified: true.
```

- **Case 1 — `(provider, sub)` already linked:** just log in. The only always-safe
  path. Note the join key: **`(provider, subject)`, never email.** `sub` is the
  IdP's stable, non-reassignable identifier for the user; email is a mutable,
  attacker-influenced attribute.
- **Case 2 — brand-new identity, email owned by nobody:** provision a fresh
  account and link. Safe.
- **Case 3 — brand-new identity, email matches a local account:** the danger zone.
  - `LINK_MODE=unsafe`: auto-link by email → **the vulnerability**.
  - `LINK_MODE=safe`: refuse. Make the user log in with their password first, then
    link from account settings (`handleExplicitLink`), where the **session** — not
    an email claim — proves they own the local account.

The one-sentence version for an interview: **an IdP's `email` claim proves the IdP
believes it, not that the caller controls your local account with that email; only
`(provider, sub)` matching an existing link, or a successful login to the local
account, may attach a new identity to it.** Even `email_verified: true` isn't
enough on its own — you have to trust *that specific IdP's* verification process,
and for a public IdP where anyone can self-register, you generally shouldn't for
auto-linking.

---

## Lab

Three containers via Podman Compose: **Postgres** (the schema),
**Mailpit** (an SMTP sink with a web UI, so magic links are real emails you open
in a browser), and the **Go app**.

### Start it

```bash
cd 04-account-lifecycle/lab
podman compose up --build        # add -d to background it
# Postgres applies schema.sql on first boot; app waits for it.
```

Open **http://localhost:8025** — Mailpit's inbox. Every verification link and
notification the service sends lands here.

### Endpoints

| Method + path | What it does |
|---|---|
| `POST /signup` | create user (`pending_verification`), mail a verify link |
| `GET  /verify-email?token=` | redeem the link → `active` |
| `POST /login` / `POST /logout` | password login; enforces the lifecycle gate |
| `GET  /me` | current account state |
| `POST /email/change` | step-up + send confirm to new address |
| `GET  /email/confirm?token=` | apply the change, notify old address |
| `POST /deactivate` | reversible; revokes sessions |
| `POST /delete` | step-up; soft-delete + revoke sessions |
| `POST /admin/purge?days=N` | the retention cron; erases PII of old soft-deletes |
| `GET  /export` | GDPR right-of-access dump |
| `GET  /audit` | this user's lifecycle event log |
| `POST /login/google` | federated login (the linking decision tree) |
| `POST /identities/link` | the **safe** way to link (authenticated) |
| `GET  /fake-idp/authorize?sub=&email=&email_verified=` | mints a test assertion |

### Guided demos

```bash
./demo-lifecycle.sh      # signup → verify → change email → deactivate → delete → purge
./demo-linking-ato.sh    # the account-takeover, live
```

Run the ATO demo once as shipped (`LINK_MODE=unsafe`) and watch the attacker get a
session on the victim's account. Then flip the mode and watch it refuse:

```bash
# edit compose.yaml: LINK_MODE: unsafe  ->  safe
podman compose up -d --build app
./demo-linking-ato.sh    # now 409, refused
```

### Exercises

Most of these ask you to *break* something and watch the defense hold — the
Module 0 pattern.

1. **Purge really erases.** Run the lifecycle demo, then
   `podman compose exec postgres psql -U lab -d lab -c
   "SELECT id, email, status FROM users WHERE status='purged';"`. Confirm `email`
   is `NULL` but the row (the tombstone) survives. Now try to re-register the
   purged address — does the partial unique index let you? Should it?
2. **Replay a verification token.** Grab a verify link from Mailpit, redeem it,
   then `curl` the same URL again. Explain the second response in terms of the
   atomic single-use `UPDATE`.
3. **Build password reset.** It's the token pattern from §3 with a new `purpose`.
   Add `POST /password-reset` (request) and `GET /password-reset/confirm`
   (redeem + set new hash). Enforce enumeration-safety on the request endpoint
   (same response whether or not the email exists — Module 0).
4. **Close the linking hole for real.** In `safe` mode, implement the *good* path
   end-to-end: log in with the password, then `POST /identities/link` with a fresh
   assertion, and confirm the identity attaches. Then argue: should you *also*
   require `email_verified` on the assertion even for explicit linking? Why or why
   not?
5. **Add an absolute retention policy.** `handlePurge` takes `?days=`. Wire a
   second lifecycle rule: accounts stuck in `pending_verification` for more than 7
   days should be purged too (abandoned signups are PII you're holding for no
   reason). Where does that belong — the same cron, or a separate one?

### Tear down

```bash
podman compose down -v      # -v also drops the Postgres volume (fresh schema next time)
```

---

## Self-check quiz (10 questions)

<details>
<summary>1. Why must the primary key be a UUID and not the email address?</summary>

Emails are mutable (users change them), reassignable (providers recycle addresses),
and compare equal in non-obvious ways (case, dots, plus-tags). Anything that
references the user by email breaks when the email changes. A stable synthetic key
(`users.id`) decouples identity from any attribute, and lets the email be updated,
nulled on purge, or duplicated across historical/tombstone rows without cascading
damage.
</details>

<details>
<summary>2. What's the difference between deactivated, soft_deleted, and purged?</summary>

`deactivated` is reversible — the account and all its data are intact, just hidden;
the user can come back. `soft_deleted` marks the account for deletion, revokes
access immediately, and starts a retention clock, but data still exists (grace
period + legal/support holds). `purged` is terminal: PII erased, only a tombstone
row remains so foreign keys elsewhere stay valid.
</details>

<details>
<summary>3. Why null the PII instead of DELETEing the users row for GDPR erasure?</summary>

Erasure requires removing *personal data*, not breaking referential integrity.
Hard-deleting the row cascades into records you're legally required to keep (orders
for tax, audit logs for security) or orphans them. Nulling the PII and keeping a
status=purged tombstone satisfies erasure while everything that legitimately
references the user by ID stays valid.
</details>

<details>
<summary>4. Verification tokens are stored hashed. Against which specific threat?</summary>

A read-only exposure of the database — a stolen backup, a compromised read
replica, a SQL-injection `SELECT` — that never touches the application. If raw
tokens were stored, that leak hands out live magic links (account verification,
email change, password reset). Hashing means the leaked rows can't be redeemed;
the attacker would need the raw token, which only ever left via the email.
</details>

<details>
<summary>5. Why does changing your email re-prompt for the password when you're already logged in?</summary>

The email is the recovery channel; controlling it means controlling the account.
An attacker who steals only a session cookie (XSS, a shared machine) shouldn't be
able to seize the account permanently. Requiring the password at the moment of a
high-value change (step-up / re-authentication) raises the bar from "has a session"
to "knows the secret."
</details>

<details>
<summary>6. Why send the "your email was changed" notice to the OLD address, and after the change?</summary>

If the change was legitimate, it's a harmless confirmation. If it was an attacker
who hijacked the session, the old address is the *only* channel the real owner
still controls — the notice (with a revert link) is their sole chance to catch it.
Sending it to the new address would just tell the attacker. It goes out after the
change so it reflects what actually happened.
</details>

<details>
<summary>7. In federated login, why is (provider, sub) the join key and never email?</summary>

`sub` is the IdP's stable, unique, non-reassignable identifier for that user —
exactly what you need to recognize "the same person logging in again." Email is a
mutable attribute the user (or attacker) can often set to an arbitrary value at the
IdP. Joining on email means trusting an attacker-influenceable field to decide
which local account to attach to — the account-takeover primitive.
</details>

<details>
<summary>8. Walk through the pre-account-takeover attack in four steps.</summary>

(1) Attacker registers an account at a public IdP and sets its email to the
victim's address. (2) Attacker clicks "Sign in with <IdP>" on the target site. (3)
The site finds no linked identity but sees the email matches a local account, and
auto-links the attacker's IdP identity to it. (4) The attacker gets a session on
the victim's account without ever knowing the password. Fix: never auto-link on
email; require a password login (or an already-linked `sub`) to attach a new
identity.
</details>

<details>
<summary>9. Is `email_verified: true` from the IdP enough to auto-link safely?</summary>

No. It shifts the question to "do I trust *this* IdP's verification process for
*this* use?" For a public IdP where anyone can self-register, that trust is
misplaced for auto-linking — and even a correct `email_verified` only proves the
user controls that email, not that they control *your* local account with the same
email. Safe linking is gated on proving control of the local account (a password
login), not on any assertion field.
</details>

<details>
<summary>10. Where does the safe linking path prove ownership of the local account?</summary>

In `handleExplicitLink`: the request carries the local account's **session**
(`requireSession`), which was established by a successful password login. That
session is the proof of ownership; the assertion only supplies the identity to
attach. Ownership comes from the authenticated session, never from the assertion's
email claim.
</details>

---

## References

- [OWASP — Pre-Account Takeover / account linking guidance](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- ["Pre-hijacking attacks on web user accounts" — Microsoft / Sudhodanan & Paverd](https://arxiv.org/abs/2205.10174) — the paper that named the account-linking ATO classes
- [GDPR Art. 17 — Right to erasure](https://gdpr-info.eu/art-17-gdpr/) and [Art. 15 — Right of access](https://gdpr-info.eu/art-15-gdpr/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) — session revocation on state change
