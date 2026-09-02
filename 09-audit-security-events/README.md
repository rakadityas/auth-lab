# Module 9 — Audit Logging & Security Events

> The record of what happened, and the alarm that tells the user when it
> shouldn't have. Two audiences, both non-negotiable for an identity team: a
> **tamper-evident audit log** for investigators and compliance, and **security
> notifications** for the account owner — who is often the only person who can
> tell "that login wasn't me." Plus the modern piece: **shared signals** (CAEP/
> RISC) so a security event at the IdP reaches every downstream app in seconds,
> not at the next login.

**Time:** ~1.5h reading, ~1.5h lab, ~1h quiz.
**Prerequisites:** Modules 0–3 (you should know what a login, session, MFA change,
and password reset are — those are the events being logged and alerted on).

Every other module *does* things to accounts. This one is about **remembering**
them trustworthily and **telling the right people**. It's unglamorous and it's
what auditors, incident responders, and worried users all depend on.

---

## 1. Two records, two audiences

A security-relevant action produces **two** different outputs, and conflating
them is a common mistake:

| | Audit log | Security notification |
|---|---|---|
| **For** | you, security, compliance, investigators | the account owner |
| **Answers** | "what happened, exactly, and in what order?" | "was that you?" |
| **Shape** | append-only, complete, tamper-evident | timely, human-readable, actionable |
| **Example** | `seq 6: alice password_changed from 66.66.66.66` | "Your password was changed. Not you? Recover now." |

Look at any handler in [lab/events.go](lab/events.go): it performs the action,
**appends an audit event**, and **sends a notification**. Both, every time, for
anything security-relevant (login from new device, password change, MFA disabled,
email change, recovery).

---

## 2. The tamper-evident audit log

An audit log has one job under adversarial conditions: an attacker (or a rogue
insider) who gains database access must not be able to **quietly erase their
tracks**. A plain table fails this — anyone with `UPDATE`/`DELETE` rewrites
history and no one's the wiser.

The lab's fix is a **hash chain** (see [lab/audit.go](lab/audit.go)). Each row
stores `hash = sha256(its own fields ‖ prev_hash)`, where `prev_hash` is the
previous row's hash. This links every row to all of its predecessors:

```
seq1  hash1 = H(fields1 ‖ GENESIS)
seq2  hash2 = H(fields2 ‖ hash1)
seq3  hash3 = H(fields3 ‖ hash2)
             ▲
             └─ edit fields3, and hash3 no longer matches a recomputation,
                AND seq4's prev_hash no longer matches seq3 — the break is
                localized exactly at the tampered row.
```

`GET /audit/verify` walks the chain and recomputes every hash. Editing, deleting,
or reordering any past row makes it report `valid: false` and the **exact seq**
where the chain broke. The demo tampers with row 3 directly (as an insider
would), and verification catches it and points right at seq 3.

### What this does and doesn't give you

- **Detects** tampering after the fact — you'll know the log was altered and
  where. That's often enough: an attacker who can't alter the log *undetectably*
  can't hide.
- **Doesn't prevent** it, and a sufficiently capable attacker who controls the
  writer could recompute the whole chain forward. Production hardening layers on:
  writing to **append-only/WORM storage**, shipping to a **separate security
  system** (SIEM) the app can't rewrite, periodically **anchoring** the tip hash
  somewhere external (notarization), or signing each entry with a key the app
  server doesn't hold. The chain is the foundation those build on.

---

## 3. Security notifications — the user as a sensor

For account takeover, the account owner is frequently your best (sometimes only)
detector. A notification to their **existing, verified contact channel** is the
alarm. The rules the lab follows:

- **Notify on the events that matter:** new-device sign-in, password change, MFA
  disabled, email change, new recovery method. These are exactly the steps an
  attacker takes *after* getting in.
- **Send to the channel the attacker doesn't control.** A "password changed" alert
  goes to the current address, so even if an attacker changed it, the old owner
  hears (this ties back to Module 4's "notify the old email").
- **Make it actionable:** "wasn't you? → recover / review sessions," not just FYI.
- **New device is the highest-value one:** it's often the user's first sign their
  password leaked, before any damage. `handleLogin` tracks `known_devices` and
  fires only on genuinely new ones — so it's a signal, not spam.

Session inventory (`GET /sessions`) is the companion UI: "here's everywhere you're
logged in," so a user who gets a bad-news notification can see and (in a fuller
build) revoke the rogue session — the Module 3 mechanics, surfaced to the user.

---

## 4. Shared signals — CAEP / RISC

Here's the gap notifications and logs don't close. SSO (Module 2) issues a token
good for, say, an hour. Five minutes later the IdP disables the user — fired, or
detected as compromised. **Every relying party keeps honoring that token for the
other 55 minutes**, because access was decided once, at login, and never
re-evaluated.

The **OpenID Shared Signals Framework** — **CAEP** (Continuous Access Evaluation
Protocol) and **RISC** (Risk Incident Sharing and Coordination) — fixes this by
letting identity systems **push security events to each other in near-real-time**.
The IdP emits `session-revoked` / `credential-change` / `assurance-level-change`;
subscribed RPs receive it and revoke access on their side immediately. Access
becomes *continuous*, not frozen at login.

[lab/caep.go](lab/caep.go) models the emission side: `emitCAEP` publishes an event
to a feed a subscriber polls (`GET /caep/feed`). The password-change and
MFA-disable handlers emit the corresponding CAEP types. In real SSF each event is
a signed **Security Event Token** (SET, RFC 8417) pushed to registered receivers;
the lab keeps the vocabulary and the flow, drops the crypto plumbing.

The one-liner: **notifications tell the human; shared signals tell the other
machines** — and both beat waiting for the next login.

---

## Lab

Postgres (the hash-chained log + devices + sessions) and Mailpit (notifications
at http://localhost:8025). Users are bare ids (`alice`) mapped to
`alice@auth-lab.test` for delivery.

### Start it

```bash
cd 09-audit-security-events/lab
podman compose up --build       # -d to background
```

### The demo

```bash
./demo-audit.sh
```

It fires new-device / password-change / MFA-disable events (watch Mailpit),
prints the audit log, **verifies the hash chain (valid)**, tampers with a past
row, and **verifies again (broken, at the exact row)**, then shows the CAEP feed.

### Endpoints

| Method + path | Purpose |
|---|---|
| `POST /login` `{user,device}` | login; alerts + audits on a new device |
| `POST /password/change` `{user}` | audit + notify + CAEP `credential-change` |
| `POST /mfa/disable` `{user}` | audit + notify + CAEP `assurance-level-change` |
| `GET /audit` | the append-only log |
| `GET /audit/verify` | walk + recompute the hash chain |
| `POST /audit/tamper` `{seq,new_detail}` | **demo only** — edit a past row |
| `GET /sessions?user=` | session inventory |
| `GET /caep/feed` | shared-signal feed a downstream RP would consume |

### Exercises

1. **Watch the chain localize tampering.** Run the demo, then tamper with a
   *different* seq and re-verify — the `broken_at_seq` moves to match. Tamper with
   two rows; confirm it reports the *earliest* break (verification stops there).
2. **Try to tamper undetectably — and see why you can't (easily).** After editing
   row 3's `detail`, also try to "fix" its stored `hash` by hand. You'd have to
   recompute row 3's hash *and* row 4's `prev_hash` *and* row 4's hash *and* row
   5's… all the way to the tip. That cascade is the tamper-evidence.
3. **Notify only on genuinely new devices.** Confirm the second login from
   `laptop-1` sends no mail. Then add a *geo* to the event and alert on a new
   country even for a known device (the Module 8 signal, surfaced as a
   notification).
4. **Consume a CAEP signal.** Write a tiny second endpoint that, given the feed,
   "revokes" (deletes) all `sessions` for any subject with a `credential-change`
   event — i.e. act as a subscribed RP doing continuous evaluation.
5. **Move the log out of reach.** Argue where you'd ship these events so the app
   server can't rewrite them (SIEM, append-only bucket, a separate account), and
   what you'd anchor externally to detect a full-chain rewrite.

### Tear down

```bash
podman compose down -v
```

---

## Self-check quiz (10 questions)

<details>
<summary>1. Why are the audit log and the security notification two different things?</summary>

Different audiences and purposes. The audit log is a complete, ordered,
tamper-evident record for you/security/compliance and investigations. The
notification is a timely, human-readable, actionable alert to the account owner so
they can catch "that wasn't me." One is for reconstructing what happened; the other
is for stopping it in progress.
</details>

<details>
<summary>2. What does a hash chain give an audit log, mechanically?</summary>

Each row's hash covers its own contents plus the previous row's hash, linking all
rows. Editing, deleting, or reordering any past row makes its recomputed hash (and
the next row's prev-link) fail to match, so tampering is detectable and localized
to the exact row — you can't silently rewrite history.
</details>

<details>
<summary>3. Detect vs prevent — which does the hash chain do, and why does that matter?</summary>

It *detects* tampering after the fact; it doesn't by itself *prevent* it. That
still matters a lot: an attacker who can't alter the log undetectably can't hide
their tracks, which is the property investigations and compliance actually need.
Prevention comes from where you store it (append-only/WORM, a separate system),
layered on top.
</details>

<details>
<summary>4. A capable attacker controls the app server. How can they still beat the chain, and what stops them?</summary>

If they control the writer and the whole table, they can recompute every hash
forward from their edit, producing a valid-looking chain. Defenses: ship entries
to a separate system the app can't rewrite (SIEM), write to append-only/WORM
storage, sign entries with a key the app server doesn't hold, or periodically
anchor the tip hash somewhere external so a full rewrite is still detectable.
</details>

<details>
<summary>5. Why is "new device sign-in" the most valuable notification?</summary>

It often fires *before* any damage — a login from an unrecognized device is
frequently the first observable sign that the password has leaked, giving the user
a chance to react before the attacker changes anything. Later events (password
changed, MFA disabled) are alarms after the takeover is underway.
</details>

<details>
<summary>6. When an attacker changes the account email, where must the "email changed" notice go, and why?</summary>

To the *old* (previous) address. If it went only to the new address, the attacker
who just set it would be the sole recipient. The old address is the channel the
legitimate owner still controls, making the notice their one chance to catch the
change and revert it.
</details>

<details>
<summary>7. Why must new-device notifications fire only on genuinely new devices?</summary>

If every login alerted, users would be flooded and would learn to ignore the
alerts — so the one that actually matters (a real intruder's new device) gets
tuned out. Tracking known devices and alerting only on unseen ones keeps the signal
meaningful.
</details>

<details>
<summary>8. What problem do CAEP/RISC shared signals solve that notifications and logs don't?</summary>

The window between an access-affecting event and the next login. SSO tokens are
valid for their lifetime; if the IdP disables a user mid-session, relying parties
keep honoring the token until it expires. Shared signals push events
(session-revoked, credential-change) to RPs in near-real-time so they revoke access
immediately — continuous evaluation instead of decide-once-at-login.
</details>

<details>
<summary>9. Give two CAEP event types and what a receiver should do with each.</summary>

`session-revoked` → the RP terminates that subject's sessions/tokens immediately.
`credential-change` (or `assurance-level-change`) → the RP should re-evaluate: drop
elevated access, force re-authentication, or revoke tokens, because the subject's
authentication state changed under it. The receiver reacts rather than waiting for
the token to expire.
</details>

<details>
<summary>10. In one sentence: notifications vs shared signals.</summary>

Notifications alert the human account owner so a person can react; shared signals
(CAEP/RISC) alert the other machines/relying parties so systems can revoke access
automatically — both act on a security event immediately instead of waiting for the
next login.
</details>

---

## References

- [OpenID Shared Signals Framework (SSF)](https://openid.net/wg/sharedsignals/) — CAEP and RISC
- [CAEP specification & event types (openid.net)](https://openid.net/specs/openid-caep-specification-1_0.html)
- [RFC 8417 — Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) and [OWASP Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)
- [NIST SP 800-92 — Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
