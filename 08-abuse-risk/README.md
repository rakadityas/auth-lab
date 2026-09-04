# Module 8 — Abuse, Risk & Adaptive Authentication

> Module 0 stopped one attacker guessing one account. This module stops the
> attack that actually empties real products: **credential stuffing** — millions
> of leaked `email:password` pairs sprayed one-try-each across a botnet. The tool
> is **risk-based (adaptive) auth**: score every login from many signals and vary
> the response — let most people straight through, challenge the suspicious, block
> the abusive — instead of one rule for everyone.

**Time:** ~1.5h reading, ~1.5h lab, ~1h quiz.
**Prerequisites:** Module 0 (throttling vs lockout, breached-password checking),
Module 3 (MFA — step-up is the "challenge" tier here).

Every prior module assumed the person logging in is the account owner and asked
"do they have the right secret?" Attackers don't play that game one account at a
time. They arrive with valid-*somewhere* credentials at massive scale and let
password reuse do the work. Defeating that isn't a better password check — it's
reading the **context** of each attempt.

### ELI5 — in simple words

**The attack.** Some other website got hacked, and a list of a million
`email + password` pairs is now for sale. Many people reuse the same password
everywhere. So the attacker simply **tries each pair on your site, one time each**.

Why do the old defenses fail here?

> Module 0 said: *"block an account after 5 wrong tries."*
> But the attacker only tries **once per account**. He never reaches 5. He just
> has a million accounts. Even if only 0.5% work, that is 5,000 stolen accounts.

**The clue that catches him.** Look at one account and you see nothing strange.
But step back and look at the whole picture:

> *One computer just tried 25 **different** accounts in two minutes.*

A real person does not do that. That pattern is the fingerprint of the attack —
and you can only see it if you look **across** accounts, not at one account.

**The solution: judge the situation, not just the password.**
Collect small clues and add up points:

| Clue | Points |
|---|---|
| This computer touched 20+ different accounts | +60 |
| We have never seen this device before | +25 |
| Login from a different country than last time | +30 |
| This password appears in a known leaked list | +20 |

Then act based on the total:

- **Low score → just let them in.** No annoyance. This must be most people!
- **Medium score → ask for a code (MFA).** "Your password is right, but this
  looks unusual — prove it's really you."
- **High score → refuse.**

The beauty: the attacker's robot gets blocked, while a normal person on their
usual laptop notices **nothing at all**. And once you pass a check on a new
device, we remember that device, so you are not asked again.

---

## 1. The attack: credential stuffing (and why Module 0 misses it)

Module 0's defenses were **per-account**: throttle failures against *this* email,
delay every response so timing doesn't leak. Against stuffing they do almost
nothing, because stuffing is **per-account-shallow, cross-account-wide**:

- The attacker has a breach dump: `alice@… / hunter2`, `bob@… / letmein`, … —
  millions of pairs, each a password the user *actually used somewhere*.
- They try **one password per account** (the one from the dump). Per-account
  throttling never trips — there's only one attempt per account.
- They spread it across a botnet, so per-IP rate limits on a single address don't
  catch a distributed spray either.
- Even a 0.5% success rate against a million accounts is 5,000 takeovers.

The signal Module 0 can't see: **one origin touching enormous numbers of distinct
accounts with a low success rate.** That pattern — not any single account's
failures — is the fingerprint of stuffing, and reading it needs cross-account,
cross-request state.

---

## 2. Risk-based auth: many weak signals → one score → three outcomes

The engine is in [lab/risk.go](lab/risk.go). Each login attempt carries context
(IP, device, geolocation, the password itself); each **signal** contributes
points; the total maps to a decision. No single signal is trusted alone — that's
the design. A new device is normal (people get new phones); a new device **plus** a
new country **plus** a breached password **plus** an IP hammering 20 accounts is
not.

The signals this lab scores:

| Signal | Why it matters | Points |
|---|---|---|
| **IP velocity** — distinct accounts one IP has hit recently | the core stuffing tell | up to 60 |
| **IP failure rate** — recent failed logins from the IP | stuffing has low success | up to 25 |
| **Unknown / absent device** — never seen for this account | new device = higher risk | 20–25 |
| **New geolocation** — country differs from last login | account sharing / travel / theft | 30 |
| **Breached password** — appears in a known dump | it's *where stuffing lists come from* | 20 |

And the three outcomes — the heart of *adaptive* auth (`decide`):

- **allow** (low score): straight through, **zero friction**. This must be the
  overwhelming majority path or you've built a system users hate.
- **step_up** (medium): the credentials were fine, but the context is off —
  demand a second factor (Module 3) *before* issuing a session. Friction applied
  **only where risk warrants it**.
- **deny** (high): refuse. Return a generic "unusual activity" message — don't
  tell the attacker which signal tripped, or they'll tune around it.

The demo shows one identity, one password, getting all three answers depending
only on context — and a 25-account stuffing burst getting walled off while a
returning user on a known device never feels a thing.

---

## 3. The device-trust loop (getting friction right)

Adaptive auth is only worth it if real users rarely see the friction. The
mechanism: **learn trust from success.** A clean login (`allow`) records the
device and geolocation as known (`recordAttempt`). Next time from that
device+location, those signals score zero and the user sails through.

One subtlety the lab enforces, and Exercise 3 makes you break: **trust is earned
only by a fully completed login** — a clean `allow`, or a step-up whose MFA was
actually completed (`handleMFA`). Merely *triggering* a step-up must **not** mark
the device trusted, or an attacker who trips the challenge and walks away has
silently whitelisted their device. (This was a real bug during this lab's
construction; the fix is the `trusted` flag being gated on `outcome == "allow"`.)

So the user's lifetime looks like: first login anywhere → mild friction (step-up)
→ complete it once → trusted forever on that device. Attackers, arriving on fresh
devices from bad IPs with breached passwords, stay permanently in the high-risk
lane.

---

## 4. Beyond this lab (name these in an interview)

- **Bot defense / proof-of-work / CAPTCHA** as a *step-up tier* below MFA: make
  automated attempts expensive without annoying humans. Invisible challenges
  (device attestation, behavioral signals) first; visible CAPTCHA last.
- **Device fingerprinting** beyond a cookie: TLS/JA3, canvas, header order — used
  to recognize a device that's clearing cookies. Privacy-fraught; regulated.
- **Impossible travel** done properly: not just "new country" but "two logins too
  far apart in space for the time between them."
- **Breached-credential response runbook:** when *your* users appear in a new
  dump, proactively force-reset or flag them (this is the account-side of Module
  0's HIBP check, at population scale).
- **ML risk scoring:** the weights here are hand-set; mature systems learn them
  from labeled fraud outcomes. The *architecture* — signals → score → adaptive
  response — is identical; only the scoring function changes.
- **Feedback from downstream fraud:** a login that later turns out fraudulent
  should retro-train the score. Auth risk and payment/abuse fraud are one system.

---

## Lab

Go + Redis (Redis holds the cross-request counters: per-IP account sets, failure
counters, per-account known-device sets and last-geo).

Password verification is deliberately trivial (any non-empty password clears the
credential step) so the lab **isolates the risk decision** — in production this
engine wraps a real password check from the earlier modules.

### Start it

```bash
cd 08-abuse-risk/lab
podman compose up --build       # -d to background
```

### The demo

```bash
./demo-risk.sh
```

It walks all three outcomes for one user, then fires a 25-account stuffing burst
from one IP and watches it get denied — while the legitimate user is unaffected.

### Signals are driven by headers (so you can steer each one)

```bash
curl -s -X POST localhost:8080/login \
  -H 'X-Forwarded-For: 6.6.6.6' \    # source IP (spoof to simulate a botnet)
  -H 'X-Device: my-laptop' \          # device id (a "device cookie")
  -H 'X-Geo: US' \                    # geolocation (stands in for IP-geo)
  -d '{"email":"alice@corp.com","password":"hunter2"}' | jq
```

| Method + path | Purpose |
|---|---|
| `POST /login` | adaptive login → allow / mfa_required / blocked |
| `POST /mfa` | complete a step-up (any 6-digit code passes) → trusts the device |
| `GET /risk?email=` | score a context without logging in (introspection) |
| `POST /admin/reset` | flush counters between demo runs |

### Exercises

1. **Make stuffing succeed, then defeat it.** Lower the `ip_velocity` thresholds
   in `score` to huge numbers (effectively off) and re-run the stuffing burst —
   every attempt now `allow`s. That's an undefended system. Restore the thresholds
   and watch the same burst get denied. The whole defense is that one cross-account
   signal.
2. **Tune the friction/security trade.** Move the `step_up` threshold from 30 to
   50. Fewer users get challenged (happier) but more risky logins slip to `allow`
   (less safe). Find where you'd set it and justify it — this is the core product
   tension of adaptive auth.
3. **Reproduce the trust-leak bug.** In `handleLogin`, change `trusted` to
   `credentialOK && d.Outcome != "deny"` (so step-up counts as trusted). Trigger a
   step-up for a new device but **don't** complete MFA, then log in again from that
   device — it's now `allow`ed without ever proving the second factor. Revert and
   explain why trust must require a completed authentication.
4. **Add an impossible-travel signal.** Store a timestamp with the last geo and
   score higher when the country changes within, say, 60 minutes (physically
   impossible) than when it changes after a week (plausible travel).
5. **Add a per-account velocity signal.** One account being tried from many
   different IPs quickly is *targeted* takeover (vs stuffing's one-IP-many-accounts).
   Score it. Note it's the transpose of signal 1.

### Tear down

```bash
podman compose down -v
```

---

## Self-check quiz (10 questions)

<details>
<summary>1. Why do Module 0's per-account defenses miss credential stuffing?</summary>

They react to repeated failures against a single account. Stuffing makes one
attempt per account (the password from a breach dump), across millions of
accounts, from many IPs — so no single account sees repeated failures and no
single IP looks like classic brute force. The attack is wide and shallow; the
per-account view is narrow and deep, so they don't overlap.
</details>

<details>
<summary>2. What single signal best distinguishes stuffing, and why?</summary>

The number of *distinct accounts* one origin (IP/ASN/fingerprint) attempts in a
short window. Legitimate traffic from one source touches few accounts; a stuffing
bot walks a list, hitting many. Combined with a low success rate, it's the
signature the per-account view can't see.
</details>

<details>
<summary>3. What is adaptive (risk-based) authentication in one sentence?</summary>

Instead of one fixed login policy, you score each attempt from contextual signals
and vary the response — allow low-risk logins with no friction, challenge
medium-risk ones with step-up, and block high-risk ones — so security scales with
risk rather than punishing everyone equally.
</details>

<details>
<summary>4. Why sum many weak signals instead of acting on any one?</summary>

Individually the signals have high false-positive rates — a new device or a new
country is completely normal for real users, so blocking on it alone would lock
out legitimate people constantly. Combining them means friction is applied only
when several independent indicators agree, which is where genuine risk actually
concentrates.
</details>

<details>
<summary>5. Why is "step-up" a distinct outcome rather than folding into allow/deny?</summary>

Because the right answer to medium risk is neither "let them in" (unsafe) nor
"block them" (blocks real users whose credentials were correct). Step-up resolves
the uncertainty: the credentials were right but the context is odd, so prove a
second factor. It converts a risky-but-possibly-legitimate attempt into a safe
one without a false rejection.
</details>

<details>
<summary>6. Why must a denied login return a generic message?</summary>

A specific message ("blocked: too many accounts from your IP", "unrecognized
device") tells the attacker exactly which signal tripped, so they tune around it —
rotate IPs, replay a stolen device id, slow down. A generic "unusual activity"
denies them that feedback loop.
</details>

<details>
<summary>7. How does the system keep friction low for real users over time?</summary>

It learns trust from successful logins: a clean login records the device and
geolocation as known, so those signals score zero next time and the user passes
without a challenge. Friction is a one-time cost per new device, not a recurring
tax.
</details>

<details>
<summary>8. Why must triggering a step-up NOT, by itself, trust the device?</summary>

If merely reaching the step-up tier marked the device trusted, an attacker with
correct credentials could trip the challenge, abandon it, and have whitelisted
their device for future no-friction logins — bypassing the second factor entirely.
Trust must be earned only by a *completed* authentication (a clean allow or a
passed MFA), never by an incomplete one.
</details>

<details>
<summary>9. Why is a breached password a useful risk signal specifically for stuffing?</summary>

Stuffing lists are *built from* breach corpora — the passwords being tried are, by
definition, breached ones. So a login presenting a password known to be in a dump
is disproportionately likely to be a stuffing attempt rather than a legitimate
user (who ideally isn't reusing a breached password). It corroborates the other
signals.
</details>

<details>
<summary>10. Where do the hand-tuned weights in this lab differ from production, and where are they the same?</summary>

Production systems typically *learn* the weights (and interactions) from labeled
fraud outcomes, often with ML, and retro-train from downstream fraud signals. What
stays identical is the architecture: collect contextual signals, combine them into
a risk score, and map that score to an adaptive response. Only the scoring function
gets smarter; the shape doesn't change.
</details>

---

## References

- [OWASP — Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [OWASP Automated Threats to Web Applications (OAT-008 Credential Stuffing)](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [NIST SP 800-63B §5.2.2 — throttling and rate limiting](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Have I Been Pwned — Pwned Passwords (k-anonymity range API)](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [Google — reCAPTCHA / risk analysis](https://developers.google.com/recaptcha) and vendor write-ups on device fingerprinting (JA3/JA4)
