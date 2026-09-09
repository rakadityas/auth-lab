# Module 7 — Multi-Tenancy, B2B Organizations & SCIM

> The jump from "an app with users" to "an app enterprises buy." Now users belong
> to **organizations**, each org brings its **own SSO**, and — the part teams
> forget until an auditor asks — the enterprise expects to **deprovision** people
> centrally. This module builds tenant isolation, org-scoped roles, invitations,
> per-tenant SSO with JIT, and SCIM, and shows the incident class that appears
> when you do the first half without the second.

**Time:** ~2h reading, ~2h lab, ~1h quiz.
**Prerequisites:** Module 4 (user/identity model, token pattern), Module 5
(authorization — you'll see roles go from global to org-scoped). Module 2 (SSO/
OIDC) is helpful background for the SSO section.

Everything before this had one flat set of users. B2B SaaS doesn't work that way:
Acme and Beta are separate customers on one deployment, and the entire job is
making sure Acme never sees Beta's data while each runs its own identity policy.

### ELI5 — in simple words

Until now, your app was **one house with many people**. Now it is **one big
office building with many companies inside**. Acme is on floor 3, Beta is on
floor 5. They share the building, but they must **never** see each other's files.

Three new ideas:

**1. Which company are you in right now?**
A person is not just "an admin". They are "an admin **of Acme**". The same person
might be a normal member at Beta, and a total stranger at Gamma. So permission
always belongs to the pair *(person + company)*, never to the person alone.

**2. The one rule you must never break.**
Every single database question must include *"...and only for this company"*:

```sql
SELECT * FROM projects WHERE org_id = <the company we verified>
```

Forget those last few words **one time**, and Acme can read Beta's files. This is
the most common and most serious bug in this kind of system. In the lab you will
delete those words on purpose, see the leak, and put them back.

**3. Getting people IN is easy. Getting people OUT is the part everyone forgets.**

A company connects their own login system (their SSO). Employees log in happily.
Then an employee is **fired**. IT disables them in the company's system... and
your app never finds out! Why? Because your app only talks to their login system
*when someone tries to log in*. The fired person's access just sits there, alive.

This is a real and common security incident, called *"SSO works but offboarding
doesn't."*

The fix is **SCIM**: the company's system actively *pushes* messages to your app —
"add this person", "**this person is disabled now**". You will watch a user get
provisioned, use the app, then get switched off and be blocked on his very next
click.

---

## 1. The tenant model

Three tables carry it (see [lab/schema.sql](lab/schema.sql)):

```
  "alice is an admin" is not a fact. "alice is an admin OF ACME" is.

     users (one row per human, globally)
       alice ──┬────────────────────┬──────────────────┐
               │                    │                  │
        memberships row      memberships row      (no row)
        org: Acme            org: Beta                 │
        role: admin          role: member              ▼
        active: true         active: true         Gamma: 403.
               │                    │             not "no access to
               ▼                    ▼             this project" —
     ┌── organizations ──┐  ┌──────────────┐      she does not exist
     │ Acme              │  │ Beta         │      here at all.
     │  projects, data,  │  │  projects,   │
     │  SCIM token, SSO  │  │  data, …     │
     └───────────────────┘  └──────────────┘
        the isolation boundary. nothing crosses it.

  Every query, without exception:

     request ──► who are you?  ──► which org?  ──► active membership there?
                                        │                   │ no ──► 403
                                        ▼ yes
              SELECT … WHERE org_id = tc.orgID   ◄── from the VERIFIED context
                                   ▲
                                   └── never from the request body. a client
                                       sending {"org_id": "<Beta>"} is ignored.

     forget that WHERE clause once  ──►  cross-tenant data leak.
     defense in depth: Postgres row-level security makes a forgotten
     clause fail CLOSED instead of leaking.
```


- **`organizations`** — the tenants. Each is an isolation boundary.
- **`users`** — one row per human, globally. A user can belong to several orgs
  (a contractor, an agency, someone with a personal + work account).
- **`memberships`** — the join, and the heart of the model:
  `(org_id, user_id, role, active, source)`. A user's rights are **always** a
  property of the *membership*, never of the user alone.

That last point is the whole design. "alice is an admin" is meaningless; "alice is
an admin **of Acme**" is the fact. The same person is an admin of Acme, a member
of Beta, and nothing in Gamma — three membership rows, three different answers.

---

## 2. Tenant isolation — the boundary you must never cross

Every request answers two questions before touching data: *who are you* (auth,
prior modules) and *which tenant are you acting in*. `tenantScoped` in
[lab/tenant.go](lab/tenant.go) resolves both into a `tenantContext{userID, orgID,
role}` by looking up an **active membership** — and rejects anyone without one.

Then the ironclad rule for every query in a multi-tenant system:

> **Every statement is filtered by the resolved `org_id`, and the `org_id` comes
> from the verified context — never from the request body or a client-supplied
> parameter.**

Look at `handleCreateProject`: the insert's `org_id` is `tc.orgID`, not a field
the caller sent. A client that puts `"org_id": "<Beta's id>"` in its JSON can't
write into Beta, because that field is ignored. And `handleListProjects` has
`WHERE org_id = $1`. Omit that clause **one time** and you've built a cross-tenant
data leak — the single most common and most serious multi-tenancy bug. The demo
shows alice, a real Acme admin, getting nothing but a 403 when she aims `X-Org` at
Beta.

Defense in depth beyond the app layer (not in this lab, worth knowing): Postgres
**row-level security** policies that enforce `org_id = current_setting('app.org')`
in the database itself, so a forgotten `WHERE` fails closed rather than leaking.

### Roles are now org-scoped

In Module 5, a role was global. Here `memberships.role` is per-org. `tenantAdmin`
requires the `admin` role **in the org of the request** — so bob, a mere member of
Acme, is refused when he tries to invite someone, even though he'd be an admin if
he held that role in some other org. Same user, different org, different answer.

---

## 3. Getting users in

Two paths, because enterprises use both:

### Invitations (the self-serve path)

An admin invites by email; the invitee gets a single-use, expiring, **hashed**
token (the exact Module 4 pattern) and accepting it creates their membership. See
`handleInvite` / `handleAcceptInvite`.

### Enterprise SSO + home-realm discovery + JIT

The enterprise path is three ideas stacked:

- **Per-tenant SSO connection** — each org registers its IdP and the email
  **domain** it owns (`sso_connections`). Acme owns `acme.com`.
- **Home-realm discovery** — the user types their email on one generic login box;
  the domain decides which IdP to send them to. Nobody picks "which company am I"
  from a dropdown. `GET /sso/discover?email=alice@acme.com` → Acme's Okta.
- **JIT (just-in-time) provisioning** — the *first* time someone from `acme.com`
  logs in via Acme's SSO, their membership is created on the spot. No admin has to
  pre-add every employee; the IdP having authenticated them is enough (the org
  opted in with `jit_enabled`). See `handleSSOCallback`.

JIT is why an enterprise rollout doesn't require importing a staff list up front —
but it also means access is granted by *whoever the IdP will authenticate for that
domain*, which is exactly why the **off**-boarding side has to be just as
automatic.

---

## 4. Getting users out — SCIM, and the incident class

Here's the failure that shows up in real postmortems: a company buys your product,
wires up SSO, everyone logs in happily. An employee is fired. IT disables them in
the corporate IdP and moves on. **But your app never heard about it** — SSO only
runs when someone *tries* to log in, and a fired employee's existing sessions,
API tokens, and membership just… persist. "SSO works but offboarding doesn't."

```
  "SSO works but offboarding doesn't" — the incident, drawn:

   WITHOUT SCIM
     Acme fires frank ──► IT disables him in Okta ──► ✔ done, they think
                                                          │
     your app: never told. SSO only runs at LOGIN, and frank
     doesn't need to log in — he already has:
        · a live session cookie          ──► still works
        · an API token                   ──► still works
        · an active membership row       ──► still works
     ...for as long as your session TTL, which may be weeks.

   WITH SCIM  (the IdP pushes lifecycle INTO your app)
     Okta ── PATCH /scim/v2/Users/frank {active:false} ──► your app
                    │ bearer token = Acme's SCIM token
                    │ so it can only ever touch Acme's rows
                    ▼
     memberships(Acme, frank).active = false
                    │
                    ▼
     the very NEXT request: tenantScoped finds no active membership ──► 403

   two rules that keep it correct:
     · deactivate the MEMBERSHIP, not the human — frank's Beta membership
       and his global user row are none of Acme's business
     · SSO must not silently re-activate him on his next login, or you
       just reopened the door you closed
```

**SCIM 2.0** (RFC 7643/7644) closes the gap: a standard REST API the IdP calls to
push user lifecycle *into* your app, proactively.

- **Provision:** `POST /scim/v2/Users` creates the user + an active membership.
- **Deprovision:** `PATCH /scim/v2/Users/{id}` with `active: false` — the signal
  Okta/Entra send when someone is offboarded. `handleSCIMPatch` flips the
  membership inactive, and `tenantScoped` blocks them on the **very next request**.
- **Hard remove:** `DELETE /scim/v2/Users/{id}` drops the membership entirely.

Two details the lab makes concrete:

- **SCIM is org-scoped by its bearer token.** Each org's IdP presents a per-tenant
  token (`scim_tokens`); `scimAuth` pins every SCIM call to that token's org.
  Acme's token cannot touch Beta's users — SCIM respects the same tenant boundary
  as the app.
- **Deactivate the membership, don't delete the human.** Frank leaving Acme must
  not nuke his Beta membership or his global user row. Offboarding is scoped to
  the org that offboarded him. And SSO must **not** silently resurrect a
  deactivated membership on the next login — `handleSSOCallback` refuses, or you've
  reopened the door you just closed.

---

## Lab

Postgres + the Go app (invitation emails would go to Mailpit in a fuller build;
the demo returns invite tokens directly for scriptability). Seeded world:

```
orgs:     Acme (acme.com, SSO+JIT, SCIM enabled)      Beta (separate tenant)
users:    alice@acme.com  — admin of Acme             carol@beta.com — admin of Beta
          bob@acme.com    — member of Acme
projects: "Acme Roadmap" (Acme)                       "Beta Secrets" (Beta)
```

### Start it

```bash
cd 07-multitenancy-scim/lab
podman compose up --build       # -d to background
```

### The two demos

```bash
./demo-tenancy.sh            # isolation, org-scoped roles, invite, discovery, JIT
./demo-scim-offboarding.sh   # provision -> access -> PATCH active=false -> access cut
```

Watch for the two moments that are the whole module: alice (a legitimate Acme
admin) getting **403** when she aims at Beta, and frank getting cut off **on his
next request** the instant SCIM deactivates him.

### Endpoints

| Method + path | Auth | Purpose |
|---|---|---|
| `GET/POST /projects` | `X-User` + `X-Org` (active member) | tenant-scoped data |
| `GET /members` | active member | list the org's members |
| `POST /invitations` | org **admin** | invite by email |
| `POST /invitations/accept` | token | join an org |
| `GET /sso/discover?email=` | none | home-realm discovery |
| `POST /sso/callback` | (fake assertion) | SSO login + JIT |
| `POST/GET /scim/v2/Users` | `Bearer` SCIM token | provision / list |
| `PATCH/DELETE /scim/v2/Users/{id}` | `Bearer` SCIM token | deprovision |

`X-User`/`X-Org` stand in for a verified session + selected tenant; the SCIM
bearer token stands in for the IdP's credential.

### Exercises

1. **Build the leak, then fix it.** In `handleListProjects`, delete the
   `WHERE org_id = $1`. Rebuild and call `/projects` as alice — she now sees
   *Beta Secrets* too. This is the cross-tenant leak in three deleted words. Put
   it back and internalize why every multi-tenant query needs it.
2. **Block the body-injection variant.** Try to make `handleCreateProject` trust
   an `org_id` from the JSON body instead of `tc.orgID`, then have alice create a
   project "in" Beta. Confirm it works (the bug) — then revert and explain why the
   tenant id must always come from the verified context.
3. **Turn JIT off.** Set `jit_enabled = false` for Acme
   (`UPDATE sso_connections …`), then SSO-login a brand-new `acme.com` address.
   It's refused — now membership requires an explicit invite. Discuss the
   security/convenience trade.
4. **Prove the offboarding gap, then close it.** Comment out the `!active` refusal
   in `handleSSOCallback`, deactivate frank via SCIM, then SSO him back in — watch
   SSO silently un-revoke him. That's the bug. Restore the check.
5. **Add SCIM Groups → roles.** SCIM also syncs group membership. Add
   `/scim/v2/Groups` handling that maps an IdP group (e.g. "Admins") to the
   `admin` role on the membership. Now role changes flow from the IdP too.

### Tear down

```bash
podman compose down -v
```

---

## Self-check quiz (10 questions)

<details>
<summary>1. Why do rights live on the membership, not the user?</summary>

Because one human can belong to many organizations with different rights in each
(admin of Acme, member of Beta, nothing in Gamma). Attaching a role to the user
globally can't express that; attaching it to the `(user, org)` membership can. The
membership is the unit of "what may this person do *here*."
</details>

<details>
<summary>2. State the one rule that prevents cross-tenant data leaks.</summary>

Every query is filtered by an `org_id` that comes from the server-verified request
context (the resolved membership), never from client input. Miss the filter on one
query, or trust a client-supplied org id, and one tenant can read or write
another's data.
</details>

<details>
<summary>3. Why must a handler take org_id from the context, not the request body?</summary>

If the tenant id is a body/parameter the client controls, a caller can name
another org's id and operate inside it (read its rows, insert into it). Deriving
org_id from the verified membership means the client can only ever act within an
org it actually belongs to — the boundary can't be argued around.
</details>

<details>
<summary>4. What is home-realm discovery and what problem does it solve?</summary>

Routing a login to the right IdP based on the user's email domain (acme.com →
Acme's Okta). It solves the "which of our hundreds of enterprise customers are
you?" problem without making the user pick their company from a list — they just
type their email and are sent to their own SSO.
</details>

<details>
<summary>5. What does JIT provisioning do, and what's the risk of enabling it?</summary>

On a user's first successful SSO login, it auto-creates their membership rather
than requiring an admin to pre-add them. The risk: access is then granted to
anyone the org's IdP will authenticate for that domain, so a misconfigured or
over-broad IdP directly becomes over-broad access — and it makes automatic
*de*-provisioning (SCIM) essential, since you're no longer curating the member
list by hand.
</details>

<details>
<summary>6. Describe the "SSO works but offboarding doesn't" incident.</summary>

A company sets up SSO; users log in fine. An employee is terminated and disabled
in the corporate IdP — but the app only consults the IdP at login time, so the
ex-employee's existing membership, sessions, and tokens persist. Nothing told the
app to revoke them. Access lingers after departure. SCIM (push deprovisioning) is
what closes it.
</details>

<details>
<summary>7. How does SCIM deprovisioning cut access, and how fast?</summary>

The IdP sends `PATCH /scim/v2/Users/{id}` with `active: false`; the app flips the
membership's `active` flag. The per-request membership check (`tenantScoped`) then
refuses the user on their very next request. It's immediate for anything that
re-checks membership per request; long-lived sessions/tokens need their own
revocation (Module 3) to be equally prompt.
</details>

<details>
<summary>8. Why deactivate the membership instead of deleting the user on offboarding?</summary>

The user is one human who may belong to several orgs; deleting the user row would
revoke their access everywhere and destroy history. Offboarding is scoped to the
org that did it, so you deactivate (or delete) only that *membership*. Their other
memberships and their global identity are untouched.
</details>

<details>
<summary>9. Why must SSO refuse to log in a deactivated membership?</summary>

Because if SSO auto-reactivates on login (or JIT re-creates the membership), a
just-offboarded user logs straight back in and the deprovisioning is undone. The
SSO callback has to treat a deactivated membership as revoked and refuse, rather
than resurrect it.
</details>

<details>
<summary>10. How is SCIM itself scoped to a tenant?</summary>

Each org's IdP authenticates to the SCIM API with a per-org bearer token; the
server maps the token to exactly one org and pins every operation to it. Acme's
SCIM token can only create/modify/list Acme's members — SCIM respects the same
tenant isolation as the application API.
</details>

---

## References

- [SCIM 2.0 — RFC 7644 (Protocol)](https://datatracker.ietf.org/doc/html/rfc7644) and [RFC 7643 (Core Schema)](https://datatracker.ietf.org/doc/html/rfc7643)
- [WorkOS / Okta docs on SCIM provisioning and deprovisioning](https://www.okta.com/blog/2020/03/scim-a-primer-on-the-system-for-cross-domain-identity-management/) (vendor-neutral primer)
- [Postgres Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) — enforcing tenant isolation in the database
- [OWASP — Multi-tenancy / Broken Access Control (A01:2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [Home-realm discovery — Microsoft Entra docs](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/home-realm-discovery-policy)
