# Module 5 — Authorization in Practice: RBAC → ReBAC

> Module 0 *named* the authorization models in one paragraph. This module makes
> you **build two of them** over the same domain and feel exactly where the
> simple one breaks — because "why can this user do that?" is the question an
> identity team answers all day, and the wrong data model makes it unanswerable.

**Time:** ~2h reading, ~2h lab, ~1h quiz.
**Prerequisites:** Module 0 (you should recall AuthN vs AuthZ and that RBAC/ABAC/
ReBAC exist). No prior authorization-systems knowledge assumed.

Authentication asks *who are you*; authorization asks *what may you do*. Every
module so far was about the first. This is the second — and it's where a lot of
real breaches live, because a bug here doesn't crash, it silently says "allow."

The lab runs **one document API** against **two interchangeable engines**. You
send the identical request and watch the answer differ.

### ELI5 — in simple words

You are inside the building. Now: **which rooms can you enter?**

There are two ways to decide.

**Way 1 — RBAC ("what is your job title?")**

> Bob is an "editor". Editors can edit. So Bob can edit.

Simple and fast. But notice the problem: it never asks **edit *what*?** Bob is an
editor of *everything* — including the secret document nobody ever gave him.
Real life is not like that. Real life says "Bob can edit *this* folder."

**Way 2 — ReBAC ("how are you connected to this thing?")**

Instead of job titles, we store simple facts about relationships:

```
carol is a viewer of  README
README lives inside   folder "Engineering"
bob    is an editor of folder "Engineering"
dave   is a member of  group "staff"
staff  can view        README
```

Now to answer "can Bob edit README?" we **follow the connections**: Bob edits the
Engineering folder → README is inside that folder → so yes, Bob can edit README.
But the secret document is not in that folder, so Bob is refused. Correct!

This is how Google does it internally (a system called **Zanzibar**). Three nice
things come free: giving one person access to one file, inheriting access from a
folder, and giving access to a whole group.

**The third lesson: where do you put the check?**
Put it in **one place** that every request must pass through (like a single guard
at one door), not scattered in fifty different places. If you sprinkle checks
everywhere, one day someone forgets one — and that forgotten spot is the breach.

---

## 1. RBAC — roles carry permissions

The workhorse model. Three tables:

```
user_roles:        alice → admin        role_permissions:  admin  → {read,write,delete}
                   bob   → editor                          editor → {read,write}
                   carol → viewer                          viewer → {read}
```

"May bob write?" is one join: *does bob hold any role that grants `doc:write`?*
See `rbacAllows` in [lab/policy.go](lab/policy.go) — a single `EXISTS`.

RBAC is fast, comprehensible, and auditable ("show me everyone with the `admin`
role"). It is the right default for a huge fraction of systems. But look closely
at what the permission is attached to: **the role, globally.** There is no object
in the query. `bob` the editor may write *every* document in the system, because
"editor" doesn't mean "editor of X" — it means "editor, everywhere."

```
  RBAC asks about the PERSON.  ReBAC asks about the PERSON *and* the THING.

  RBAC                                ReBAC (Zanzibar-style)
  ────                                ──────────────────────
    bob ──► editor ──► {read,write}     folder:eng
                                          │ parent
    "may bob write?"                      ▼
        one join. no document              document:readme
        appears in the question              ▲          ▲
                                     viewer  │          │ viewer
    so bob may write                    user:carol   group:staff#member
    EVERY document                                        ▲
    that exists.                                          │ member
        └── "editor" means                            user:dave
            editor of the world
                                     "may bob write readme?"
                                        walk the graph: readme's parent is
                                        eng, bob edits eng → yes, inherited

  RBAC runs out the moment someone says any of these out loud:
     "editor on THIS doc, not that one"      "share this one file with one
     "whoever owns the folder owns the        outside person"
      files inside it"                       "everyone in the staff group"
```

### Where RBAC runs out

The moment a requirement says *"editor on this document but not that one,"* or
*"whoever owns a folder can edit the files inside it,"* or *"share this one doc
with one external user,"* pure global RBAC can't say it. The usual patches:

- **Scoped roles** — `user_roles(user, role, scope)` where scope is a tenant,
  project, or object. This works and is common; it's RBAC creeping toward
  relationships. It handles "editor of project X" but gets awkward at
  "inheritance" (folder → file) and "groups of groups."
- **ABAC (attribute-based)** — decisions from attributes + a policy language
  (user.dept == doc.dept). Flexible, but "why was this allowed?" becomes hard to
  answer and per-object sharing still doesn't fit naturally.

When the relationships between objects *are* the access rules — owners, parents,
groups, sharing — you want a model whose primitive is the relationship itself.

---

## 2. ReBAC — permissions derived from relationships (Zanzibar)

This is the model behind Google's internal authorization system **Zanzibar**, and
the open-source engines that copy it: **SpiceDB, OpenFGA, Ory Keto**. One idea:
store **relation tuples** and *derive* permissions from them with a graph walk.

A tuple reads `object#relation@subject`:

```
document:readme#viewer@user:carol           carol is a viewer of readme
document:readme#parent@folder:eng           readme's parent is folder eng
folder:eng#editor@user:bob                   bob is an editor of folder eng
document:readme#viewer@group:staff#member    every MEMBER of staff may view readme
group:staff#member@user:dave                 dave is a member of staff
```

Everything is that one shape (see the single `relation_tuples` table in
[lab/schema.sql](lab/schema.sql)). Permissions are **rules over relations**, in
[lab/policy.go](lab/policy.go):

```
doc:read   := viewer ∪ editor ∪ owner
doc:write   := editor ∪ owner
doc:delete  := owner
viewer/editor/owner := direct tuples  ∪  same relation on the PARENT folder (inherited)
```

Three things fall out of the same machinery, none needing a schema change:

- **Per-object grants.** `document:secret#owner@user:alice` grants on *that one
  document*. RBAC's global roles can't express this without a scope column.
- **Inheritance.** `readme` has a `parent` tuple pointing at folder `eng`; bob
  edits `eng`, so the check *recurses up* and bob inherits editor on `readme` —
  but **not** on the root-level `secret`, which has no such parent. Access follows
  the object graph.
- **Groups (usersets).** `…@group:staff#member` means "everyone with `member` on
  `group:staff`." The check recurses into that relation, so adding dave to staff
  grants him everything staff can reach. Groups-of-groups just works by recursion.

### The `check` primitive

`check(object, relation, subject)` in [lab/policy.go](lab/policy.go) is the heart
of Zanzibar. For each tuple on `(object, relation)` it handles three cases:

1. **direct** — `@user:alice`: does it name our subject? Hit.
2. **userset** — `@group:staff#member`: recurse — does the subject have `member`
   on `group:staff`?
3. **computed/inherited** — for a document/folder, also check the same relation on
   its parent folder, recursing up the tree.

A `seen` set guards against cycles. This is a naive, readable version; production
engines add caching, a consistency token (Zanzibar's "zookie"), and reverse
indexes for "list all documents alice can read." The *model* is exactly this.

---

## 3. Where the permission check lives

```
  Where the check happens matters more than which model you picked.

     request
        │
        ▼
   ┌─────────────────────────────────────────┐
   │ authz("doc:write") middleware      PEP  │  ← policy ENFORCEMENT point
   │ one choke point, one line per route     │    (greppable, deny by default)
   └───────────────┬─────────────────────────┘
                   │ "may alice doc:write readme?"
                   ▼
   ┌─────────────────────────────────────────┐
   │ the engine: rbacAllows | rebacAllows PDP│  ← policy DECISION point
   └───────────────┬─────────────────────────┘    (swappable — handlers
                   │ allow / deny                    never know which)
                   ▼
   ┌─────────────────────────────────────────┐
   │ your handler — business logic only      │
   └─────────────────────────────────────────┘

  the failure mode this prevents: authorization written as `if` statements
  inside handlers. one new endpoint, one forgotten `if`, one open door.
  a route with no wrapper must fail CLOSED, not open.
```

Notice in [lab/main.go](lab/main.go) that **every** guarded route is wrapped in
one `authz(permission, handler)` middleware. The check happens at the **edge of
the request**, before any business logic, in exactly one place per route. This is
deliberate and it is the other half of the lesson:

- **One choke point, not scattered `if`s.** Authorization spread through business
  logic is how you get the endpoint someone forgot to guard. Centralize it: a
  middleware, a decorator, a service-mesh filter — but *one* pattern, greppable.
- **Deny by default.** A route with no `authz` wrapper should fail closed (here it
  simply has no unauthenticated path to the data). New endpoints are locked until
  someone explicitly grants access, never open until someone remembers to lock.
- **The engine is swappable.** `authz` calls `rbacAllows` *or* `rebacAllows` based
  on config. The handlers don't know or care. In real systems this is the
  "policy decision point" (the engine) vs "policy enforcement point" (the
  middleware) split — keep them separate so you can change models without
  rewriting handlers.
- **403 vs 404.** Denying with `403 Forbidden` confirms the object exists.
  Sometimes that's a leak (a private repo's existence). Returning `404` hides it.
  The lab uses 403 for legibility; the choice is real and situational.

---

## Lab

Two containers: **Postgres** (schema + seed) and the **Go app**. The seed builds
one world used by both engines:

```
documents:  README  (inside folder "Engineering")     Board Secret  (root, no folder)
users:      alice  — global admin,  ReBAC owner of Board Secret
            bob    — global editor, ReBAC editor of folder Engineering
            carol  — global viewer, ReBAC direct viewer of README
            dave   — no role;        ReBAC member of group "staff" (staff can view README)
```

### Start it

```bash
cd 05-authorization/lab
podman compose up --build          # -d to background
```

### The core exercise: run the same demo against both engines

```bash
./demo-authz.sh                    # ships in MODEL=rebac
```

Then switch engines and run the identical script:

```bash
# edit compose.yaml:  MODEL: rebac  ->  rbac
podman compose up -d --build app
./demo-authz.sh
```

Watch these two rows flip between the runs — they *are* the lesson:

| Question | RBAC | ReBAC |
|---|---|---|
| Can **bob** write **Board Secret**? | **ALLOW** — he's a global editor | **DENY** — he only edits folder Engineering |
| Can **dave** read **README**? | **DENY** — he has no role | **ALLOW** — via group `staff` membership |

RBAC *over-grants* (bob touches a secret he was never given) and *under-grants*
(dave, correctly entitled via a group, is invisible to it). ReBAC gets both right
because access follows the relationships.

### Introspection

```bash
curl -s localhost:8080/explain/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
     -H 'X-User: bob@corp.com' | jq
```

`/explain` dumps *why* — the tuples on the object and each derived permission. A
real engine exposes this as `check`/`expand`; you will lean on it constantly when
debugging "why can this person see that?"

### Endpoints

| Method + path | Permission checked |
|---|---|
| `GET /documents/{id}` | `doc:read` |
| `PUT /documents/{id}` | `doc:write` |
| `DELETE /documents/{id}` | `doc:delete` |
| `GET /explain/{id}` | none — shows the authorization reasoning |

Identify the caller with `-H 'X-User: <email>'` (a stand-in for a verified
session/JWT — authentication was the earlier modules' job).

### Exercises

1. **Add a per-object share, no schema change.** Insert one tuple giving carol
   `editor` on README:
   `INSERT INTO relation_tuples VALUES ('document','aaaa…','editor','user','<carol-uuid>','')`
   (get her id from the `users` table). Re-run: carol can now write README but
   still not delete it. Do the same in RBAC — you can't, without inventing a
   scoped-role column. Write down what that tells you.
2. **Break inheritance and watch access disappear.** Delete the
   `document:readme#parent@folder:eng` tuple. Bob loses write on README (he only
   had it by inheriting from the folder). Restore it. This is why "who can touch
   this file?" in a ReBAC system requires walking the graph, not reading one row.
3. **Nest a group inside a group.** Create `group:eng-team#member@group:staff#member`
   (staff are members of eng-team) and grant `document:secret#viewer@group:eng-team#member`.
   Confirm dave can now read the secret — through *two* levels of group. Trace the
   recursion in `check`.
4. **Add a cycle and confirm the guard holds.** Insert
   `group:a#member@group:b#member` and `group:b#member@group:a#member`, then check
   any permission that touches them. It should terminate (return false), not hang.
   Find the line in `check` that saves you.
5. **Make RBAC less wrong.** Add a `scope` column to `user_roles` and change
   `rbacAllows` to require the scope match the object (or a wildcard). You'll
   reinvent a slice of ReBAC. Note what's still hard: inheritance and groups.

### Tear down

```bash
podman compose down -v
```

---

## Self-check quiz (10 questions)

<details>
<summary>1. In one sentence, the difference between RBAC and ReBAC?</summary>

RBAC grants permissions to *roles* a user holds (usually globally), so the check
ignores the object; ReBAC derives permissions from *relationships between the user
and the specific object* (owner/editor/parent/member), so access follows the
object graph.
</details>

<details>
<summary>2. Why could bob write the Board Secret under RBAC but not ReBAC?</summary>

RBAC gave bob the global `editor` role, whose `doc:write` permission is not tied
to any object — so it applies to every document, including one he was never
specifically granted. ReBAC only makes bob an editor of the *folder Engineering*;
the secret has no parent relationship to that folder, so nothing grants bob access
to it.
</details>

<details>
<summary>3. What is a relation tuple, and what are its parts?</summary>

`object#relation@subject`: the object being granted on (e.g. `document:readme`),
the relation (`viewer`), and the subject it points at — either a direct user
(`user:carol`) or a userset (`group:staff#member`, meaning everyone with `member`
on `group:staff`). It's the single, uniform fact type the whole ReBAC model is
built from.
</details>

<details>
<summary>4. How does ReBAC express "everyone in the staff group can view this"?</summary>

One tuple whose subject is a userset:
`document:readme#viewer@group:staff#member`. The `check` walk, on reaching it,
recurses to ask "does this user have `member` on `group:staff`?" — so membership
tuples (`group:staff#member@user:dave`) transitively grant the view. Adding/removing
a member is one tuple; no per-document change.
</details>

<details>
<summary>5. Trace how bob inherits edit rights on README.</summary>

`check(document:readme, editor, user:bob)` finds no direct editor tuple for bob on
readme. It then follows readme's `parent` tuple to `folder:eng` and recurses:
`check(folder:eng, editor, user:bob)` — which finds the direct tuple
`folder:eng#editor@user:bob`. Hit. Access flowed up the object graph.
</details>

<details>
<summary>6. Why centralize the permission check in one middleware instead of in each handler?</summary>

So authorization can't be *forgotten*. Scattered `if user.canX()` checks mean the
one endpoint someone omitted is a silent hole. A single `authz(perm, handler)`
choke point is greppable, uniformly applied, fails closed for un-wrapped routes,
and lets you swap the underlying engine (RBAC↔ReBAC) without touching business
logic — the PEP/PDP separation.
</details>

<details>
<summary>7. What does "deny by default" mean and why does it matter here?</summary>

A request is refused unless a rule explicitly permits it; a new or un-wrapped
endpoint is closed until someone grants access, rather than open until someone
remembers to lock it. It matters because the failure mode of authorization is
silent — an over-permissive default doesn't error, it just leaks — so the safe
default has to be "no."
</details>

<details>
<summary>8. When is returning 403 (vs 404) on a denied request itself a leak?</summary>

403 confirms the object exists — for a private repository, document, or user
profile, merely revealing existence to someone unauthorized can be the whole
breach (enumeration, targeting). Returning 404 ("no such object") hides existence
from those who lack access. Use 404-style hiding when existence is sensitive; 403
is fine when it isn't.
</details>

<details>
<summary>9. Why does the recursive check need a "seen" set?</summary>

Relation tuples form a graph, and groups can reference each other (a ∈ b, b ∈ a),
which would make the recursion loop forever. Marking each `object#relation` visited
and refusing to re-enter it guarantees termination. Without it, a cyclic group
membership — accidental or malicious — hangs the check.
</details>

<details>
<summary>10. Name two things production Zanzibar-style engines add that this lab omits.</summary>

Any two of: caching of check results; a consistency/snapshot token (Zanzibar's
"zookie") so a check reflects a known revision after a write; reverse indexes to
answer "list every object user X can read" (not just yes/no on one object);
sharded storage; and a schema/policy language instead of hand-written Go rules.
The *model* (tuples + derived permissions via graph walk) is identical.
</details>

---

## References

- [Zanzibar: Google's Consistent, Global Authorization System (USENIX ATC 2019)](https://research.google/pubs/pub48190/) — the founding paper
- [SpiceDB docs — modeling with relationships](https://authzed.com/docs) and [OpenFGA modeling guide](https://openfga.dev/docs/modeling/getting-started)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP — Broken Access Control (A01:2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) — why this module is #1 on the list
- [NIST RBAC model (INCITS 359)](https://csrc.nist.gov/projects/role-based-access-control) — the formal RBAC reference
