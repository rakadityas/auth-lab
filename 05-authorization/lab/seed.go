package main

import (
	"context"
	"log"
	"net/http"
)

func handleExplain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, ok := callerID(ctx, r)
	if !ok {
		jsonErr(w, 401, "unknown or missing X-User")
		return
	}
	jsonOut(w, 200, explain(ctx, userID, "document", r.PathValue("id")))
}

// Fixed IDs so the demo scripts and README can name objects directly.
const (
	uAlice = "11111111-1111-1111-1111-111111111111" // owner of the secret doc
	uBob   = "22222222-2222-2222-2222-222222222222" // editor of the eng folder
	uCarol = "33333333-3333-3333-3333-333333333333" // viewer of one doc
	uDave  = "44444444-4444-4444-4444-444444444444" // member of the "staff" group

	dReadme = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" // lives in folder eng
	dSecret = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" // lives at root, alice owns
	fEng    = "eng"                                  // folder ids are plain strings in tuples
)

// seed is idempotent: safe to run on every boot.
func seed(ctx context.Context) {
	ex := func(sql string, args ...any) {
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			log.Fatalf("seed: %v\n  %s", err, sql)
		}
	}

	// users
	for _, u := range []struct{ id, email string }{
		{uAlice, "alice@corp.com"}, {uBob, "bob@corp.com"},
		{uCarol, "carol@corp.com"}, {uDave, "dave@corp.com"},
	} {
		ex(`INSERT INTO users (id, email) VALUES ($1,$2) ON CONFLICT (id) DO NOTHING`, u.id, u.email)
	}

	// documents + folder
	ex(`INSERT INTO folders (id,name) VALUES ($1,'Engineering') ON CONFLICT DO NOTHING`, fEng)
	ex(`INSERT INTO documents (id,title,folder_id) VALUES ($1,'README',$2) ON CONFLICT DO NOTHING`, dReadme, fEng)
	ex(`INSERT INTO documents (id,title) VALUES ($1,'Board Secret') ON CONFLICT DO NOTHING`, dSecret)

	// ---- RBAC seed: GLOBAL roles ----
	for _, r := range []string{"admin", "editor", "viewer"} {
		ex(`INSERT INTO roles (name) VALUES ($1) ON CONFLICT DO NOTHING`, r)
	}
	rp := func(role, perm string) {
		ex(`INSERT INTO role_permissions VALUES ($1,$2) ON CONFLICT DO NOTHING`, role, perm)
	}
	rp("admin", "doc:read")
	rp("admin", "doc:write")
	rp("admin", "doc:delete")
	rp("editor", "doc:read")
	rp("editor", "doc:write")
	rp("viewer", "doc:read")
	// bob is a global editor; carol a global viewer. Note: this says NOTHING
	// about WHICH documents — that's exactly the point of the demo.
	ex(`INSERT INTO user_roles VALUES ($1,'editor') ON CONFLICT DO NOTHING`, uBob)
	ex(`INSERT INTO user_roles VALUES ($1,'viewer') ON CONFLICT DO NOTHING`, uCarol)
	ex(`INSERT INTO user_roles VALUES ($1,'admin') ON CONFLICT DO NOTHING`, uAlice)

	// ---- ReBAC seed: relation tuples ----
	tup := func(ot, oid, rel, st, sid, srel string) {
		ex(`INSERT INTO relation_tuples
		    (object_type,object_id,relation,subject_type,subject_id,subject_relation)
		    VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, ot, oid, rel, st, sid, srel)
	}
	// alice OWNS the secret doc (per-object grant — RBAC can't say "just this one")
	tup("document", dSecret, "owner", "user", uAlice, "")
	// readme lives in folder eng; bob is an editor of eng -> inherits editor on readme
	tup("document", dReadme, "parent", "folder", fEng, "")
	tup("folder", fEng, "editor", "user", uBob, "")
	// carol is a direct viewer of readme only
	tup("document", dReadme, "viewer", "user", uCarol, "")
	// group demo: everyone in staff can view readme; dave is a staff member
	tup("document", dReadme, "viewer", "group", "staff", "member")
	tup("group", "staff", "member", "user", uDave, "")

	log.Printf("seed complete")
}
