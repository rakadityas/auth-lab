package main

import (
	"context"
	"log"
)

// Fixed IDs so demos can name orgs directly. Two tenants — Acme and Beta —
// so the isolation demo has a neighbor to (fail to) leak into.
const (
	orgAcme = "aaaa1111-0000-0000-0000-000000000001"
	orgBeta = "bbbb2222-0000-0000-0000-000000000002"

	// Acme's SCIM bearer token (raw). The IdP presents this on SCIM calls.
	acmeSCIMToken = "scim-acme-secret-token"
)

func seed(ctx context.Context) {
	ex := func(sql string, args ...any) {
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			log.Fatalf("seed: %v\n  %s", err, sql)
		}
	}

	ex(`INSERT INTO organizations (id,name,slug) VALUES ($1,'Acme','acme'),($2,'Beta','beta')
	    ON CONFLICT DO NOTHING`, orgAcme, orgBeta)

	// Seed users + memberships. alice is an ADMIN of Acme; bob a MEMBER of Acme;
	// carol an admin of Beta. Note carol has NO membership in Acme — the
	// isolation demo turns her away there.
	seedMember := func(email, org, role string) {
		var uid string
		ex2 := db.QueryRow(ctx,
			`INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email=EXCLUDED.email RETURNING id`, email)
		ex2.Scan(&uid)
		ex(`INSERT INTO memberships (org_id,user_id,role,source,active) VALUES ($1,$2,$3,'invite',true)
		    ON CONFLICT DO NOTHING`, org, uid, role)
	}
	seedMember("alice@acme.com", orgAcme, "admin")
	seedMember("bob@acme.com", orgAcme, "member")
	seedMember("carol@beta.com", orgBeta, "admin")

	// A per-tenant project in each org (the thing that must not cross tenants).
	ex(`INSERT INTO projects (org_id,name) VALUES ($1,'Acme Roadmap') ON CONFLICT DO NOTHING`, orgAcme)
	ex(`INSERT INTO projects (org_id,name) VALUES ($1,'Beta Secrets') ON CONFLICT DO NOTHING`, orgBeta)

	// Acme brings enterprise SSO for acme.com, with JIT on.
	ex(`INSERT INTO sso_connections (org_id,domain,idp_name,jit_enabled,default_role)
	    VALUES ($1,'acme.com','Acme Okta',true,'member') ON CONFLICT DO NOTHING`, orgAcme)

	// Acme's SCIM bearer token.
	ex(`INSERT INTO scim_tokens (token_hash,org_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		hashToken(acmeSCIMToken), orgAcme)

	log.Printf("seed complete (Acme=%s Beta=%s)", orgAcme, orgBeta)
}
