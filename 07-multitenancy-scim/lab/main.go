// Module 7 lab — multi-tenancy, B2B organizations & SCIM.
//
// One deployment, many tenant orgs. Demonstrates: tenant-isolated data access,
// org-scoped roles, invitations, per-tenant SSO with home-realm discovery + JIT
// provisioning, and SCIM 2.0 provisioning/deprovisioning (the offboarding half
// enterprises actually audit).
//
// Postgres + Mailpit (for invite emails), same shape as Module 4.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var db *pgxpool.Pool

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()
	dsn := env("DATABASE_URL", "postgres://lab:lab@localhost:5432/lab")
	var err error
	for i := 0; i < 30; i++ {
		db, err = pgxpool.New(ctx, dsn)
		if err == nil {
			err = db.Ping(ctx)
		}
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	seed(ctx)

	mux := http.NewServeMux()

	// Tenant-scoped app API. The caller says who they are (X-User) and which
	// org they're acting in (X-Org); tenantCtx enforces the membership.
	mux.HandleFunc("GET /projects", tenantScoped(handleListProjects))
	mux.HandleFunc("POST /projects", tenantScoped(handleCreateProject))
	mux.HandleFunc("GET /members", tenantScoped(handleListMembers))
	mux.HandleFunc("POST /invitations", tenantAdmin(handleInvite))
	mux.HandleFunc("POST /invitations/accept", handleAcceptInvite)

	// SSO: home-realm discovery + a fake IdP callback that does JIT.
	mux.HandleFunc("GET /sso/discover", handleDiscover)
	mux.HandleFunc("POST /sso/callback", handleSSOCallback)

	// SCIM 2.0 — the IdP calls these with the org's bearer token.
	mux.HandleFunc("POST /scim/v2/Users", scimAuth(handleSCIMCreate))
	mux.HandleFunc("PATCH /scim/v2/Users/{id}", scimAuth(handleSCIMPatch))
	mux.HandleFunc("DELETE /scim/v2/Users/{id}", scimAuth(handleSCIMDelete))
	mux.HandleFunc("GET /scim/v2/Users", scimAuth(handleSCIMList))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := ":" + env("PORT", "8080")
	log.Printf("multitenancy lab on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}
func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// jsonRaw encodes the body only; the caller has already set Content-Type and
// status (SCIM uses its own content type and status conventions).
func jsonRaw(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }
