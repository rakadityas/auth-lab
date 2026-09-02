// Module 5 lab — authorization in practice: RBAC and ReBAC over one domain.
//
// The service exposes a tiny document API. Every mutating/reading endpoint is
// guarded by a permission check; a MODEL env var (rbac | rebac) swaps which
// engine answers "may this user do this?" — so you can hit the SAME request
// against both models and see where each one can and cannot express intent.
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

var (
	db    *pgxpool.Pool
	model = env("MODEL", "rebac") // rbac | rebac
)

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

	// The authorization is applied HERE, at the edge of each handler, via the
	// `authz` middleware — not scattered through business logic. Centralizing
	// the check is itself a design lesson (see README §"Where the check lives").
	mux.HandleFunc("GET /documents/{id}", authz("doc:read", handleReadDoc))
	mux.HandleFunc("PUT /documents/{id}", authz("doc:write", handleWriteDoc))
	mux.HandleFunc("DELETE /documents/{id}", authz("doc:delete", handleDeleteDoc))

	// Introspection: "why can (or can't) I do this?" — invaluable for debugging
	// authorization and exactly what a real policy engine exposes (check/expand).
	mux.HandleFunc("GET /explain/{id}", handleExplain)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := ":" + env("PORT", "8080")
	log.Printf("authz lab listening on %s (MODEL=%s)", addr, model)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// The caller identifies itself with X-User: <email> (a stand-in for a verified
// session/JWT from the earlier modules; authorization, not authentication, is
// the subject here).
func callerID(ctx context.Context, r *http.Request) (string, bool) {
	email := r.Header.Get("X-User")
	if email == "" {
		return "", false
	}
	var id string
	if err := db.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
		return "", false
	}
	return id, true
}

// authz is the single choke point. It resolves the caller, then asks whichever
// engine MODEL selects whether `perm` is allowed on the object in the path.
func authz(perm string, next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userID, ok := callerID(ctx, r)
		if !ok {
			jsonErr(w, 401, "unknown or missing X-User")
			return
		}
		objID := r.PathValue("id")

		var allowed bool
		var err error
		switch model {
		case "rbac":
			allowed, err = rbacAllows(ctx, userID, perm)
		default:
			allowed, err = rebacAllows(ctx, userID, "document", objID, perm)
		}
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if !allowed {
			// 404, not 403, when the point is to hide existence. Here we use 403
			// to make the demos legible; the choice is a real design decision.
			jsonErr(w, 403, "forbidden: "+perm+" on document:"+objID)
			return
		}
		next(w, r, objID)
	}
}

// ---- trivial handlers (the domain is not the point) ------------------------

func handleReadDoc(w http.ResponseWriter, r *http.Request, docID string) {
	var title string
	if err := db.QueryRow(r.Context(), `SELECT title FROM documents WHERE id = $1`, docID).Scan(&title); err != nil {
		jsonErr(w, 404, "no such document")
		return
	}
	jsonOut(w, 200, map[string]string{"id": docID, "title": title})
}

func handleWriteDoc(w http.ResponseWriter, r *http.Request, docID string) {
	var in struct {
		Title string `json:"title"`
	}
	json.NewDecoder(r.Body).Decode(&in)
	db.Exec(r.Context(), `UPDATE documents SET title = $1 WHERE id = $2`, in.Title, docID)
	jsonOut(w, 200, map[string]string{"status": "updated", "title": in.Title})
}

func handleDeleteDoc(w http.ResponseWriter, r *http.Request, docID string) {
	db.Exec(r.Context(), `DELETE FROM documents WHERE id = $1`, docID)
	jsonOut(w, 200, map[string]string{"status": "deleted"})
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}
