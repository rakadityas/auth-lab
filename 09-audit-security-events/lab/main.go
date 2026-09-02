// Module 9 lab — audit logging & security events.
//
// Builds the tamper-evident audit log an identity team needs, wires security
// events to user-facing notifications (new device, password change, MFA
// disabled), exposes a session inventory, and shows the CAEP/RISC "shared
// signals" idea for telling OTHER systems that something changed.
//
// Postgres (the hash-chained log) + Mailpit (security notifications).
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

	mux := http.NewServeMux()
	// Actions that generate security events + audit entries.
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /password/change", handlePasswordChange)
	mux.HandleFunc("POST /mfa/disable", handleMFADisable)
	// The audit log itself.
	mux.HandleFunc("GET /audit", handleAuditList)
	mux.HandleFunc("GET /audit/verify", handleAuditVerify) // walk the hash chain
	mux.HandleFunc("POST /audit/tamper", handleTamper)     // DEMO ONLY: edit a past row
	// Session inventory (the user's "where am I logged in" page).
	mux.HandleFunc("GET /sessions", handleSessions)
	// CAEP/RISC shared-signal emission (concept).
	mux.HandleFunc("GET /caep/feed", handleCAEPFeed)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := ":" + env("PORT", "8080")
	log.Printf("audit lab on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
