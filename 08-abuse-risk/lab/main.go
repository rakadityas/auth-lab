// Module 8 lab — abuse, risk & adaptive (risk-based) authentication.
//
// Module 0 threw a fixed delay and per-account throttle at brute force. That
// stops one attacker guessing one account. It does NOTHING against the attack
// that actually drains real products: CREDENTIAL STUFFING — millions of
// (email,password) pairs from a breach, sprayed one-try-per-account across a
// botnet. This lab builds the defense: score every login attempt from multiple
// signals and ADAPT the response (allow / step-up MFA / deny) to the risk.
//
// Go + Redis (counters, sets, device memory). No real passwords — the focus is
// the risk engine, so any password "works" and risk decides what happens next.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb *redis.Client
	ctx = context.Background()
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	rdb = redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "localhost:6379")})
	for i := 0; i < 30; i++ {
		if err := rdb.Ping(ctx).Err(); err == nil {
			break
		}
		time.Sleep(time.Second)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /mfa", handleMFA)           // completes a step-up challenge
	mux.HandleFunc("GET /risk", handleRiskInspect)   // explain the score for a request
	mux.HandleFunc("POST /admin/reset", handleReset) // clear counters between demos
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := ":" + env("PORT", "8080")
	log.Printf("abuse/risk lab on %s", addr)
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
