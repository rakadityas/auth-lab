package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	rdb    *redis.Client
	otps   *OTPStore
	magics *MagicStore
	safe   bool
)

const sessionTTL = 30 * time.Minute

func main() {
	safe = env("MODE", "safe") != "unsafe"
	rdb = redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "localhost:6379")})
	otps = NewOTPStore(rdb, []byte(env("OTP_PEPPER", "dev-pepper")), safe)
	magics = NewMagicStore(rdb, safe)

	mux := http.NewServeMux()
	mux.HandleFunc("/otp/start", hOTPStart)
	mux.HandleFunc("/otp/resend", hOTPResend)
	mux.HandleFunc("/otp/verify", hOTPVerify)
	mux.HandleFunc("/magic/start", hMagicStart)
	mux.HandleFunc("/magic/consume", hMagicConsume)
	mux.HandleFunc("/me", hMe)
	mux.HandleFunc("/metrics", hMetrics)

	mode := "SAFE"
	if !safe {
		mode = "UNSAFE (controls disabled — for the attack demos)"
	}
	log.Printf("otp lab listening on :8080  mode=%s", mode)
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// --- OTP ---------------------------------------------------------------------

func hOTPStart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Identifier string `json:"identifier"`
		Channel    string `json:"channel"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Channel == "" {
		in.Channel = "email"
	}

	req, err := otps.Start(r.Context(), in.Identifier, in.Channel, clientIP(r))
	if errors.Is(err, errQuota) {
		// Even the quota rejection is uniform-shaped and 429, not 403: it must not
		// become an oracle for "this number has been asked for a lot lately".
		writeJSON(w, 429, map[string]any{"error": "too_many_requests"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}

	deliver(req.Channel, req.Identifier, "Your sign-in code",
		"Your code is "+req.Code+". It expires in 5 minutes. If you did not request it, ignore this message — nobody can sign in without it.")

	// The response is IDENTICAL whether or not the identifier has an account.
	// Anything else (different status, different latency, "no such user") turns
	// the login form into a user-enumeration API — and for a passwordless system
	// the identifier list IS the account list.
	out := map[string]any{"request_id": req.ID, "expires_in": req.ExpiresIn, "resend_after": int(resendCooloff.Seconds())}
	if !safe {
		// UNSAFE mode only: hand the plaintext code back to the caller so the demos
		// can show ground truth (what the brute force is searching for) without
		// going to the inbox. Obviously this exists nowhere in a real system.
		out["code_leaked_for_demo"] = req.Code
	}
	writeJSON(w, 200, out)
}

func hOTPResend(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RequestID string `json:"request_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	req, err := otps.Resend(r.Context(), in.RequestID, clientIP(r))
	switch {
	case errors.Is(err, errThrottled):
		w.Header().Set("Retry-After", "30")
		writeJSON(w, 429, map[string]any{"error": "slow_down"})
		return
	case errors.Is(err, errQuota):
		writeJSON(w, 429, map[string]any{"error": "too_many_requests"})
		return
	case err != nil:
		writeJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	deliver(req.Channel, req.Identifier, "Your sign-in code",
		"Your code is "+req.Code+". The previous code no longer works.")
	writeJSON(w, 200, map[string]any{"request_id": req.ID, "resent": true})
}

func hOTPVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RequestID string `json:"request_id"`
		Code      string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, left, err := otps.Verify(r.Context(), in.RequestID, in.Code)
	switch {
	case errors.Is(err, errTooMany):
		writeJSON(w, 429, map[string]any{"error": "too_many_attempts", "hint": "request a new code"})
		return
	case errors.Is(err, errNotFound):
		writeJSON(w, 400, map[string]any{"error": "expired_or_unknown_request"})
		return
	case err != nil:
		writeJSON(w, 401, map[string]any{"error": "invalid_code", "attempts_left": left})
		return
	}

	// Success. Note what a passwordless system just did: it created a full session
	// off ONE factor delivered to an inbox. That is why the risk engine (Module 8)
	// and the security notification (Module 9) matter more here, not less.
	tok := newSession(r.Context(), id)
	writeJSON(w, 200, map[string]any{"session": tok, "identifier": id, "expires_in": int(sessionTTL.Seconds())})
}

// --- magic link --------------------------------------------------------------

func hMagicStart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Identifier string `json:"identifier"`
	}
	if !decode(w, r, &in) {
		return
	}
	link, err := magics.Issue(r.Context(), in.Identifier)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "internal"})
		return
	}
	base := env("PUBLIC_BASE", "http://localhost:8080")
	url := base + "/magic/consume?token=" + link.Token

	// The same-browser nonce rides in a cookie on the REQUESTING device.
	http.SetCookie(w, &http.Cookie{
		Name: "magic_nonce", Value: link.SameBrowser, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(magicTTL.Seconds()),
	})
	sendMail(in.Identifier, "Your sign-in link", "Click to sign in (valid 10 minutes, once):\n\n"+url)
	writeJSON(w, 200, map[string]any{"sent": true})
}

func hMagicConsume(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	nonce := ""
	if c, err := r.Cookie("magic_nonce"); err == nil {
		nonce = c.Value
	}
	id, err := magics.Consume(r.Context(), tok, nonce)
	if err != nil {
		// One message for "already used", "expired", "never existed" and "wrong
		// browser" — each distinct message is a hint to someone holding a stolen link.
		writeJSON(w, 400, map[string]any{"error": "link_invalid"})
		return
	}
	writeJSON(w, 200, map[string]any{"session": newSession(r.Context(), id), "identifier": id})
}

// --- session + plumbing ------------------------------------------------------

func newSession(ctx context.Context, id string) string {
	tok := randomToken(32)
	rdb.Set(ctx, "sess:"+tok, id, sessionTTL)
	return tok
}

func hMe(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, err := rdb.Get(r.Context(), "sess:"+tok).Result()
	if err != nil {
		writeJSON(w, 401, map[string]any{"error": "unauthenticated"})
		return
	}
	writeJSON(w, 200, map[string]any{"identifier": id})
}

// hMetrics exposes the SMS meter. In production this dashboard is how you notice
// toll fraud on the day it starts instead of on the invoice.
func hMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"mode":         map[bool]string{true: "safe", false: "unsafe"}[safe],
		"sms_sent":     atomic.LoadInt64(&smsSent),
		"sms_cost_usd": float64(atomic.LoadInt64(&smsCostMicros)) / 1e6,
		// Deliberately NOT reporting the caller's own quota here: an endpoint that
		// tells you how much of a limit you have left is a probe for finding the
		// limit. You want this number on your dashboard, not in the API.
	})
}

func randomToken(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func clientIP(r *http.Request) string {
	// Demo-only: trust an explicit header so the scripts can simulate many sources.
	// In production you take this from your own edge, never from a client header.
	if v := r.Header.Get("X-Demo-IP"); v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad_json"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
