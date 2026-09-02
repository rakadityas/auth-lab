package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// handleLogin is the adaptive login. It scores the attempt, then either lets the
// user in, forces a step-up MFA challenge, or blocks — and records the attempt
// so the counters that feed future scores stay current.
//
// NOTE: password verification is intentionally trivial here (any non-empty
// password "succeeds" at the credential step) so the demo isolates the RISK
// decision. Real systems run this risk engine AROUND a real password check.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	a := parseAttempt(r)
	if a.email == "" {
		jsonOut(w, 400, map[string]string{"error": "email required"})
		return
	}

	d := decide(a)

	// The credential itself: empty password = failed credential (drives the
	// per-IP failure signal for the stuffing demo). A wrong guess counts as a
	// failure regardless of risk.
	credentialOK := a.password != ""
	// Trust (device/geo learning) is earned ONLY by a clean allow — never by a
	// step-up that hasn't been completed, nor by a deny.
	trusted := credentialOK && d.Outcome == "allow"
	recordAttempt(a, credentialOK, trusted)

	switch {
	case !credentialOK:
		jsonOut(w, 401, map[string]any{"result": "invalid credentials", "risk": d})
	case d.Outcome == "deny":
		// High risk: refuse outright. Prefer a generic message; don't teach the
		// attacker which signal tripped.
		jsonOut(w, 403, map[string]any{"result": "blocked — unusual activity", "risk": d})
	case d.Outcome == "step_up":
		// Medium risk: credentials were fine, but require a second factor before
		// issuing a session. Mint a short-lived challenge tied to this attempt.
		ch := mintChallenge(a.email)
		jsonOut(w, 200, map[string]any{
			"result": "mfa_required", "challenge_id": ch,
			"hint": "POST /mfa with {\"challenge_id\":...,\"code\":\"000000\"} (any 6 digits pass in the lab)",
			"risk": d,
		})
	default:
		// Low risk: straight through, no friction. This is the 99% path.
		jsonOut(w, 200, map[string]any{"result": "logged in", "risk": d})
	}
}

// handleMFA completes a step-up challenge. In the lab any 6-digit code passes;
// the point is that clearing MFA converts a risky attempt into a trusted one AND
// learns the device/geo so the user isn't challenged again next time.
func handleMFA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code"`
	}
	readJSON(r, &in)
	email := rdb.Get(ctx, "mfa:"+in.ChallengeID).Val()
	if email == "" {
		jsonOut(w, 400, map[string]string{"error": "unknown or expired challenge"})
		return
	}
	if len(in.Code) != 6 {
		jsonOut(w, 401, map[string]string{"error": "bad code"})
		return
	}
	rdb.Del(ctx, "mfa:"+in.ChallengeID)

	// Trust this device+geo going forward (the header context of the ORIGINAL
	// attempt would be carried through; here we read the current request's).
	dev := r.Header.Get("X-Device")
	if dev != "" {
		rdb.SAdd(ctx, kKnownDevices(email), dev)
	}
	if g := r.Header.Get("X-Geo"); g != "" {
		rdb.Set(ctx, kLastGeo(email), g, 90*24*time.Hour)
	}
	jsonOut(w, 200, map[string]string{"result": "logged in", "note": "device now trusted; future logins won't step up"})
}

func mintChallenge(email string) string {
	b := make([]byte, 12)
	rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	rdb.Set(ctx, "mfa:"+id, email, 5*time.Minute)
	return id
}

// handleRiskInspect scores an attempt WITHOUT logging in — the "why is this
// risky?" introspection an analyst or the user's security page would show.
func handleRiskInspect(w http.ResponseWriter, r *http.Request) {
	a := attempt{
		email:  first(r.URL.Query().Get("email"), ""),
		ip:     first(r.Header.Get("X-Forwarded-For"), "10.0.0.1"),
		device: r.Header.Get("X-Device"),
		geo:    first(r.Header.Get("X-Geo"), "US"),
	}
	jsonOut(w, 200, decide(a))
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	rdb.FlushDB(ctx)
	jsonOut(w, 200, map[string]string{"status": "counters cleared"})
}
