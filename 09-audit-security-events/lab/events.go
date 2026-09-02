package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// These handlers model the security-relevant actions. Each one does three
// things every such action in a real system must do:
//   1. perform the action
//   2. write an AUDIT event (tamper-evident, for investigators)
//   3. send a SECURITY NOTIFICATION to the user (their early-warning system)
//
// (2) and (3) are different audiences: the audit log is for you/security/
// compliance; the notification is for the account owner, who is often the only
// party who can tell "that wasn't me."

func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// handleLogin records a login and — the security event — alerts the user if the
// device is one we've never seen for them before.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User   string `json:"user"`
		Device string `json:"device"`
	}
	readJSON(r, &in)
	if in.User == "" || in.Device == "" {
		jsonOut(w, 400, map[string]string{"error": "user and device required"})
		return
	}
	ctx := r.Context()
	ip := first(r.Header.Get("X-Forwarded-For"), "203.0.113.9")

	// Is this a new device for the user?
	var seenBefore bool
	db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM known_devices WHERE user_id=$1 AND device_id=$2)`,
		in.User, in.Device).Scan(&seenBefore)
	db.Exec(ctx, `INSERT INTO known_devices (user_id, device_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		in.User, in.Device)

	// Create a session (feeds the inventory).
	sid := randID()
	db.Exec(ctx, `INSERT INTO sessions (id,user_id,device_id,ip) VALUES ($1,$2,$3,$4)`,
		sid, in.User, in.Device, ip)

	appendEvent(ctx, in.User, "login", in.Device, ip, "device="+in.Device)

	if !seenBefore {
		// THE security event: new device. This mail is often the user's only
		// signal that their password has been compromised.
		notify(in.User, "New sign-in to your account",
			"A new device just signed in:\n  device: "+in.Device+"\n  ip: "+ip+
				"\n  time: "+time.Now().Format(time.RFC1123)+
				"\n\nIf this wasn't you, change your password and review your active sessions immediately.")
		appendEvent(ctx, "system", "security_notification", in.User, "", "new_device_login")
		jsonOut(w, 200, map[string]any{"result": "logged in", "new_device": true, "session": sid,
			"note": "security notification sent (check Mailpit)"})
		return
	}
	jsonOut(w, 200, map[string]any{"result": "logged in", "new_device": false, "session": sid})
}

func handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User string `json:"user"`
	}
	readJSON(r, &in)
	if in.User == "" {
		jsonOut(w, 400, map[string]string{"error": "user required"})
		return
	}
	ctx := r.Context()
	ip := first(r.Header.Get("X-Forwarded-For"), "203.0.113.9")

	appendEvent(ctx, in.User, "password_changed", in.User, ip, "")
	// Password change is a classic account-takeover step; ALWAYS notify, and to
	// the existing contact address (an attacker can't suppress that channel).
	notify(in.User, "Your password was changed",
		"Your account password was just changed from ip "+ip+".\n"+
			"If this wasn't you, your account may be compromised — use the account-recovery link now.")
	emitCAEP(ctx, in.User, "credential-change") // tell downstream systems (see caep.go)
	jsonOut(w, 200, map[string]string{"result": "password changed", "note": "notification + CAEP signal emitted"})
}

func handleMFADisable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User string `json:"user"`
	}
	readJSON(r, &in)
	if in.User == "" {
		jsonOut(w, 400, map[string]string{"error": "user required"})
		return
	}
	ctx := r.Context()
	ip := first(r.Header.Get("X-Forwarded-For"), "203.0.113.9")

	appendEvent(ctx, in.User, "mfa_disabled", in.User, ip, "")
	// Disabling MFA weakens the account — a very common attacker move after
	// takeover. High-signal event: notify loudly.
	notify(in.User, "Two-factor authentication was turned OFF",
		"MFA was disabled on your account from ip "+ip+".\n"+
			"If this wasn't you, re-enable it and change your password immediately.")
	emitCAEP(ctx, in.User, "assurance-level-change")
	jsonOut(w, 200, map[string]string{"result": "mfa disabled", "note": "high-signal notification + CAEP emitted"})
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	rows, _ := db.Query(r.Context(),
		`SELECT id, device_id, ip, created_at FROM sessions WHERE user_id=$1 ORDER BY created_at`, user)
	out := []map[string]any{}
	for rows.Next() {
		var id, dev, ip string
		var created time.Time
		rows.Scan(&id, &dev, &ip, &created)
		out = append(out, map[string]any{"session": id, "device": dev, "ip": ip, "created_at": created})
	}
	jsonOut(w, 200, out)
}

func first(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
