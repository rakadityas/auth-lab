package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// A login attempt's context. In production these come from the request, a
// device cookie, and IP-geo/reputation lookups; here they're headers so the
// demo can drive each signal deliberately.
type attempt struct {
	email    string
	password string
	ip       string // X-Forwarded-For (spoofed by the demo to simulate a botnet)
	device   string // X-Device: a stable per-device id (a "device cookie")
	geo      string // X-Geo: country code, stands in for IP geolocation
	ua       string // User-Agent
}

func parseAttempt(r *http.Request) attempt {
	body := struct{ Email, Password string }{}
	readJSON(r, &body)
	return attempt{
		email:    strings.ToLower(body.Email),
		password: body.Password,
		ip:       first(r.Header.Get("X-Forwarded-For"), "10.0.0.1"),
		device:   r.Header.Get("X-Device"),
		geo:      first(r.Header.Get("X-Geo"), "US"),
		ua:       first(r.Header.Get("User-Agent"), "curl"),
	}
}

func first(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// A single risk signal that fired, with the points it added and why.
type signal struct {
	Name   string `json:"signal"`
	Points int    `json:"points"`
	Detail string `json:"detail"`
}

// score is the risk engine. It sums weighted signals into a score; the caller
// maps the score to a decision. The weights are illustrative — in a real system
// they're tuned against labeled fraud data (and increasingly ML-scored), but the
// SHAPE is exactly this: many weak signals combine into one number.
func score(a attempt) (int, []signal) {
	var sigs []signal
	add := func(name string, pts int, detail string) {
		sigs = append(sigs, signal{name, pts, detail})
	}

	// --- Signal 1: per-IP velocity (the credential-stuffing tell) -----------
	// One IP attempting MANY DISTINCT accounts in a short window is the
	// signature of stuffing: a botnet walking a breach list, one try each.
	ipMin := int(rdb.SCard(ctx, kIPAccounts(a.ip)).Val())
	switch {
	case ipMin >= 20:
		add("ip_velocity", 60, fmt.Sprintf("%d distinct accounts from this IP recently", ipMin))
	case ipMin >= 8:
		add("ip_velocity", 35, fmt.Sprintf("%d distinct accounts from this IP recently", ipMin))
	case ipMin >= 4:
		add("ip_velocity", 15, fmt.Sprintf("%d distinct accounts from this IP recently", ipMin))
	}

	// --- Signal 2: per-IP failure rate --------------------------------------
	// Stuffing has a LOW success rate (most breached passwords are stale). A
	// high recent-failure count from an IP is corroborating evidence.
	fails, _ := rdb.Get(ctx, kIPFails(a.ip)).Int() // 0 if key absent
	if fails >= 10 {
		add("ip_failures", 25, fmt.Sprintf("%d recent failed logins from this IP", fails))
	} else if fails >= 5 {
		add("ip_failures", 12, fmt.Sprintf("%d recent failed logins from this IP", fails))
	}

	// --- Signal 3: unknown device -------------------------------------------
	// A login from a device we've seen succeed for THIS account before is low
	// risk; a brand-new device is higher. This is the single most useful signal
	// for real users: it keeps returning users frictionless.
	if a.device == "" {
		add("no_device_id", 20, "no device identifier presented")
	} else if !rdb.SIsMember(ctx, kKnownDevices(a.email), a.device).Val() {
		add("new_device", 25, "device never before seen for this account")
	}

	// --- Signal 4: new geolocation / impossible travel ----------------------
	lastGeo := rdb.Get(ctx, kLastGeo(a.email)).Val()
	if lastGeo != "" && lastGeo != a.geo {
		add("new_geo", 30, fmt.Sprintf("login from %s; previous was %s", a.geo, lastGeo))
	}

	// --- Signal 5: breached / weak password ---------------------------------
	// A password known to be in a breach corpus is far likelier to be a stuffing
	// hit (that's where the list came from). Module 0 checked HIBP; here a small
	// static set stands in.
	if breachedPasswords[a.password] {
		add("breached_password", 20, "password appears in a known breach corpus")
	}

	total := 0
	for _, s := range sigs {
		total += s.Points
	}
	return total, sigs
}

// Decision thresholds. The whole point of ADAPTIVE auth: not a binary
// allow/deny, but a middle tier that adds friction (step-up MFA) only when the
// risk warrants it — so 99% of real users sail through and attackers hit a wall.
type decision struct {
	Outcome string   `json:"outcome"` // allow | step_up | deny
	Score   int      `json:"score"`
	Signals []signal `json:"signals"`
}

func decide(a attempt) decision {
	total, sigs := score(a)
	out := "allow"
	switch {
	case total >= 70:
		out = "deny"
	case total >= 30:
		out = "step_up"
	}
	return decision{Outcome: out, Score: total, Signals: sigs}
}

// recordAttempt updates the counters future scores read from.
//   - credentialOK=false bumps the per-IP failure counter.
//   - trusted=true "learns" the device and geo, so the next login from them is
//     low risk. CRUCIAL: trust is only earned by a FULLY authenticated login
//     (outcome=allow, or a completed step-up), never by merely triggering a
//     step-up. Otherwise an attacker who trips step-up and abandons it would
//     silently mark their device trusted — defeating the whole mechanism.
func recordAttempt(a attempt, credentialOK, trusted bool) {
	pipe := rdb.Pipeline()
	// per-IP distinct accounts, 10-min sliding window (approximated by TTL)
	pipe.SAdd(ctx, kIPAccounts(a.ip), a.email)
	pipe.Expire(ctx, kIPAccounts(a.ip), 10*time.Minute)
	if !credentialOK {
		pipe.Incr(ctx, kIPFails(a.ip))
		pipe.Expire(ctx, kIPFails(a.ip), 10*time.Minute)
	}
	if trusted {
		if a.device != "" {
			pipe.SAdd(ctx, kKnownDevices(a.email), a.device)
		}
		pipe.Set(ctx, kLastGeo(a.email), a.geo, 90*24*time.Hour)
	}
	pipe.Exec(ctx)
}

// redis key helpers
func kIPAccounts(ip string) string      { return "ip:accts:" + ip }
func kIPFails(ip string) string         { return "ip:fails:" + ip }
func kKnownDevices(email string) string { return "known:dev:" + email }
func kLastGeo(email string) string      { return "geo:last:" + email }

// A stand-in breach corpus (Module 0 does the real HaveIBeenPwned range check).
var breachedPasswords = map[string]bool{
	"password": true, "123456": true, "qwerty": true, "letmein": true,
	"password123": true, "admin": true, "welcome": true,
}
