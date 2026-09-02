package main

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// CAEP (Continuous Access Evaluation Protocol) and RISC (Risk Incident Sharing
// and Coordination) are the OpenID "Shared Signals Framework": a standard way
// for identity systems to PUSH security events to each other in near-real-time,
// so access decisions aren't frozen at login.
//
// The problem they solve: SSO issues a token good for an hour. Five minutes in,
// the IdP disables the user (fired, compromised). Without shared signals, every
// relying party keeps honoring that token for the remaining 55 minutes. CAEP
// lets the IdP emit a "session-revoked" / "credential-change" event that RPs
// subscribe to and act on immediately.
//
// This lab just models the EMISSION side: security events land in an in-memory
// feed a subscriber could poll. Real SSF wraps each event in a signed SET
// (Security Event Token, RFC 8417) and pushes it to registered receivers.

type caepEvent struct {
	Time    time.Time `json:"time"`
	Subject string    `json:"subject"`
	Type    string    `json:"event_type"` // caep.dev event types
}

var (
	caepMu   sync.Mutex
	caepFeed []caepEvent
)

// emitCAEP publishes a shared signal. Mapped to standard-ish CAEP event types
// so the vocabulary is familiar; the point is that OTHER systems can react.
func emitCAEP(ctx context.Context, subject, kind string) {
	var t string
	switch kind {
	case "credential-change":
		t = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	case "assurance-level-change":
		t = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	case "session-revoked":
		t = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	default:
		t = "https://schemas.openid.net/secevent/caep/event-type/" + kind
	}
	caepMu.Lock()
	caepFeed = append(caepFeed, caepEvent{Time: time.Now(), Subject: subject, Type: t})
	caepMu.Unlock()

	// A shared signal is itself audit-worthy.
	appendEvent(ctx, "system", "caep_emitted", subject, "", kind)
}

// handleCAEPFeed is what a subscribed relying party would poll (or, in real
// SSF, receive pushed). An RP seeing "credential-change" for a subject would
// revoke that subject's tokens/sessions on its side — continuous evaluation.
func handleCAEPFeed(w http.ResponseWriter, r *http.Request) {
	caepMu.Lock()
	defer caepMu.Unlock()
	jsonOut(w, 200, map[string]any{
		"note":   "a subscribed relying party polls/receives these and revokes access accordingly",
		"events": caepFeed,
	})
}
