package main

import (
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Each ceremony is a begin/finish pair:
//
//   begin  — server invents a random CHALLENGE and returns the options the
//            browser passes to navigator.credentials.create()/.get(). The
//            challenge + expected data are stashed server-side.
//   finish — browser returns the authenticator's signed response; the server
//            verifies it against the stashed challenge and the expected origin,
//            RP ID, and (for login) the stored public key.
//
// The challenge is what makes each ceremony a fresh, un-replayable proof.

func username(r *http.Request) string {
	if n := r.URL.Query().Get("user"); n != "" {
		return n
	}
	return "demo-user"
}

// ---- REGISTRATION (navigator.credentials.create) ---------------------------

func handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user := users.getOrCreate(username(r))

	options, sessionData, err := web.BeginRegistration(user,
		// Prefer a discoverable (resident) credential — a true "passkey" the
		// authenticator stores and can offer without the server naming it first.
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	stash(w, "reg", sessionData)
	jsonOut(w, 200, options)
}

func handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, ok := users.get(username(r))
	if !ok {
		jsonErr(w, 400, "begin registration first")
		return
	}
	sessionData, ok := unstash(r, "reg")
	if !ok {
		jsonErr(w, 400, "no registration in progress")
		return
	}

	// FinishRegistration does the real verification: parses the attestation,
	// checks the challenge matches, the origin matches RPOrigins, the RP ID hash
	// matches, and that user-presence (and user-verification if required) flags
	// are set. Any mismatch -> error, and no credential is stored.
	credential, err := web.FinishRegistration(user, *sessionData, r)
	if err != nil {
		jsonErr(w, 400, "registration failed: "+err.Error())
		return
	}
	users.addCredential(user.name, credential)
	jsonOut(w, 200, map[string]any{
		"status":        "passkey registered",
		"credential_id": credential.ID,
		"clone_warning": credential.Authenticator.CloneWarning,
	})
}

// ---- AUTHENTICATION (navigator.credentials.get) ----------------------------

func handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	user, ok := users.get(username(r))
	if !ok {
		jsonErr(w, 404, "no such user — register a passkey first")
		return
	}
	options, sessionData, err := web.BeginLogin(user)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	stash(w, "login", sessionData)
	jsonOut(w, 200, options)
}

func handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	user, ok := users.get(username(r))
	if !ok {
		jsonErr(w, 404, "no such user")
		return
	}
	sessionData, ok := unstash(r, "login")
	if !ok {
		jsonErr(w, 400, "no login in progress")
		return
	}

	// FinishLogin verifies the assertion signature with the STORED public key,
	// re-checks challenge/origin/RP-ID, and returns the updated credential
	// (notably its incremented signature counter).
	credential, err := web.FinishLogin(user, *sessionData, r)
	if err != nil {
		jsonErr(w, 401, "login failed: "+err.Error())
		return
	}

	// Clone detection: the authenticator's signature counter must move forward.
	// If the library saw it go backwards/stall, CloneWarning is set — a signal
	// that two copies of the private key may exist (a cloned authenticator).
	if credential.Authenticator.CloneWarning {
		jsonErr(w, 401, "possible cloned authenticator (counter regressed) — rejecting")
		return
	}
	users.updateCredential(user.name, credential) // persist the new counter

	setLogin(w, user.name)
	jsonOut(w, 200, map[string]any{"status": "authenticated", "user": user.name})
}
