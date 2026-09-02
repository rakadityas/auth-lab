package main

import (
	"net/http"
	"strings"
)

// SCIM 2.0 (RFC 7643/7644) is how an enterprise IdP pushes user lifecycle into
// your app: create, update, and — the part that matters most — DEACTIVATE users
// centrally. "SSO works but offboarding doesn't" is a real incident class: a
// company disables an employee in their IdP, but without SCIM your app never
// hears about it and the ex-employee's account lingers. SCIM closes that gap.
//
// This is a deliberately minimal SCIM: enough to show the provisioning AND
// deprovisioning paths and how they map onto the memberships table.

// scimAuth authenticates the IdP by its per-org bearer token and pins the
// request to that token's org. SCIM is org-scoped exactly like the app API.
func scimAuth(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("WWW-Authenticate", "Bearer")
			scimErr(w, 401, "bearer token required")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		var orgID string
		if err := db.QueryRow(r.Context(),
			`SELECT org_id FROM scim_tokens WHERE token_hash = $1`, hashToken(token)).Scan(&orgID); err != nil {
			scimErr(w, 401, "invalid SCIM token")
			return
		}
		next(w, r, orgID)
	}
}

func scimErr(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	// SCIM has its own error envelope.
	jsonRaw(w, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail, "status": code,
	})
}

// scimUser renders a membership as a SCIM User resource. `id` is the user id;
// `active` mirrors the membership's active flag — the field the IdP toggles.
func scimUser(orgID, userID, email string, active bool) map[string]any {
	return map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":       userID,
		"userName": email,
		"active":   active,
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"meta":     map[string]any{"resourceType": "User", "location": "/scim/v2/Users/" + userID},
	}
}

// POST /scim/v2/Users — provision. Creates the user (if new) and an ACTIVE
// membership in the token's org, sourced 'scim'.
func handleSCIMCreate(w http.ResponseWriter, r *http.Request, orgID string) {
	var in struct {
		UserName string `json:"userName"`
		Active   *bool  `json:"active"`
	}
	if err := readJSON(r, &in); err != nil || in.UserName == "" {
		scimErr(w, 400, "userName required")
		return
	}
	ctx := r.Context()
	email := strings.ToLower(in.UserName)
	userID := upsertUser(ctx, email)
	active := in.Active == nil || *in.Active
	db.Exec(ctx,
		`INSERT INTO memberships (org_id, user_id, role, source, active)
		 VALUES ($1,$2,'member','scim',$3)
		 ON CONFLICT (org_id, user_id) DO UPDATE SET active = EXCLUDED.active, source = 'scim'`,
		orgID, userID, active)

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(201)
	jsonRaw(w, scimUser(orgID, userID, email, active))
}

// PATCH /scim/v2/Users/{id} — the deprovisioning path. Okta/Entra send a
// PatchOp setting active=false when an employee is offboarded. We flip the
// membership inactive, which tenantScoped then blocks on the very next request.
func handleSCIMPatch(w http.ResponseWriter, r *http.Request, orgID string) {
	userID := r.PathValue("id")
	var in struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"Operations"`
	}
	if err := readJSON(r, &in); err != nil {
		scimErr(w, 400, "bad PatchOp")
		return
	}

	// Find the active=<bool> operation (SCIM clients vary in how they encode it).
	var newActive *bool
	for _, op := range in.Operations {
		if strings.EqualFold(op.Op, "replace") {
			switch v := op.Value.(type) {
			case bool:
				if strings.EqualFold(op.Path, "active") {
					newActive = &v
				}
			case map[string]any:
				if a, ok := v["active"].(bool); ok {
					newActive = &a
				}
			}
		}
	}
	if newActive == nil {
		scimErr(w, 400, "only active replace is supported in this lab")
		return
	}

	ctx := r.Context()
	tag, _ := db.Exec(ctx,
		`UPDATE memberships SET active = $1 WHERE org_id = $2 AND user_id = $3`,
		*newActive, orgID, userID)
	if tag.RowsAffected() == 0 {
		scimErr(w, 404, "no such user in this org")
		return
	}
	var email string
	db.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email)
	w.Header().Set("Content-Type", "application/scim+json")
	jsonRaw(w, scimUser(orgID, userID, email, *newActive))
}

// DELETE /scim/v2/Users/{id} — hard deprovision: remove the membership entirely
// (the user may still belong to other orgs). Some IdPs DELETE, others just PATCH
// active=false; support both.
func handleSCIMDelete(w http.ResponseWriter, r *http.Request, orgID string) {
	userID := r.PathValue("id")
	tag, _ := db.Exec(r.Context(),
		`DELETE FROM memberships WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	if tag.RowsAffected() == 0 {
		scimErr(w, 404, "no such user in this org")
		return
	}
	w.WriteHeader(204)
}

// GET /scim/v2/Users — list this org's members as SCIM resources.
func handleSCIMList(w http.ResponseWriter, r *http.Request, orgID string) {
	rows, err := db.Query(r.Context(), `
		SELECT u.id, u.email, m.active
		  FROM memberships m JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 ORDER BY u.email`, orgID)
	if err != nil {
		scimErr(w, 500, err.Error())
		return
	}
	var resources []map[string]any
	for rows.Next() {
		var id, email string
		var active bool
		rows.Scan(&id, &email, &active)
		resources = append(resources, scimUser(orgID, id, email, active))
	}
	w.Header().Set("Content-Type", "application/scim+json")
	jsonRaw(w, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resources),
		"Resources":    resources,
	})
}
