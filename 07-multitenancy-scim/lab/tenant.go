package main

import (
	"net/http"
)

// tenantContext is the resolved, verified "who + where" for a request: this
// user, acting in this org, with this org-scoped role. EVERY tenant-scoped
// handler gets one, and every query it runs is filtered by ctx.orgID.
type tenantContext struct {
	userID string
	orgID  string
	role   string
}

// tenantScoped resolves (X-User, X-Org) into a membership and rejects anyone
// who is not an ACTIVE member of that org. This is the isolation boundary: a
// user of Acme presenting X-Org: <Beta's id> is turned away here, before any
// data is touched.
func tenantScoped(next func(http.ResponseWriter, *http.Request, tenantContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		email := r.Header.Get("X-User")
		orgID := r.Header.Get("X-Org")
		if email == "" || orgID == "" {
			jsonErr(w, 401, "X-User and X-Org required")
			return
		}

		var userID, role string
		var active bool
		err := db.QueryRow(ctx, `
			SELECT u.id, m.role, m.active
			  FROM users u
			  JOIN memberships m ON m.user_id = u.id
			 WHERE u.email = $1 AND m.org_id = $2`,
			email, orgID).Scan(&userID, &role, &active)
		if err != nil {
			// No membership row -> this user has no business in this org. The
			// same 403 whether the org exists or not (don't leak org existence).
			jsonErr(w, 403, "not a member of this organization")
			return
		}
		if !active {
			// SCIM/admin deactivated the membership: access is cut immediately,
			// even though the user account still exists (and may be active elsewhere).
			jsonErr(w, 403, "membership deactivated")
			return
		}
		next(w, r, tenantContext{userID: userID, orgID: orgID, role: role})
	}
}

// tenantAdmin is tenantScoped + requires the org-scoped 'admin' role. Note the
// role is per-org: admin of Acme is just a member (or nothing) elsewhere.
func tenantAdmin(next func(http.ResponseWriter, *http.Request, tenantContext)) http.HandlerFunc {
	return tenantScoped(func(w http.ResponseWriter, r *http.Request, tc tenantContext) {
		if tc.role != "admin" {
			jsonErr(w, 403, "admin role required in this organization")
			return
		}
		next(w, r, tc)
	})
}

// ---- tenant-scoped handlers ------------------------------------------------
//
// The one rule: every statement carries `WHERE org_id = $tc.orgID`. Omitting it
// even once is the classic cross-tenant data leak. Exercise 1 makes you do it.

func handleListProjects(w http.ResponseWriter, r *http.Request, tc tenantContext) {
	rows, err := db.Query(r.Context(),
		`SELECT id, name FROM projects WHERE org_id = $1 ORDER BY name`, tc.orgID)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	out := []map[string]string{}
	for rows.Next() {
		var id, name string
		rows.Scan(&id, &name)
		out = append(out, map[string]string{"id": id, "name": name})
	}
	jsonOut(w, 200, out)
}

func handleCreateProject(w http.ResponseWriter, r *http.Request, tc tenantContext) {
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil || in.Name == "" {
		jsonErr(w, 400, "name required")
		return
	}
	var id string
	// org_id comes from the verified context, NEVER from the request body — a
	// client must not be able to write into another tenant by naming its id.
	db.QueryRow(r.Context(),
		`INSERT INTO projects (org_id, name) VALUES ($1, $2) RETURNING id`,
		tc.orgID, in.Name).Scan(&id)
	jsonOut(w, 201, map[string]string{"id": id, "name": in.Name})
}

func handleListMembers(w http.ResponseWriter, r *http.Request, tc tenantContext) {
	rows, err := db.Query(r.Context(), `
		SELECT u.email, m.role, m.active, m.source
		  FROM memberships m JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 ORDER BY u.email`, tc.orgID)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	out := []map[string]any{}
	for rows.Next() {
		var email, role, source string
		var active bool
		rows.Scan(&email, &role, &active, &source)
		out = append(out, map[string]any{"email": email, "role": role, "active": active, "source": source})
	}
	jsonOut(w, 200, out)
}
