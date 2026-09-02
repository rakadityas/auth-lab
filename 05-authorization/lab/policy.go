package main

import (
	"context"
	"fmt"
	"strings"
)

// ============================================================================
// MODEL 1 — RBAC
// ============================================================================
//
// "Does the user hold ANY role that grants this permission?" One join. Fast,
// simple, and coarse: the permission is GLOBAL. If alice has the 'editor' role
// she may write EVERY document, because roles here carry no notion of *which*
// object. That's the model's ceiling — and the reason products outgrow it.

func rbacAllows(ctx context.Context, userID, perm string) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			  FROM user_roles ur
			  JOIN role_permissions rp ON rp.role = ur.role
			 WHERE ur.user_id = $1 AND rp.permission = $2
		)`, userID, perm).Scan(&ok)
	return ok, err
}

// ============================================================================
// MODEL 2 — ReBAC (Zanzibar style)
// ============================================================================
//
// Permissions are DERIVED from relations by a small policy, then answered with
// a graph walk over relation_tuples. This is the schema most authorization
// systems (SpiceDB, OpenFGA, Ory Keto) express in a policy language; here it is
// spelled out in Go so nothing is hidden.
//
// The policy for a document:
//
//   permission doc:read   := viewer  ∪ doc:write            (readers, plus anyone who can write)
//   permission doc:write   := editor  ∪ doc:delete           (editors, plus owners)
//   permission doc:delete  := owner
//   relation   viewer/editor/owner := <direct tuples>  ∪  <inherited from parent folder>
//
// Inheritance: a document has a `parent` tuple pointing at a folder; an editor
// of that folder is treated as an editor of the document. Folders nest, so this
// recurses up the tree.

func rebacAllows(ctx context.Context, userID, objType, objID, perm string) (bool, error) {
	subject := "user:" + userID
	switch perm {
	case "doc:read":
		return checkAny(ctx, objType, objID, []string{"viewer", "editor", "owner"}, subject)
	case "doc:write":
		return checkAny(ctx, objType, objID, []string{"editor", "owner"}, subject)
	case "doc:delete":
		return checkAny(ctx, objType, objID, []string{"owner"}, subject)
	default:
		return false, fmt.Errorf("unknown permission %q", perm)
	}
}

func checkAny(ctx context.Context, objType, objID string, relations []string, subject string) (bool, error) {
	for _, rel := range relations {
		ok, err := check(ctx, objType, objID, rel, subject, map[string]bool{})
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// check answers: does `subject` (e.g. "user:<uuid>") hold `relation` on
// object (objType,objID)? This is the Zanzibar "check" primitive — a recursive
// walk with three cases per tuple, guarded against cycles by `seen`.
func check(ctx context.Context, objType, objID, relation, subject string, seen map[string]bool) (bool, error) {
	key := objType + ":" + objID + "#" + relation
	if seen[key] {
		return false, nil // cycle guard
	}
	seen[key] = true

	rows, err := db.Query(ctx, `
		SELECT subject_type, subject_id, subject_relation
		  FROM relation_tuples
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3`,
		objType, objID, relation)
	if err != nil {
		return false, err
	}
	type edge struct{ sType, sID, sRel string }
	var edges []edge
	for rows.Next() {
		var e edge
		rows.Scan(&e.sType, &e.sID, &e.sRel)
		edges = append(edges, e)
	}

	for _, e := range edges {
		// Case A: direct subject. tuple ...@user:alice, and we're asking about
		// user:alice -> hit.
		if e.sRel == "" {
			if e.sType+":"+e.sID == subject {
				return true, nil
			}
			continue
		}
		// Case B: userset. tuple ...@group:staff#member means "everyone who has
		// `member` on group:staff". Recurse: does subject have that relation?
		ok, err := check(ctx, e.sType, e.sID, e.sRel, subject, seen)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	// Case C: inheritance rule (computed userset). For the `editor`/`viewer`/
	// `owner` relations on a document, ALSO count as holding it if you hold the
	// same relation on the document's parent folder — and recurse up folders.
	if objType == "document" || objType == "folder" {
		parents, err := parentsOf(ctx, objType, objID)
		if err != nil {
			return false, err
		}
		for _, p := range parents {
			ok, err := check(ctx, "folder", p, relation, subject, seen)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
	}
	return false, nil
}

// parentsOf returns the folder ids referenced by an object's `parent` tuples.
func parentsOf(ctx context.Context, objType, objID string) ([]string, error) {
	rows, err := db.Query(ctx, `
		SELECT subject_id FROM relation_tuples
		 WHERE object_type = $1 AND object_id = $2 AND relation = 'parent'
		   AND subject_type = 'folder'`,
		objType, objID)
	if err != nil {
		return nil, err
	}
	var out []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		out = append(out, id)
	}
	return out, nil
}

// explain produces a human-readable trace of why a permission is/ isn't granted
// — the /explain endpoint. Zanzibar calls the underlying primitive "expand".
func explain(ctx context.Context, userID, objType, objID string) map[string]any {
	subject := "user:" + userID
	out := map[string]any{"subject": subject, "object": objType + ":" + objID, "model": model}
	if model == "rbac" {
		var roles []string
		rows, _ := db.Query(ctx, `SELECT role FROM user_roles WHERE user_id = $1`, userID)
		for rows.Next() {
			var r string
			rows.Scan(&r)
			roles = append(roles, r)
		}
		out["roles"] = roles
		out["note"] = "RBAC ignores the object entirely; grants are global per role."
		return out
	}
	perms := map[string]bool{}
	for _, p := range []string{"doc:read", "doc:write", "doc:delete"} {
		ok, _ := rebacAllows(ctx, userID, objType, objID, p)
		perms[p] = ok
	}
	out["permissions"] = perms
	// list the direct tuples on the object for context
	var tuples []string
	rows, _ := db.Query(ctx,
		`SELECT relation, subject_type, subject_id, subject_relation
		   FROM relation_tuples WHERE object_type = $1 AND object_id = $2`, objType, objID)
	for rows.Next() {
		var rel, st, si, sr string
		rows.Scan(&rel, &st, &si, &sr)
		s := st + ":" + si
		if sr != "" {
			s += "#" + sr
		}
		tuples = append(tuples, objType+":"+objID+"#"+rel+"@"+s)
	}
	out["tuples_on_object"] = tuples
	out["note"] = strings.TrimSpace(`
Permissions are derived from relations + inheritance up the folder tree.`)
	return out
}
