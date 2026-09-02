package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// The genesis value the first row chains from — a fixed, well-known anchor.
const genesisHash = "GENESIS"

// One writer at a time: the chain requires each append to read the current tip
// and link to it atomically. A real system does this with a per-partition
// serialized writer or a DB advisory lock; a mutex is enough for the lab.
var appendMu sync.Mutex

// rowHash computes the hash a row commits to: its own fields plus prev_hash.
// Any change to any covered field changes this hash — and, because prev_hash is
// covered, changing a past row breaks every row after it.
func rowHash(seq int64, at time.Time, actor, action, target, ip, detail, prev string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s",
		seq, at.UTC().Format(time.RFC3339Nano), actor, action, target, ip, detail, prev)
	return hex.EncodeToString(h.Sum(nil))
}

// appendEvent adds one tamper-evident record. It reads the current tip's hash,
// links the new row to it, and stores the new row's hash as the next tip.
func appendEvent(ctx context.Context, actor, action, target, ip, detail string) error {
	appendMu.Lock()
	defer appendMu.Unlock()

	var prev string
	err := db.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil {
		prev = genesisHash // empty table -> chain from genesis
	}

	// Insert with a placeholder hash to get the assigned seq + timestamp, then
	// compute the real hash over the committed values and store it. Done in one
	// statement via RETURNING so seq/at are authoritative.
	var seq int64
	var at time.Time
	err = db.QueryRow(ctx, `
		INSERT INTO audit_events (actor, action, target, ip, detail, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,'') RETURNING seq, at`,
		actor, action, target, ip, detail, prev).Scan(&seq, &at)
	if err != nil {
		return err
	}
	h := rowHash(seq, at, actor, action, target, ip, detail, prev)
	_, err = db.Exec(ctx, `UPDATE audit_events SET hash = $1 WHERE seq = $2`, h, seq)
	return err
}

func handleAuditList(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(r.Context(),
		`SELECT seq, at, actor, action, target, ip, detail FROM audit_events ORDER BY seq`)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": err.Error()})
		return
	}
	out := []map[string]any{}
	for rows.Next() {
		var seq int64
		var at time.Time
		var actor, action, target, ip, detail string
		rows.Scan(&seq, &at, &actor, &action, &target, &ip, &detail)
		out = append(out, map[string]any{"seq": seq, "at": at, "actor": actor,
			"action": action, "target": target, "ip": ip, "detail": detail})
	}
	jsonOut(w, 200, out)
}

// handleAuditVerify walks the whole chain and re-derives each hash. If any row
// was edited, deleted, or reordered, the recomputed hash won't match the stored
// one (or the prev-link breaks) and we report the FIRST broken seq — that's
// where the tampering is.
func handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(r.Context(),
		`SELECT seq, at, actor, action, target, ip, detail, prev_hash, hash FROM audit_events ORDER BY seq`)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": err.Error()})
		return
	}
	prev := genesisHash
	count := 0
	for rows.Next() {
		var seq int64
		var at time.Time
		var actor, action, target, ip, detail, prevHash, storedHash string
		rows.Scan(&seq, &at, &actor, &action, &target, &ip, &detail, &prevHash, &storedHash)
		count++

		// 1. the row must link to the actual previous tip
		if prevHash != prev {
			jsonOut(w, 200, map[string]any{"valid": false, "broken_at_seq": seq,
				"reason": "prev_hash does not match the previous row's hash (a row was inserted/deleted/reordered)"})
			return
		}
		// 2. the stored hash must equal a fresh recomputation (row not edited)
		want := rowHash(seq, at, actor, action, target, ip, detail, prevHash)
		if want != storedHash {
			jsonOut(w, 200, map[string]any{"valid": false, "broken_at_seq": seq,
				"reason": "row contents were altered after the fact (recomputed hash != stored hash)"})
			return
		}
		prev = storedHash
	}
	jsonOut(w, 200, map[string]any{"valid": true, "events_verified": count,
		"note": "every row's hash checks out and the chain is unbroken"})
}

// handleTamper is a DEMO-ONLY endpoint: it edits a past audit row's detail
// directly, exactly as a malicious insider or attacker with DB access would.
// The point is that /audit/verify then catches it. No real system exposes this.
//
//	POST /audit/tamper  {"seq": 2, "new_detail": "covering my tracks"}
func handleTamper(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Seq       int64  `json:"seq"`
		NewDetail string `json:"new_detail"`
	}
	if err := readJSON(r, &in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "seq and new_detail required"})
		return
	}
	tag, _ := db.Exec(r.Context(),
		`UPDATE audit_events SET detail = $1 WHERE seq = $2`, in.NewDetail, in.Seq)
	if tag.RowsAffected() == 0 {
		jsonOut(w, 404, map[string]string{"error": "no such seq"})
		return
	}
	jsonOut(w, 200, map[string]string{"status": fmt.Sprintf("row %d edited directly (hash NOT updated) — now run /audit/verify", in.Seq)})
}
