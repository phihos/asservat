// Package experiment tests selected transactions. It is not production authority.
package experiment

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
)

var Denied = errors.New("denied")
var Conflict = errors.New("idempotency conflict")

type Beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}
type Request struct {
	ID, Digest, Grant, Workload string
	Bytes, Objects              int64
	Context                     bool
}

func Admit(ctx context.Context, db Beginner, r Request, beforeCommit func(pgx.Tx) error) (bool, error) {
	tx, e := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return false, e
	}
	defer tx.Rollback(context.Background())
	if r.Bytes <= 0 || r.Objects <= 0 {
		return false, Denied
	}
	var ready bool
	if e = tx.QueryRow(ctx, "SELECT ready FROM config WHERE id=1 FOR SHARE").Scan(&ready); e != nil {
		return false, e
	}
	if !ready {
		return false, Denied
	}
	var g string
	if e = tx.QueryRow(ctx, "SELECT id FROM grants WHERE id=$1 FOR UPDATE", r.Grant).Scan(&g); e != nil {
		return false, e
	}
	var capB, capO, usedB, usedO int64
	if e = tx.QueryRow(ctx, "SELECT burst_b,burst_o,used_b,used_o FROM pool WHERE id=1 FOR UPDATE").Scan(&capB, &capO, &usedB, &usedO); e != nil {
		return false, e
	}
	var pB, pO, cB, cO, hB, hO, nB, nO, xB, xO int64
	if e = tx.QueryRow(ctx, "SELECT protected_b,protected_o,context_b,context_o,hard_b,hard_o,non_b,non_o,ctx_b,ctx_o FROM workload WHERE id=$1 FOR UPDATE", r.Workload).Scan(&pB, &pO, &cB, &cO, &hB, &hO, &nB, &nO, &xB, &xO); e != nil {
		return false, e
	}
	var digest, grant, workload string
	e = tx.QueryRow(ctx, "SELECT digest,grant_id,workload_id FROM operation WHERE id=$1", r.ID).Scan(&digest, &grant, &workload)
	if e == nil {
		if digest != r.Digest || grant != r.Grant || workload != r.Workload {
			return false, Conflict
		}
		return false, tx.Commit(ctx)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return false, e
	}
	// All blocking authority/capacity locks precede the current-time check.
	var valid bool
	if e = tx.QueryRow(ctx, "SELECT NOT revoked AND expires>clock_timestamp() AND starts<max_starts FROM grants WHERE id=$1", r.Grant).Scan(&valid); e != nil {
		return false, e
	}
	if !valid {
		return false, Denied
	}
	dB, dO := int64(0), int64(0)
	if r.Context {
		if r.Bytes > cB-xB || r.Objects > cO-xO {
			return false, Denied
		}
		xB += r.Bytes
		xO += r.Objects
	} else {
		if r.Bytes > hB-cB-nB || r.Objects > hO-cO-nO {
			return false, Denied
		}
		dB = max(nB+r.Bytes-(pB-cB), 0) - max(nB-(pB-cB), 0)
		dO = max(nO+r.Objects-(pO-cO), 0) - max(nO-(pO-cO), 0)
		if dB > capB-usedB || dO > capO-usedO {
			return false, Denied
		}
		nB += r.Bytes
		nO += r.Objects
	}
	for _, q := range []struct {
		s string
		a []any
	}{
		{"UPDATE grants SET starts=starts+1 WHERE id=$1", []any{r.Grant}},
		{"UPDATE pool SET used_b=used_b+$1,used_o=used_o+$2 WHERE id=1", []any{dB, dO}},
		{"UPDATE workload SET non_b=$2,non_o=$3,ctx_b=$4,ctx_o=$5 WHERE id=$1", []any{r.Workload, nB, nO, xB, xO}},
		{"INSERT INTO operation(id,digest,grant_id,workload_id,bytes,objects,context) VALUES($1,$2,$3,$4,$5,$6,$7)", []any{r.ID, r.Digest, r.Grant, r.Workload, r.Bytes, r.Objects, r.Context}},
		{"INSERT INTO work(id) VALUES($1)", []any{r.ID}},
	} {
		if _, e = tx.Exec(ctx, q.s, q.a...); e != nil {
			return false, e
		}
	}
	if beforeCommit != nil {
		if e = beforeCommit(tx); e != nil {
			return false, e
		}
	}
	return true, tx.Commit(ctx)
}

func Publish(ctx context.Context, db Beginner, grant, art, client, capture string) error {
	tx, e := db.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var id string
	if e = tx.QueryRow(ctx, "SELECT id FROM grants WHERE id=$1 FOR UPDATE", grant).Scan(&id); e != nil {
		return e
	}
	var valid bool
	if e = tx.QueryRow(ctx, "SELECT committed AND capture=$2 FROM artifact WHERE id=$1 FOR SHARE", art, capture).Scan(&valid); e != nil {
		return e
	}
	if !valid {
		return Denied
	}
	// Artifact locking can wait past expiry; validate current authority after it.
	if e = tx.QueryRow(ctx, "SELECT NOT revoked AND expires>clock_timestamp() AND $2=ANY(clients) FROM grants WHERE id=$1", grant, client).Scan(&valid); e != nil {
		return e
	}
	if !valid {
		return Denied
	}
	var n, maxN int
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT (SELECT count(*) FROM result_artifact WHERE grant_id=$1),max_artifacts,EXISTS(SELECT 1 FROM result_artifact WHERE grant_id=$1 AND artifact_id=$2) FROM grants WHERE id=$1", grant, art).Scan(&n, &maxN, &exists); e != nil {
		return e
	}
	if !exists && n >= maxN {
		return Denied
	}
	if _, e = tx.Exec(ctx, "INSERT INTO result_artifact VALUES($1,$2) ON CONFLICT DO NOTHING", grant, art); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO child VALUES($1,$2,$3) ON CONFLICT DO NOTHING", grant, art, client); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func Spend(ctx context.Context, db Beginner, g, a, c string, n int64) error {
	if n <= 0 {
		return Denied
	}
	tx, e := db.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var id string
	if e = tx.QueryRow(ctx, "SELECT id FROM grants WHERE id=$1 FOR UPDATE", g).Scan(&id); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE grants SET result_spent=result_spent+$4 WHERE id=$1 AND NOT revoked AND expires>clock_timestamp() AND $4<=max_result-result_spent AND EXISTS(SELECT 1 FROM child WHERE grant_id=$1 AND artifact_id=$2 AND client=$3)`, g, a, c, n)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return Denied
	}
	return tx.Commit(ctx)
}
func Release(ctx context.Context, db Beginner, id string, verified bool) error {
	if !verified {
		return Denied
	}
	tx, e := db.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	// Immutable routing lookup does not lock. Mutable locks remain pool -> workload -> operation.
	var w string
	if e = tx.QueryRow(ctx, "SELECT workload_id FROM operation WHERE id=$1", id).Scan(&w); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "SELECT id FROM pool WHERE id=1 FOR UPDATE"); e != nil {
		return e
	}
	var nb, no, pb, po, cb, co int64
	if e = tx.QueryRow(ctx, "SELECT non_b,non_o,protected_b,protected_o,context_b,context_o FROM workload WHERE id=$1 FOR UPDATE", w).Scan(&nb, &no, &pb, &po, &cb, &co); e != nil {
		return e
	}
	var b, o int64
	var isctx bool
	var state string
	if e = tx.QueryRow(ctx, "SELECT bytes,objects,context,state FROM operation WHERE id=$1 FOR UPDATE", id).Scan(&b, &o, &isctx, &state); e != nil {
		return e
	}
	if state == "released" {
		return tx.Commit(ctx)
	}
	dburst, doburst := int64(0), int64(0)
	if isctx {
		_, e = tx.Exec(ctx, "UPDATE workload SET ctx_b=ctx_b-$2,ctx_o=ctx_o-$3 WHERE id=$1", w, b, o)
	} else {
		dburst = max(nb-(pb-cb), 0) - max(nb-b-(pb-cb), 0)
		doburst = max(no-(po-co), 0) - max(no-o-(po-co), 0)
		_, e = tx.Exec(ctx, "UPDATE workload SET non_b=non_b-$2,non_o=non_o-$3 WHERE id=$1", w, b, o)
	}
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE pool SET used_b=used_b-$1,used_o=used_o-$2 WHERE id=1", dburst, doburst); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE operation SET state='released' WHERE id=$1", id); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func Claim(ctx context.Context, tx pgx.Tx) (string, int64, error) {
	var id string
	var fence int64
	e := tx.QueryRow(ctx, `WITH selected AS (SELECT id FROM work WHERE audited AND NOT done AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE work w SET fence=fence+1,lease_until=clock_timestamp()+interval '30 seconds' FROM selected s WHERE w.id=s.id RETURNING w.id,w.fence`).Scan(&id, &fence)
	return id, fence, e
}
func request(id string, n int64) Request { return Request{id, "digest-" + id, "g", "a", n, 1, false} }
func reason(e error) string {
	if e == nil {
		return "ok"
	}
	return fmt.Sprint(e)
}
