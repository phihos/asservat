package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type packetReplayState struct {
	controls, calls int64
	immutable       string
}

func readPacketReplayState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q query.ContextQuery) packetReplayState {
	t.Helper()
	var state packetReplayState
	err := pool.QueryRow(ctx, `SELECT q.controls,(SELECT count(*) FROM context_query_call c WHERE c.query_id=q.id),jsonb_build_object('query',to_jsonb(q)-'controls','queries',(SELECT count(*) FROM context_query x WHERE x.root_id=q.root_id),'root',(SELECT to_jsonb(b) FROM context_query_backing b WHERE b.root_id=q.root_id),'workload',(SELECT to_jsonb(a) FROM context_query_allocation a WHERE a.id=q.allocation_id AND a.root_id=q.root_id),'accounts',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM context_query_principal p WHERE p.root_id=q.root_id),'workers',(SELECT count(*) FROM context_query_worker w WHERE w.query_id=q.id),'batches',(SELECT count(*) FROM context_query_batch b WHERE b.query_id=q.id),'uses',(SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM access_grant_use u WHERE u.root_id=q.root_id),'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM access_grant g WHERE g.root_id=q.root_id))::text FROM context_query q WHERE q.id=$1 AND q.root_id=$2`, q.ID, q.Scope.RootID).Scan(&state.controls, &state.calls, &state.immutable)
	if err != nil {
		t.Fatal("replay accounting snapshot", err)
	}
	return state
}
func assertPacketReplayDelta(t *testing.T, before, after packetReplayState, delta int64) {
	t.Helper()
	if after.controls != before.controls+delta || after.calls != before.calls+delta || after.immutable != before.immutable {
		t.Fatalf("replay controls=%d/%d calls=%d/%d immutableEqual=%t", after.controls, before.controls+delta, after.calls, before.calls+delta, after.immutable == before.immutable)
	}
}
func qualifyPacketReplayBindings(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, ledger *postgres.ContextQueries, q query.ContextQuery, r query.ContextQueryRequest, a query.ContextProjectionAuthority, auditor *auditapp.HealthyOperationAuditor, intent audit.OperationIntent) {
	t.Helper()
	before := readPacketReplayState(t, ctx, admin, q)
	if err := ledger.RegisterQueryReplayCall(ctx, q, r, a); err != nil {
		t.Fatal("same replay registration idempotence", err)
	}
	if err := ledger.PermitQuery(ctx, q, r, a); err != nil {
		t.Fatal("strict registered replay permit", err)
	}
	assertPacketReplayDelta(t, before, readPacketReplayState(t, ctx, admin, q), 0)
	for name, change := range map[string]func(*query.ContextQuery, *query.ContextQueryRequest){
		"normalized-input-mac":       func(_ *query.ContextQuery, r *query.ContextQueryRequest) { r.Call.InputDigest[0] ^= 1 },
		"mac-version":                func(_ *query.ContextQuery, r *query.ContextQueryRequest) { r.Call.MACVersion = "different" },
		"caller-key":                 func(q *query.ContextQuery, _ *query.ContextQueryRequest) { q.InvocationKey.Key += "changed" },
		"caller-key-digest":          func(q *query.ContextQuery, _ *query.ContextQueryRequest) { q.InvocationKey.RequestDigest[0] ^= 1 },
		"client":                     func(_ *query.ContextQuery, r *query.ContextQueryRequest) { r.Call.Principal.ClientID += "changed" },
		"expired-request":            func(_ *query.ContextQuery, r *query.ContextQueryRequest) { r.Call.Until = time.Now().Add(-time.Second) },
		"poll-masquerading-as-begin": func(_ *query.ContextQuery, r *query.ContextQueryRequest) { r.Call.Tool = "get_query_result" },
	} {
		t.Run("replay-refuses-"+name, func(t *testing.T) {
			badQ, badR := q, r
			change(&badQ, &badR)
			if err := ledger.RegisterQueryReplayCall(ctx, badQ, badR, a); err == nil {
				t.Fatal("changed replay accepted")
			}
			assertPacketReplayDelta(t, before, readPacketReplayState(t, ctx, admin, q), 0)
		})
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := ledger.RegisterQueryReplayCall(cancelled, q, r, a); err == nil {
		t.Fatal("cancelled replay accepted")
	}
	// The SQL role independently refuses a genuinely acknowledged Begin whose
	// MAC binds different normalized input, even when Go registration is bypassed.
	wrong := intent
	n := time.Now().UTC().Truncate(time.Microsecond)
	wrong.ID, wrong.TraceID = custodyID(), custodyID()
	wrong.InputDigest = artifact.Digest{99}
	wrong.CreatedAt = n
	wrong.RequestUntil = n.Add(5 * time.Second)
	wrong.WriteUntil = n.Add(30 * time.Second)
	call, stopCall := context.WithDeadline(ctx, wrong.RequestUntil)
	defer stopCall()
	if err := auditor.Begin(call, wrong); err != nil {
		t.Fatal("real wrong-input intent", err)
	}
	bad := r
	bad.Call.ID = wrong.ID
	bad.Call.InputDigest = wrong.InputDigest
	bad.Call.StartedAt = n
	bad.Call.Until = wrong.RequestUntil
	bad.Call.WriteUntil = wrong.WriteUntil
	bad.OwnerID = custodyID()
	if err := ledger.RegisterQueryReplayCall(call, q, bad, a); err == nil {
		t.Fatal("real acknowledged different-input replay accepted")
	}
	encoded, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	_, err = hub.Exec(call, `INSERT INTO context_query_call(operation_id,query_id,request,is_poll) VALUES($1,$2,$3,false)`, wrong.ID, q.ID, encoded)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("compiled role bypassed replay SQL input binding", err)
	}
	assertPacketReplayDelta(t, before, readPacketReplayState(t, ctx, admin, q), 0)
	out := audit.OperationOutcome{Intent: wrong, Status: "unavailable", Reason: "not_available", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{98}, OutputBytes: 0, MetadataUntil: wrong.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if err = auditor.Finish(ctx, out); err != nil {
		t.Fatal("wrong replay actual refusal acknowledgement", err)
	}
	t.Log("real acknowledged changed-input replay denied by adapter and compiled SQL; same-call replay no control/poll/query/read/grant debit; current source/grant and original query unchanged")
}

func qualifyPacketReplayCannotRead(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, ledger *postgres.ContextQueries, q query.ContextQuery, r query.ContextQueryRequest, w query.ContextQueryWorker, a query.ContextProjectionAuthority, raw bool) {
	t.Helper()
	before := readPacketReplayState(t, ctx, admin, q)
	if !q.Current(a, time.Now()) || !r.Valid(time.Now()) || !w.Matches(q) {
		t.Fatal("replay no-read control invalid")
	}
	if _, err := ledger.BeginReadBatch(ctx, q, r, w, custodyID(), a); err == nil {
		t.Fatal("replay Begin funded a batch")
	}
	assertPacketReplayDelta(t, before, readPacketReplayState(t, ctx, admin, q), 0)
	now := time.Now().UTC().Truncate(time.Microsecond)
	end := q.Deadline
	for _, cut := range []time.Time{r.Call.Until, a.ValidUntil} {
		if cut.Before(end) {
			end = cut
		}
	}
	batch := query.ContextReadBatch{ID: custodyID(), QueryID: q.ID, OperationID: r.Call.ID, Generation: 1, Worker: w, Request: r, StartedAt: now, Until: end, CleanupUntil: q.CleanupUntil}
	if !batch.Current(q, a, now) {
		t.Fatal("SQL purpose control batch invalid")
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := hub.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if raw {
		if _, err = tx.Exec(ctx, `UPDATE access_grant SET bytes_spent=bytes_spent+24576,operations_spent=operations_spent+1 WHERE root_id=$1 AND id=$2`, q.Scope.RootID, q.Grant.ParentID); err != nil {
			t.Fatal("replay purpose control debit", err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO access_grant_use(id,root_id,parent_id,child_id,operation,bytes,operations) VALUES($1,$2,$3,$4,$5,24576,1)`, batch.ID, q.Scope.RootID, q.Grant.ParentID, q.Grant.ChildID, q.Scope.BeginTool()); err != nil {
			t.Fatal("replay purpose control use", err)
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO context_query_batch(id,query_id,operation_id,generation,batch) VALUES($1,$2,$3,$4,$5)`, batch.ID, q.ID, r.Call.ID, batch.Generation, body)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" || pg.Message != "query batch unavailable" {
		t.Fatal("compiled role accepted replay-call read purpose", err)
	}
	if err = tx.Rollback(context.Background()); err != nil {
		t.Fatal("replay purpose control rollback", err)
	}
	assertPacketReplayDelta(t, before, readPacketReplayState(t, ctx, admin, q), 0)
	t.Log("replay call cannot create a batch: adapter and compiled SQL purpose guards deny; controlled reservation transaction rolled back without debit")
}
