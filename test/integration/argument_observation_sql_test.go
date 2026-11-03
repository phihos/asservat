package integration

import (
	"context"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual generated queries and constraints using an admitted capture and
// independently approved event ceilings. The header/mechanism pins are explicit
// synthetic SQL component data, not installed argument acquisition authority.
func qualifyArgumentObservationSQL(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, root, acceptance, grant string, accepted capture.Accepted) {
	t.Helper()
	id := func(s string) pgtype.UUID {
		var v pgtype.UUID
		if err := v.Scan(s); err != nil {
			t.Fatal(err)
		}
		return v
	}
	ts := func(v time.Time) pgtype.Timestamptz {
		return pgtype.Timestamptz{Time: v.UTC().Truncate(time.Microsecond), Valid: true}
	}
	params := func() custodydb.InsertArgumentObservationParams {
		now := time.Now().UTC().Truncate(time.Microsecond)
		ed := evidence.ContextExpectationDigest(accepted.Expectation)
		rule := collector.ArgumentObservationAccountingRule()
		pin := artifact.Digest{9}
		var policy string
		if err := admin.QueryRow(ctx, "SELECT policy_uid FROM policy_acceptance WHERE root_id=$1 AND id=$2", root, acceptance).Scan(&policy); err != nil {
			t.Fatal(err)
		}
		return custodydb.InsertArgumentObservationParams{ID: id(custodyID()), RootID: id(root), PolicyUid: pgtype.Text{String: policy, Valid: true}, AcceptanceID: id(acceptance), GrantID: id(grant), CaptureID: id(accepted.CaptureID), AttemptID: id(accepted.Expectation.Registration.Location.AttemptID), Fence: id(custodyID()), ActionID: accepted.Expectation.ActionID, PodUid: accepted.Expectation.PodUID, NodeUid: "synthetic-node", BootID: "synthetic-boot", CollectorPodUid: "synthetic-collector", CollectorEpoch: "synthetic-process", ExpectationDigest: ed[:], ProgramDigest: pin[:], BindingScope: pin[:], AccountingRule: rule[:], SourceObservedAt: ts(now), SourceFreshUntil: ts(now.Add(5 * time.Second)), StartedAt: ts(now), SessionUntil: ts(now.Add(70 * time.Second)), StartBy: ts(now.Add(10 * time.Second)), DurationMillis: 60000, Credit: 512, MaxBytesPerSecond: 512, ArgumentDefinitionDigest: pin[:], EventCredit: 1, MaxEventsPerSecond: 10, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxTrackedThreads: 4096}
	}
	read := func(want int64) {
		t.Helper()
		var pb, pe, gb, ge int64
		if err := admin.QueryRow(ctx, `SELECT a.observed_bytes_spent,a.observed_events_spent,g.policy_observed_bytes_spent,g.policy_observed_events_spent FROM policy_acceptance a JOIN access_grant g ON g.root_id=a.root_id AND g.id=$3 WHERE a.root_id=$1 AND a.id=$2`, root, acceptance, grant).Scan(&pb, &pe, &gb, &ge); err != nil || pe != want || ge != want || pb != want*512 || gb != want*512 {
			t.Fatal("dual aggregate spend", pb, pe, gb, ge, want, err)
		}
	}
	raw, err := fs.ReadFile(migrations.Files(), "00128_syscall_observation_events.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, _ := strings.Cut(string(raw), "-- +goose Down")
	// Even a retained session with zero counters blocks rollback. All changes in
	// this deliberate DDL-only probe roll back; production inserts follow debits.
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = custodydb.New(tx).InsertArgumentObservation(ctx, params()); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal("60-second original argument session", err)
	}
	_, err = tx.Exec(ctx, down)
	_ = tx.Rollback(ctx)
	if err == nil || !strings.Contains(err.Error(), "retained syscall observation event spend") {
		t.Fatal("retained session downgrade", err)
	}
	read(0)
	// A downstream insertion refusal rolls BOTH debits back.
	tx, err = hub.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q := custodydb.New(tx)
	n, err := q.SpendPolicyObservation(ctx, custodydb.SpendPolicyObservationParams{RootID: id(root), ID: id(acceptance), Bytes: 512, Events: 1})
	if err != nil || n != 1 {
		_ = tx.Rollback(ctx)
		t.Fatal(n, err)
	}
	n, err = q.SpendPolicyGrantObservation(ctx, custodydb.SpendPolicyGrantObservationParams{RootID: id(root), ID: id(grant), Bytes: 512, Events: 1})
	if err != nil || n != 1 {
		_ = tx.Rollback(ctx)
		t.Fatal(n, err)
	}
	invalid := params()
	invalid.MaxProbeBytes = 513
	if _, err = q.InsertArgumentObservation(ctx, invalid); err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("invalid mechanism persisted")
	}
	_ = tx.Rollback(ctx)
	read(0)
	// Accepted policy and current grant have independent ceilings (20 versus10).
	n, err = custodydb.New(hub).SpendPolicyObservation(ctx, custodydb.SpendPolicyObservationParams{RootID: id(root), ID: id(acceptance), Bytes: 512, Events: 21})
	if err != nil || n != 0 {
		t.Fatal("accepted event ceiling", n, err)
	}
	n, err = custodydb.New(hub).SpendPolicyGrantObservation(ctx, custodydb.SpendPolicyGrantObservationParams{RootID: id(root), ID: id(grant), Bytes: 512, Events: 11})
	if err != nil || n != 0 {
		t.Fatal("grant event ceiling", n, err)
	}
	var successes atomic.Int64
	var wg sync.WaitGroup
	failures := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := hub.Begin(ctx)
			if err != nil {
				failures <- err
				return
			}
			defer tx.Rollback(ctx)
			q := custodydb.New(tx)
			n, err := q.SpendPolicyObservation(ctx, custodydb.SpendPolicyObservationParams{RootID: id(root), ID: id(acceptance), Bytes: 512, Events: 1})
			if err != nil {
				failures <- err
				return
			}
			if n != 1 {
				return
			}
			n, err = q.SpendPolicyGrantObservation(ctx, custodydb.SpendPolicyGrantObservationParams{RootID: id(root), ID: id(grant), Bytes: 512, Events: 1})
			if err != nil {
				failures <- err
				return
			}
			if n != 1 {
				return
			}
			if err = tx.Commit(ctx); err != nil {
				failures <- err
				return
			}
			successes.Add(1)
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if successes.Load() != 10 {
		t.Fatal("concurrent original event budget", successes.Load())
	}
	read(10)
	// Persist a representative immutable original source tuple. SQL direct probes
	// above qualify debit concurrency; application tests own tuple-derived scopes.
	p := params()
	row, err := custodydb.New(hub).InsertArgumentObservation(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := custodydb.New(hub).ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: id(root), CaptureID: id(accepted.CaptureID)})
	if err != nil || row.ID != replay.ID || row.Fence != replay.Fence || !row.StartBy.Time.Equal(replay.StartBy.Time) || row.EventCredit != replay.EventCredit {
		t.Fatal("original tuple readback", err)
	}
	if _, err = custodydb.New(hub).InsertArgumentObservation(ctx, params()); err == nil {
		t.Fatal("same capture replaced original session")
	}
	if _, err = admin.Exec(ctx, "UPDATE policy_observation_session SET event_credit=event_credit+1 WHERE id=$1", row.ID); err == nil {
		t.Fatal("immutable credit refilled")
	}
	if _, err = admin.Exec(ctx, "UPDATE policy_acceptance SET observed_events_spent=0 WHERE id=$1", id(acceptance)); err == nil {
		t.Fatal("accepted counter reset")
	}
	if _, err = admin.Exec(ctx, "UPDATE access_grant SET policy_observed_events_spent=0 WHERE id=$1", id(grant)); err == nil {
		t.Fatal("grant counter reset")
	}
	tx, err = admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, down)
	_ = tx.Rollback(ctx)
	if err == nil || !strings.Contains(err.Error(), "retained syscall observation event spend") {
		t.Fatal("populated event downgrade", err)
	}
	read(10)
	t.Log("SQL128: independent20/10 event ceilings,32 contenders ->10 dual debits, immutable60-second session, failed insert rolls both pools back, retained-state rollback refused")
}
