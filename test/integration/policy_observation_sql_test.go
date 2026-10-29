package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This is a generated-query/DDL component test on a genuinely admitted capture.
// The node tuple, scope digest and observation review are explicit synthetic SQL
// facts on an ordinary header plan. They are never application/raw authority.
// Actual companion, authenticated node, prefix and complete backing remain gates.
func qualifyFinitePolicyObservationSQL(t *testing.T, ctx context.Context, admin, hub *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, root, acceptance, grant string, accepted capture.Accepted) {
	t.Helper()
	asID := func(s string) pgtype.UUID {
		var id pgtype.UUID
		if err := id.Scan(s); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ts := func(t time.Time) pgtype.Timestamptz {
		return pgtype.Timestamptz{Time: t.UTC().Truncate(time.Microsecond), Valid: true}
	}
	checkCode := func(err error, code string) {
		t.Helper()
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != code {
			t.Fatalf("want PostgreSQL %s, got %v", code, err)
		}
	}
	q := custodydb.New(hub)
	ed := evidence.ContextExpectationDigest(accepted.Expectation)
	marker := sha256.Sum256([]byte("synthetic-finite-sql-component-not-a-permit"))
	rule := collector.ObservationAccountingRule()
	if accepted.Expectation.Recording == nil || accepted.Expectation.Recording.DurationMillis != 1000 || accepted.Expectation.Recording.Filter == nil {
		t.Fatal("SQL fixture expected actual one-second frozen filter")
	}
	program := make([]planvalue.BPFInstruction, len(accepted.Expectation.Recording.Filter.Program))
	for i, ins := range accepted.Expectation.Recording.Filter.Program {
		program[i] = planvalue.BPFInstruction{Code: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	programDigest := planning.FilterProgramDigest(program)
	const credit = int64(32 << 20) // R*(one-second recording + one-second burst)
	params := func(now time.Time) custodydb.InsertPolicyObservationParams {
		return custodydb.InsertPolicyObservationParams{ID: asID(custodyID()), RootID: asID(root), PolicyUid: "", AcceptanceID: asID(acceptance), GrantID: asID(grant), CaptureID: asID(accepted.CaptureID), AttemptID: asID(accepted.Expectation.Registration.Location.AttemptID), Fence: asID(custodyID()), ActionID: accepted.Expectation.ActionID, PodUid: accepted.Expectation.PodUID, NodeUid: "synthetic-node", BootID: "synthetic-boot", CollectorPodUid: "synthetic-collector", CollectorEpoch: "synthetic-process", ExpectationDigest: ed[:], ProgramDigest: programDigest[:], BindingScope: marker[:], AccountingRule: rule[:], SourceObservedAt: ts(now), SourceFreshUntil: ts(now.Add(5 * time.Second)), StartedAt: ts(now), SessionUntil: ts(now.Add(10 * time.Second)), StartBy: ts(now.Add(5 * time.Second)), DurationMillis: 1000, Credit: credit, MaxBytesPerSecond: 16 << 20}
	}
	var policy string
	if err := admin.QueryRow(ctx, "SELECT policy_uid FROM policy_acceptance WHERE root_id=$1 AND id=$2", root, acceptance).Scan(&policy); err != nil {
		t.Fatal(err)
	}
	readSpend := func(want int64) {
		t.Helper()
		var policyBytes, grantBytes, sessions int64
		err := admin.QueryRow(ctx, `SELECT a.observed_bytes_spent,g.policy_observed_bytes_spent,(SELECT count(*) FROM policy_observation_session o WHERE o.root_id=a.root_id AND o.capture_id=$3)
   FROM policy_acceptance a JOIN access_grant g ON g.root_id=a.root_id AND g.id=$4 WHERE a.root_id=$1 AND a.id=$2`, root, acceptance, accepted.CaptureID, grant).Scan(&policyBytes, &grantBytes, &sessions)
		wantRows := int64(0)
		if want > 0 {
			wantRows = 1
		}
		if err != nil || policyBytes != want || grantBytes != want || sessions != wantRows {
			t.Fatalf("independent original pool/session read: accepted=%d grant=%d sessions=%d want=%d err=%v", policyBytes, grantBytes, sessions, want, err)
		}
	}
	debit := func(tx pgx.Tx) *custodydb.Queries {
		t.Helper()
		query := custodydb.New(tx)
		if _, err := query.LockPermissionStream(ctx, asID(root)); err != nil {
			t.Fatal(err)
		}
		if _, err := query.ReadGrantForUpdate(ctx, custodydb.ReadGrantForUpdateParams{RootID: asID(root), ID: asID(grant)}); err != nil {
			t.Fatal(err)
		}
		n, err := query.SpendPolicyObservedBytes(ctx, custodydb.SpendPolicyObservedBytesParams{RootID: asID(root), ID: asID(acceptance), Bytes: credit})
		if err != nil || n != 1 {
			t.Fatal("accepted observed debit", n, err)
		}
		n, err = query.SpendPolicyGrantObservedBytes(ctx, custodydb.SpendPolicyGrantObservedBytesParams{RootID: asID(root), ID: asID(grant), Bytes: credit})
		if err != nil || n != 1 {
			t.Fatal("grant observed debit", n, err)
		}
		return query
	}
	readSpend(0)
	active := func(want int64) {
		t.Helper()
		n, err := q.CountActivePolicyObservations(ctx, custodydb.CountActivePolicyObservationsParams{RootID: asID(root), AcceptanceID: asID(acceptance)})
		if err != nil || n != want {
			t.Fatalf("live original session count=%d want=%d err=%v", n, want, err)
		}
	}
	active(0)
	// Hold the actual insertion table after both real counter writes. The
	// database INSERT guard must reject the original source cutoff after waiting,
	// and the independent read must prove both debits rolled back.
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err = blocker.Exec(ctx, "LOCK TABLE policy_observation_session IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	tx, err := hub.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	query := debit(tx)
	now, err := query.CurrentTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expired := params(now.Time)
	expired.PolicyUid = policy
	expired.SourceFreshUntil = ts(now.Time.Add(300 * time.Millisecond))
	done := make(chan error, 1)
	pid := tx.Conn().PgConn().PID()
	go func() { _, err := query.InsertPolicyObservation(ctx, expired); done <- err }()
	joined := false
	defer func() {
		if joined {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = blocker.Rollback(cleanup)
		select {
		case <-done:
		case <-cleanup.Done():
			t.Error("owned insertion goroutine did not join after lock release")
		}
		_ = tx.Rollback(cleanup)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err = admin.QueryRow(ctx, "SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1", pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			joined = true
			t.Fatal("insert did not wait behind held table", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("owned insertion never reached actual lock wait")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if wait := time.Until(expired.SourceFreshUntil.Time.Add(50 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if err = blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		joined = true
		checkCode(err, "23514")
	case <-time.After(3 * time.Second):
		t.Fatal("expired insertion did not finish")
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	readSpend(0)
	t.Log("actual held-table original source cutoff: INSERT CHECK23514; independent accepted/grant observed spend=0 and sessions=0 after rollback")

	// A fresh original tuple commits the same finite debit exactly once.
	var lsn string
	if err = admin.QueryRow(ctx, "SELECT pg_current_wal_insert_lsn()::text").Scan(&lsn); err != nil {
		t.Fatal(err)
	}
	tx, err = hub.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	query = debit(tx)
	now, err = query.CurrentTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original := params(now.Time)
	original.PolicyUid = policy
	row, err := query.InsertPolicyObservation(ctx, original)
	if err != nil {
		t.Fatal("finite original SQL tuple", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	readSpend(credit)
	active(1)
	for _, amount := range []int64{0, -1, (1 << 30) - credit + 1} {
		n, err := q.SpendPolicyObservedBytes(ctx, custodydb.SpendPolicyObservedBytesParams{RootID: asID(root), ID: asID(acceptance), Bytes: amount})
		if err != nil || n != 0 {
			t.Fatal("accepted observed pool accepted nonpositive/excess debit", amount, n, err)
		}
		n, err = q.SpendPolicyGrantObservedBytes(ctx, custodydb.SpendPolicyGrantObservedBytesParams{RootID: asID(root), ID: asID(grant), Bytes: amount})
		if err != nil || n != 0 {
			t.Fatal("grant observed pool accepted nonpositive/excess debit", amount, n, err)
		}
	}
	replay, err := q.ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: asID(root), CaptureID: asID(accepted.CaptureID)})
	if err != nil || !reflect.DeepEqual(row, replay) {
		t.Fatal("immutable original SQL receipt replay", err)
	}
	now, err = q.CurrentTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := params(now.Time) // fresh dates/new session/fence cannot rearm this capture
	duplicate.PolicyUid = policy
	_, err = q.InsertPolicyObservation(ctx, duplicate)
	checkCode(err, "23505")
	_, err = admin.Exec(ctx, "UPDATE policy_observation_session SET credit=credit+1 WHERE id=$1", original.ID)
	checkCode(err, "23514")
	_, err = admin.Exec(ctx, "UPDATE policy_observation_session SET collector_epoch='replacement' WHERE id=$1", original.ID)
	checkCode(err, "23514")
	readSpend(credit)
	var rowBytes, relationBytes, wal int64
	if err = admin.QueryRow(ctx, `SELECT pg_column_size(o),pg_total_relation_size('policy_observation_session'),pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$2::pg_lsn)::bigint FROM policy_observation_session o WHERE id=$1`, row.ID, lsn).Scan(&rowBytes, &relationBytes, &wal); err != nil {
		t.Fatal(err)
	}
	t.Logf("SQL component sample only: session tuple=%dB entire current observation relation/indexes=%dB global WAL delta including debit/insert/negative mutations=%dB; not whole-graph/worst-case backing qualification", rowBytes, relationBytes, wal)

	role := narrowRole(t, ctx, admin, "finite_observation_finalize_", "synthetic-observation-finalize", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("context-cleanup-finalize", role)
		if !ok {
			t.Fatal("finalizer purpose")
		}
		return grants
	})
	finalizer := poolFor(role, "synthetic-observation-finalize")
	defer finalizer.Close()
	retire := custodydb.New(finalizer)
	_, err = retire.RetirePolicyObservation(ctx, custodydb.RetirePolicyObservationParams{RootID: asID(root), CaptureID: asID(accepted.CaptureID)})
	checkCode(err, "23514")
	if wait := time.Until(row.LeaseUntil.Time.Add(30 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	_, err = retire.RetirePolicyObservation(ctx, custodydb.RetirePolicyObservationParams{RootID: asID(root), CaptureID: asID(accepted.CaptureID)})
	checkCode(err, "23514")
	readSpend(credit)
	active(0) // expiry releases concurrency, never prepaid observed bytes or row
	t.Log("actual compiled finalizer: early and expired-but-unfinalized retirement CHECK23514; original conservative observed spend retained; no packet acquisition/native artifact")
}
