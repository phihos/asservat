package integration

import (
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualifyContextControlCapacity(t *testing.T, ctx context.Context, admin, capturePool, configPool *pgxpool.Pool, storage, backing *postgres.Ledger, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T, int64, int64, int64) captureAdmissionScenario) {
	t.Helper()
	// The early concurrency cases must not leave their expanded connection pools
	// alive throughout later download/worker qualification. Give this helper its
	// own purpose-separated pools; the common scenario factory stays sequential.
	capturePool = poolFor("capture_runtime", "synthetic-capture")
	defer capturePool.Close()
	configPool = poolFor("context_control_config_runtime", "synthetic-context-control-config")
	defer configPool.Close()
	var err error
	backing, err = postgres.New(ctx, configPool)
	if err != nil {
		t.Fatal(err)
	}
	createOriginal := create
	create = func(t *testing.T, slots, full, replay int64) captureAdmissionScenario {
		t.Helper()
		s := createOriginal(t, slots, full, replay)
		admissions, err := postgres.NewContextAdmissions(ctx, capturePool, s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
		if err != nil {
			t.Fatal(err)
		}
		s.s = admissions
		return s
	}
	qualifyContextControlMigration(t, ctx, admin, create)
	charge := func(t *testing.T, s captureAdmissionScenario, full, replay int64) {
		t.Helper()
		var a, b int64
		if err := admin.QueryRow(ctx, "SELECT charged_full,charged_replay FROM context_control_account WHERE root_id=$1 AND allocation_id=$2", s.a.RootID, s.a.Registration.AllocationID).Scan(&a, &b); err != nil || a != full || b != replay {
			t.Fatalf("control charge got %d/%d want %d/%d: %v", a, b, full, replay, err)
		}
	}
	fresh := func(t *testing.T, s captureAdmissionScenario, key string) captureAdmissionScenario {
		t.Helper()
		in := s.a.Plan.Input
		in.CaptureID = custodyID()
		p, err := planning.CompileContext(in, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		s.a.Plan = p
		s.a.IdempotencyKey = key
		s.a.Registration.Location.ArtifactID = custodyID()
		s.a.Registration.Location.AttemptID = custodyID()
		s.a.CaseID = custodyID()
		s.a.OccurrenceID = custodyID()
		return s
	}
	t.Run("control-capacity-concurrent-replay-charged-once", func(t *testing.T) {
		s := create(t, 8, 1, 1)
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Add(1)
			go func() { defer wg.Done(); _, err := s.s.AdmitContext(ctx, s.a); errs <- err }()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		charge(t, s, 1, 1)
		next := fresh(t, s, "new-operation")
		if _, err := next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrCapacity) {
			t.Fatal("exhausted metadata accepted", err)
		}
		charge(t, s, 1, 1)
		if got, err := s.s.AdmitContext(ctx, s.a); err != nil || !got.Replay {
			t.Fatal("quota exhaustion prevented original replay", err)
		}
	})
	t.Run("distinct-concurrent-requests-cannot-overdraw-control-slots", func(t *testing.T) {
		s := create(t, 8, 1, 1)
		requests := make([]captureAdmissionScenario, 8)
		for i := range requests {
			requests[i] = fresh(t, s, "concurrent-"+strconv.Itoa(i))
		}
		var wg sync.WaitGroup
		errs := make(chan error, len(requests))
		for _, request := range requests {
			wg.Add(1)
			go func() { defer wg.Done(); _, err := request.s.AdmitContext(ctx, request.a); errs <- err }()
		}
		wg.Wait()
		close(errs)
		accepted := 0
		for err := range errs {
			if err == nil {
				accepted++
			} else if !errors.Is(err, capture.ErrCapacity) {
				t.Fatal(err)
			}
		}
		if accepted != 1 {
			t.Fatal("wrong admission count", accepted)
		}
		charge(t, s, 1, 1)
	})
	t.Run("control-replay-slot-exhaustion-is-independent-of-full-records", func(t *testing.T) {
		s := create(t, 4, 4, 1)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		next := fresh(t, s, "other-operation")
		if _, err := next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrCapacity) {
			t.Fatal(err)
		}
		charge(t, s, 1, 1)
	})
	t.Run("same-root-workload-retains-protected-capacity", func(t *testing.T) {
		a := create(t, 4, 1, 1)
		// The second workload shares the actual permission/retention root and
		// namespace. Its storage and metadata allocations are independently backed.
		b := fresh(t, a, "workload-b")
		in := b.a.Plan.Input
		in.Target.Request.Workload.UID = custodyID()
		in.Target.Request.Workload.Name = "worker"
		in.Target.Request.PodUID = custodyID()
		in.Target.Request.PodName = "worker-123"
		in.Target.Pin.UID = in.Target.Request.PodUID
		in.Target.Pin.Name = in.Target.Request.PodName
		if err := a.retention.observe(ctx); err != nil {
			t.Fatal(err)
		}
		policies, err := (privacyapp.AcceptedRetentionReader{Topology: a.retention.topology, Sources: a.retention.reader, Now: time.Now}).RetentionPolicies(ctx, in.Target.Target())
		if err != nil {
			t.Fatal(err)
		}
		in.Retention, err = privacy.Resolve(policies, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: in.Retention.AnchorAt}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		in.Target.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		in.Target.FreshUntil = in.Target.ObservedAt.Add(5 * time.Second)
		b.a.Plan, err = planning.CompileContext(in, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		projection, err := a.p.Permissions(ctx, in.Target.Target())
		if err != nil {
			t.Fatal(err)
		}
		b.a.Eligibility = authorization.ContextEligibility(a.a.Eligibility.VerifiedIdentity, projection, in.Target.Target(), time.Now())
		if !b.a.Eligibility.Eligible {
			t.Fatal(b.a.Eligibility.Reason)
		}
		allocation := custodyID()
		b.a.Registration.AllocationID = allocation
		b.a.Storage.AllocationID = allocation
		b.a.Storage.WorkloadUID = in.Target.Request.Workload.UID
		if err = storage.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: allocation, PoolID: a.poolID, ScopeID: custodyID(), ServiceClass: "context", PoolRevision: 1, Revision: 1, Bytes: b.a.Registration.ReservedBytes() * 4, Objects: 16, ValidUntil: a.a.Registration.AnchorAt.Add(30 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, "INSERT INTO context_storage_binding(root_id,cluster_id,namespace_uid,workload_uid,allocation_id,source_uid,source_generation,source_digest,observed_at,fresh_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", b.a.RootID, b.a.Storage.ClusterID, b.a.Storage.NamespaceUID, b.a.Storage.WorkloadUID, allocation, b.a.Storage.Revision.UID, b.a.Storage.Revision.Generation, b.a.Storage.Revision.Digest[:], b.a.Storage.ObservedAt, b.a.Storage.FreshUntil); err != nil {
			t.Fatal(err)
		}
		if err = backing.ProvisionContextControlAllocation(ctx, capacity.ContextControlAllocation{ObservedAt: time.Now().UTC().Truncate(time.Microsecond), FreshUntil: time.Now().UTC().Truncate(time.Microsecond).Add(4 * time.Second), RootID: b.a.RootID, AllocationID: allocation, PoolRevision: 1, Revision: 1, FullRecords: 2, ReplayRecords: 1, ValidUntil: a.a.Registration.AnchorAt.Add(30 * time.Minute)}); !errors.Is(err, privacyapp.ErrCapacity) {
			t.Fatal("workload overbooked root control backing", err)
		}
		if err = backing.ProvisionContextControlAllocation(ctx, capacity.ContextControlAllocation{ObservedAt: time.Now().UTC().Truncate(time.Microsecond), FreshUntil: time.Now().UTC().Truncate(time.Microsecond).Add(4 * time.Second), RootID: b.a.RootID, AllocationID: allocation, PoolRevision: 1, Revision: 1, FullRecords: 1, ReplayRecords: 1, ValidUntil: a.a.Registration.AnchorAt.Add(30 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		if err = backing.ProvisionContextControlPool(ctx, capacity.ContextControlPool{RootID: a.a.RootID, ExpectedRevision: 1, Revision: 2, FullRecords: 1, ReplayRecords: 2, ValidUntil: a.a.Registration.AnchorAt.Add(30 * time.Minute), ObservedAt: stamp, FreshUntil: stamp.Add(5 * time.Second)}); !errors.Is(err, privacyapp.ErrCapacity) {
			t.Fatal("root shrink undercut B backing", err)
		}
		if _, err = a.s.AdmitContext(ctx, a.a); err != nil {
			t.Fatal(err)
		}
		again := fresh(t, a, "over-budget-a")
		if _, err = again.s.AdmitContext(ctx, again.a); !errors.Is(err, capture.ErrCapacity) {
			t.Fatal(err)
		}
		if _, err = b.s.AdmitContext(ctx, b.a); err != nil {
			t.Fatal("A consumed B capacity", err)
		}
		charge(t, a, 1, 1)
		charge(t, b, 1, 1)
	})
	t.Run("control-expiry-renewal-and-independent-suspension-preserve-spend", func(t *testing.T) {
		s := create(t, 4, 2, 2)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		poolUpdate := func(expected int64, paused bool, until time.Time) capacity.ContextControlPool {
			now := time.Now().UTC().Truncate(time.Microsecond)
			return capacity.ContextControlPool{RootID: s.a.RootID, ExpectedRevision: expected, Revision: expected + 1, FullRecords: 4, ReplayRecords: 4, Paused: paused, ValidUntil: until, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		}
		accountUpdate := func(expected, poolRevision int64, paused bool, full int64) capacity.ContextControlAllocation {
			now := time.Now().UTC().Truncate(time.Microsecond)
			return capacity.ContextControlAllocation{RootID: s.a.RootID, AllocationID: s.a.Registration.AllocationID, PoolRevision: poolRevision, ExpectedRevision: expected, Revision: expected + 1, FullRecords: full, ReplayRecords: 2, Paused: paused, ValidUntil: s.a.Registration.AnchorAt.Add(30 * time.Minute), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		}
		short := poolUpdate(1, false, time.Now().UTC().Truncate(time.Microsecond).Add(150*time.Millisecond))
		if err := backing.ProvisionContextControlPool(ctx, short); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		next := fresh(t, s, "after-renewal")
		if _, err := next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("expired control pool allowed admission", err)
		}
		if err := backing.ProvisionContextControlPool(ctx, short); err != nil {
			t.Fatal("exact historical configuration replay", err)
		}
		if _, err := next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("historical replay re-extended pool", err)
		}
		if err := backing.ProvisionContextControlPool(ctx, poolUpdate(2, false, s.a.Registration.AnchorAt.Add(30*time.Minute))); err != nil {
			t.Fatal("same-root renewal failed", err)
		}
		if err := backing.ProvisionContextControlAllocation(ctx, accountUpdate(1, 3, true, 2)); err != nil {
			t.Fatal(err)
		}
		if _, err := next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("paused account allowed capture", err)
		}
		if old, err := s.s.AdmitContext(ctx, s.a); err != nil || !old.Replay {
			t.Fatal("pause blocked accepted replay", err)
		}
		if err := backing.ProvisionContextControlAllocation(ctx, accountUpdate(2, 3, false, 2)); err != nil {
			t.Fatal(err)
		}
		if err := backing.ProvisionContextControlPool(ctx, poolUpdate(3, true, s.a.Registration.AnchorAt.Add(30*time.Minute))); err != nil {
			t.Fatal(err)
		}
		if _, err := next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("paused root allowed capture", err)
		}
		if err := backing.ProvisionContextControlPool(ctx, poolUpdate(4, false, s.a.Registration.AnchorAt.Add(30*time.Minute))); err != nil {
			t.Fatal(err)
		}
		shortAccount := accountUpdate(3, 5, false, 3)
		shortAccount.ValidUntil = time.Now().UTC().Truncate(time.Microsecond).Add(150 * time.Millisecond)
		if err := backing.ProvisionContextControlAllocation(ctx, shortAccount); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if _, err := next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("expired account admitted capture", err)
		}
		if err := backing.ProvisionContextControlAllocation(ctx, shortAccount); err != nil {
			t.Fatal("expired exact account replay", err)
		}
		if _, err := next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrChanged) {
			t.Fatal("account replay re-extended expiry", err)
		}
		if err := backing.ProvisionContextControlAllocation(ctx, accountUpdate(4, 5, false, 3)); err != nil {
			t.Fatal("same-account renewal failed", err)
		}
		if _, err := next.s.AdmitContext(ctx, next.a); err != nil {
			t.Fatal("renewed capacity unavailable", err)
		}
		if err := backing.ProvisionContextControlAllocation(ctx, accountUpdate(5, 5, false, 1)); !errors.Is(err, privacyapp.ErrCapacity) {
			t.Fatal("shrink forgot retained charges", err)
		}
		if err := backing.ProvisionContextControlAllocation(ctx, accountUpdate(5, 5, false, 2)); err != nil {
			t.Fatal("safe shrink of unused backing failed", err)
		}
		charge(t, s, 2, 2)
		var backed int64
		if err := admin.QueryRow(ctx, "SELECT backed_full FROM context_control_pool WHERE root_id=$1", s.a.RootID).Scan(&backed); err != nil || backed != 2 {
			t.Fatal("unused backing shrink mismatch", backed, err)
		}
		if err := backing.ProvisionContextControlPool(ctx, short); !errors.Is(err, privacyapp.ErrConflict) {
			t.Fatal("old revision rewound renewed pool", err)
		}
	})
	t.Run("control-configuration-CAS-and-original-observation-survive-locks", func(t *testing.T) {
		s := create(t, 2, 2, 2)
		now := time.Now().UTC().Truncate(time.Microsecond)
		update := capacity.ContextControlPool{RootID: s.a.RootID, ExpectedRevision: 1, Revision: 2, FullRecords: 4, ReplayRecords: 4, ValidUntil: s.a.Registration.AnchorAt.Add(30 * time.Minute), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		other := update
		other.FullRecords = 5
		errs := make(chan error, 2)
		go func() { errs <- backing.ProvisionContextControlPool(ctx, update) }()
		go func() { errs <- backing.ProvisionContextControlPool(ctx, other) }()
		accepted := 0
		for range 2 {
			err := <-errs
			if err == nil {
				accepted++
			} else if !errors.Is(err, privacyapp.ErrConflict) {
				t.Fatal(err)
			}
		}
		if accepted != 1 {
			t.Fatal("concurrent configuration replaced two revisions", accepted)
		}
		charge(t, s, 0, 0)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.a.RootID); err != nil {
			t.Fatal(err)
		}
		update.ExpectedRevision = 2
		update.Revision = 3
		update.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		update.FreshUntil = update.ObservedAt.Add(150 * time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- backing.ProvisionContextControlPool(ctx, update) }()
		time.Sleep(300 * time.Millisecond)
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-done; !errors.Is(err, privacyapp.ErrExpired) {
			t.Fatal("blocking work renewed configuration observation", err)
		}
		var revision int64
		if err = admin.QueryRow(ctx, "SELECT revision FROM context_control_pool WHERE root_id=$1", s.a.RootID).Scan(&revision); err != nil || revision != 2 {
			t.Fatal("expired update persisted", revision, err)
		}
	})
	t.Run("control-role-cannot-refund-rewrite-delete-or-bypass-charges", func(t *testing.T) {
		s := create(t, 2, 1, 1)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		for _, pool := range []*pgxpool.Pool{capturePool, configPool} {
			for _, sql := range []string{
				"UPDATE context_control_account SET charged_full=0", "UPDATE context_control_account SET charged_replay=0", "UPDATE context_control_pool SET backed_full=0", "DELETE FROM context_control_charge", "DELETE FROM context_control_account", "DELETE FROM context_control_pool", "SELECT reserve_context_control_charge()", "SELECT back_context_control_account()",
			} {
				_, err := pool.Exec(ctx, sql)
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
					t.Fatalf("expected role denial for %s: %v", sql, err)
				}
			}
		}
		for _, sql := range []string{"UPDATE context_control_account SET full_limit=full_limit+1", "UPDATE context_control_pool SET full_limit=full_limit+1", "UPDATE context_control_account SET configured=false"} {
			if _, err := configPool.Exec(ctx, sql); err == nil {
				t.Fatal("configuration rewrote immutable backing", sql)
			}
		}
		charge(t, s, 1, 1)
		for _, function := range []string{"reserve_context_control_charge()", "back_context_control_account()", "require_context_control_charge()"} {
			var pinned, private bool
			if err := admin.QueryRow(ctx, "SELECT proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[], NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc WHERE oid=$1::regprocedure", function).Scan(&pinned, &private); err != nil || !pinned || !private {
				t.Fatal(function, pinned, private, err)
			}
		}
	})
	t.Run("capture-charge-is-a-deferred-database-invariant", func(t *testing.T) {
		s := create(t, 2, 2, 2)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		attempt, artifactID, captureID := custodyID(), custodyID(), custodyID()
		// An administrator constructs an intentionally incomplete transaction.
		// It is always rolled back; the test proves SQL itself rejects omission,
		// independently of the application's successful admission path.
		if _, err = tx.Exec(ctx, `INSERT INTO custody_attempt(id,cluster_id,artifact_id,allocation_id,request_digest,pool_revision,allocation_revision,native_limit,reserved_bytes,anchor_at,write_until,expires_at,delete_by)
SELECT $1,cluster_id,$2,allocation_id,request_digest,pool_revision,allocation_revision,native_limit,reserved_bytes,anchor_at,write_until,expires_at,delete_by FROM custody_attempt WHERE id=$3`, attempt, artifactID, s.a.Registration.Location.AttemptID); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO context_capture(id,root_id,request_key,submission_digest,scope_digest,scope_json,expectation_json,pod_pin_json,attempt_id,permission_epoch,permission_sequence,identity_policy_uid,identity_policy_generation,identity_policy_digest,deadline)
SELECT $1,root_id,decode(repeat('ef',32),'hex'),submission_digest,scope_digest,scope_json,expectation_json,pod_pin_json,$2,permission_epoch,permission_sequence,identity_policy_uid,identity_policy_generation,identity_policy_digest,deadline FROM context_capture WHERE id=$3`, captureID, attempt, s.a.Plan.Input.CaptureID); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, "SET CONSTRAINTS context_control_capture_charge IMMEDIATE")
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Fatal("capture without charge reached constraint check", err)
		}
	})
	t.Run("backing-cannot-overbook-root-or-adopt-another-root-storage", func(t *testing.T) {
		s := create(t, 2, 1, 1)
		other := create(t, 2, 1, 1)
		err := backing.ProvisionContextControlAllocation(ctx, capacity.ContextControlAllocation{ObservedAt: time.Now().UTC().Truncate(time.Microsecond), FreshUntil: time.Now().UTC().Truncate(time.Microsecond).Add(4 * time.Second), RootID: s.a.RootID, AllocationID: other.a.Registration.AllocationID, PoolRevision: 1, Revision: 1, FullRecords: 1, ReplayRecords: 1, ValidUntil: s.a.Registration.AnchorAt.Add(time.Minute)})
		if err == nil {
			t.Fatal("foreign allocation accepted")
		}
		if err = backing.ProvisionContextControlPool(ctx, capacity.ContextControlPool{ObservedAt: time.Now().UTC().Truncate(time.Microsecond), FreshUntil: time.Now().UTC().Truncate(time.Microsecond).Add(4 * time.Second), RootID: s.a.RootID, Revision: 1, FullRecords: 1000, ReplayRecords: 1000, ValidUntil: s.a.Registration.AnchorAt.Add(time.Hour)}); !errors.Is(err, privacyapp.ErrConflict) {
			t.Fatal("same revision changed pool backing", err)
		}
	})
	t.Run("retirement-facts-never-release-uncertain-or-deleted-history", func(t *testing.T) {
		s := create(t, 2, 1, 1)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		pool := poolFor("context_retirement_read_runtime", "synthetic-context-retirement-read")
		defer pool.Close()
		reader, err := postgres.NewContextRetirementReads(ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		facts, err := reader.ContextRetirementDependencies(ctx, s.a.Plan.Input.CaptureID)
		if err != nil || facts.CustodyDeleted || !facts.IntentAuditPending || !facts.VerificationAuditPending || !facts.ExecutionUnresolved {
			t.Fatal("uncertain history not retained", facts, err)
		}
		// Descriptive deletion alone must not release the separate metadata charge.
		// This administrator mutation is a fault injection, not a cleanup proof.
		if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET state='deleted',deleted_at=clock_timestamp() WHERE id=$1", s.a.Registration.Location.AttemptID); err != nil {
			t.Fatal(err)
		}
		facts, err = reader.ContextRetirementDependencies(ctx, s.a.Plan.Input.CaptureID)
		if err != nil || !facts.CustodyDeleted || !facts.ExecutionUnresolved {
			t.Fatal(facts, err)
		}
		charge(t, s, 1, 1)
		next := fresh(t, s, "after-descriptive-delete")
		if _, err = next.s.AdmitContext(ctx, next.a); !errors.Is(err, capture.ErrCapacity) {
			t.Fatal("descriptive delete released metadata", err)
		}
		for _, sql := range []string{"DELETE FROM context_capture", "DELETE FROM context_control_charge", "UPDATE context_control_account SET charged_full=0"} {
			_, err = pool.Exec(ctx, sql)
			var p *pgconn.PgError
			if !errors.As(err, &p) || p.Code != "42501" {
				t.Fatal(sql, err)
			}
		}
	})
}

// This uses a separately owned, temporary fixture database. It applies the
// actual historical migrations, imports finite synthetic accepted records, and
// applies37. No live/harness database is downgraded and no trigger is disabled.
func qualifyContextControlMigration(t *testing.T, ctx context.Context, admin *pgxpool.Pool, create func(*testing.T, int64, int64, int64) captureAdmissionScenario) {
	t.Helper()
	t.Run("control-migration-adopts-all-history-without-free-capacity", func(t *testing.T) {
		s := create(t, 2, 2, 2)
		if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
			t.Fatal(err)
		}
		name := "control_migration_" + strings.ReplaceAll(custodyID(), "-", "")
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		config := admin.Config().Copy()
		config.ConnConfig.Database = name
		config.MaxConns = 1
		var scratch *pgxpool.Pool
		var err error
		t.Cleanup(func() {
			if scratch != nil {
				scratch.Close()
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
				t.Error("temporary migration database cleanup", err)
			}
		})
		scratch, err = pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		paths, err := filepath.Glob("../../migrations/[0-9]*.sql")
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(paths)
		var next []byte
		for _, path := range paths {
			version, err := strconv.Atoi(filepath.Base(path)[:5])
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if version == 37 {
				next = body
				break
			}
			if _, err = scratch.Exec(ctx, string(body)); err != nil {
				t.Fatalf("historical migration %d: %v", version, err)
			}
		}
		if len(next) == 0 {
			t.Fatal("missing migration37")
		}
		// All linked rows come from the real admission above. Only fixture metadata
		// is transferred; this database has no object/provider credentials. The
		// stream's initial audit refers back to the stream, so retain both records
		// in one transaction under their actual deferred foreign-key constraints.
		var initialAuditID string
		if err = admin.QueryRow(ctx, "SELECT initial_audit_id FROM permission_stream WHERE id=$1", s.a.RootID).Scan(&initialAuditID); err != nil {
			t.Fatal(err)
		}
		copyTx, err := scratch.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer copyTx.Rollback(ctx)
		for _, row := range []struct{ table, column, key string }{
			{"permission_stream", "id", s.a.RootID}, {"authority_audit", "id", initialAuditID}, {"custody_pool", "id", s.poolID},
			{"custody_allocation", "id", s.a.Registration.AllocationID},
			{"context_storage_binding", "allocation_id", s.a.Registration.AllocationID},
			{"custody_attempt", "id", s.a.Registration.Location.AttemptID},
			{"context_capture", "id", s.a.Plan.Input.CaptureID},
		} {
			var body []byte
			statement := "SELECT to_jsonb(t) FROM " + pgx.Identifier{row.table}.Sanitize() + " t WHERE " + pgx.Identifier{row.column}.Sanitize() + "=$1"
			if err = admin.QueryRow(ctx, statement, row.key).Scan(&body); err != nil {
				t.Fatal(err)
			}
			if _, err = copyTx.Exec(ctx, "INSERT INTO "+pgx.Identifier{row.table}.Sanitize()+" SELECT (jsonb_populate_record(NULL::"+pgx.Identifier{row.table}.Sanitize()+",$1::jsonb)).*", body); err != nil {
				t.Fatalf("copy %s: %v", row.table, err)
			}
		}
		if err = copyTx.Commit(ctx); err != nil {
			t.Fatal("copy linked historical records", err)
		}
		if _, err = scratch.Exec(ctx, string(next)); err != nil {
			t.Fatal("actual migration37", err)
		}
		var configured bool
		var backed, charged, count int64
		if err = scratch.QueryRow(ctx, "SELECT p.configured,p.backed_full,a.charged_full,(SELECT count(*) FROM context_control_charge) FROM context_control_pool p JOIN context_control_account a USING(root_id)").Scan(&configured, &backed, &charged, &count); err != nil || configured || backed != 1 || charged != 1 || count != 1 {
			t.Fatal("legacy costs disappeared", configured, backed, charged, count, err)
		}
		var original, migrated []byte
		if err = admin.QueryRow(ctx, "SELECT scope_json FROM context_capture WHERE id=$1", s.a.Plan.Input.CaptureID).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if err = scratch.QueryRow(ctx, "SELECT scope_json FROM context_capture WHERE id=$1", s.a.Plan.Input.CaptureID).Scan(&migrated); err != nil || !bytes.Equal(original, migrated) {
			t.Fatal("accepted identity rewritten", err)
		}
		if _, err = scratch.Exec(ctx, "UPDATE context_control_pool SET configured=true,revision=1,valid_until=clock_timestamp()+interval '1 hour',full_limit=0,replay_limit=0"); err == nil {
			t.Fatal("legacy cost was not required in new backing")
		}
		if _, err = scratch.Exec(ctx, "UPDATE context_control_pool SET configured=true,revision=1,valid_until=clock_timestamp()+interval '1 hour',full_limit=2,replay_limit=2"); err != nil {
			t.Fatal(err)
		}
		if _, err = scratch.Exec(ctx, "UPDATE context_control_account SET configured=true,revision=1,valid_until=clock_timestamp()+interval '30 minutes',full_limit=2,replay_limit=2"); err != nil {
			t.Fatal(err)
		}
		if err = scratch.QueryRow(ctx, "SELECT p.backed_full,a.charged_full FROM context_control_pool p JOIN context_control_account a USING(root_id)").Scan(&backed, &charged); err != nil || backed != 2 || charged != 1 {
			t.Fatal("adoption reset or double-backed history", backed, charged, err)
		}
	})
}
