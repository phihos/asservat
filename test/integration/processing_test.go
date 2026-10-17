package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	catalogapp "asservat.local/asservat/internal/application/catalog"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	privacyvalue "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual SQL processing decisions and encrypted independently acknowledged
// audit; the accepted privacy operator/backing remain explicit test inputs.
// The callback deliberately publishes only after the restriction has committed.
func qualifyProcessingRestrictions(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, e artifact.ContextExpectation, catalog *postgres.ContextPublications, f *processingTestFixture, publish func() error) {
	t.Helper()
	qualifyProcessingWorkerFacets(t, ctx, poolFor)
	pool := poolFor("processing_read_runtime", "synthetic-processing-read")
	defer pool.Close()
	reader, err := postgres.NewProcessingReads(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	scope := privacyvalue.ProcessingScope{Kind: "workloadInterval", ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, AcquiredFrom: e.Registration.AnchorAt.Add(-time.Second), AcquiredUntil: e.Registration.AnchorAt.Add(time.Second)}
	restrict := privacyvalue.ProcessingChange{RequestID: custodyID(), RuleID: custodyID(), Action: "restrict_processing", Scope: scope}
	blocked, err := f.service.Change(ctx, f.actor, restrict)
	if err != nil || blocked.State != "restricted" || blocked.Revision != 1 {
		t.Fatal("actual pre-publication restriction", blocked, err)
	}
	var charged, limit int64
	if err = admin.QueryRow(ctx, "SELECT a.charged,p.records_per_account FROM operation_audit_account a JOIN operation_audit_pool p USING(root_id,lane) WHERE a.root_id=$1 AND a.lane='normal'", s.a.RootID).Scan(&charged, &limit); err != nil || charged != 2 || limit != 2 {
		t.Fatal("normal audit pool is not actually full", charged, limit, err)
	}
	if err = publish(); err != nil {
		t.Fatal("restricted evidence must still be safely published", err)
	}
	var afterPublication int64
	if err = admin.QueryRow(ctx, "SELECT sequence FROM processing_root WHERE root_id=$1", s.a.RootID).Scan(&afterPublication); err != nil || afterPublication != blocked.Sequence {
		t.Fatal("publication changed unrelated processing authority", afterPublication, blocked.Sequence, err)
	}
	readProof := func() (artifact.DownloadProcessingProof, error) {
		r, err := catalog.ContextDownloadEvidence(ctx, e.Registration.Location.ArtifactID)
		if err != nil {
			return artifact.DownloadProcessingProof{}, err
		}
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			return artifact.DownloadProcessingProof{}, err
		}
		return reader.ContextProcessing(ctx, r, recovery)
	}
	if p, err := readProof(); err == nil || p != (artifact.DownloadProcessingProof{}) {
		t.Fatal("later publication bypassed preexisting workload restriction", p, err)
	}
	// Renewed installation capacity covers future rows; it cannot move any
	// older rule/decision/lineage retention date or clear that restriction.
	var originalDates []byte
	const datesQuery = "SELECT jsonb_build_object('rule',(SELECT jsonb_build_array(valid_until,retire_by) FROM processing_rule WHERE root_id=$1 AND id=$2),'decisions',(SELECT jsonb_agg(jsonb_build_array(id,valid_until,retire_by) ORDER BY id) FROM processing_decision WHERE root_id=$1),'lineage',(SELECT jsonb_agg(jsonb_build_array(artifact_id,delete_by,retire_by) ORDER BY artifact_id) FROM context_processing WHERE root_id=$1))::text"
	if err = admin.QueryRow(ctx, datesQuery, s.a.RootID, restrict.RuleID).Scan(&originalDates); err != nil {
		t.Fatal(err)
	}
	oldValidity := f.backing.ValidUntil
	if err = f.renew(); err != nil {
		t.Fatal("protected backing renewal", err)
	}
	if !f.backing.ValidUntil.After(oldValidity) {
		t.Fatal("fixture did not renew actual backing")
	}
	var newDates []byte
	if err = admin.QueryRow(ctx, datesQuery, s.a.RootID, restrict.RuleID).Scan(&newDates); err != nil || !bytes.Equal(newDates, originalDates) {
		t.Fatal("renewal rewrote original business-history dates", err)
	}
	if p, err := readProof(); err == nil || p != (artifact.DownloadProcessingProof{}) {
		t.Fatal("backing renewal erased a retained restriction", p, err)
	}
	casePool := poolFor("context_case_read_runtime", "synthetic-context-case-read")
	defer casePool.Close()
	routes, err := postgres.NewContextCaseReads(ctx, casePool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	cases := catalogapp.ContextCaseService{RootID: s.a.RootID, InstallationID: s.recovery.installation, Routes: routes, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Recovery: s.recovery.reader, Processing: reader, Now: time.Now}
	refreshPermission := func() {
		batch := s.batch
		batch.Initial = nil
		batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
		if err := s.p.RefreshPermissions(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	readActor := f.actor
	readActor.value.Scopes = []string{"evidence:read"}
	refreshPermission()
	if view, err := cases.GetContextCase(ctx, readActor, e.CaseID); err == nil || view.CaseID != "" || len(view.Artifacts) != 0 {
		t.Fatal("ordinary case metadata bypassed restriction", view, err)
	}
	release := privacyvalue.ProcessingChange{RequestID: custodyID(), RuleID: restrict.RuleID, Action: "release_processing", ExpectedRevision: 1, Scope: scope}
	foreign := f.actor
	foreign.value.Principal.Subject = "different-privacy-operator"
	foreign.value.Groups = nil
	if _, err = f.service.Change(ctx, foreign, release); err == nil {
		t.Fatal("unapproved actor removed restriction")
	}
	wrong := release
	wrong.RequestID = custodyID()
	wrong.Scope.WorkloadUID = "different-workload"
	if _, err = f.service.Change(ctx, f.actor, wrong); err == nil {
		t.Fatal("different scope removed restriction")
	}
	releaseService := f.service
	releaseService.Decisions = processingReplayLockProbe{ProcessingDecisions: releaseService.Decisions, admin: admin}
	released, err := releaseService.Change(ctx, f.actor, release)
	if err != nil || released.State != "released" || released.Revision != 2 || released.Sequence <= blocked.Sequence {
		t.Fatal("prepaid release while normal pool full", released, err)
	}
	var normalCount, releaseCount int
	if err = admin.QueryRow(ctx, "SELECT count(*) FILTER(WHERE lane='normal'),count(*) FILTER(WHERE lane='processing') FROM operation_audit WHERE root_id=$1", s.a.RootID).Scan(&normalCount, &releaseCount); err != nil || normalCount != 2 || releaseCount != 1 {
		t.Fatal("release used a new normal account or duplicated audit", normalCount, releaseCount, err)
	}
	replay, err := f.service.Change(ctx, f.actor, release)
	if err != nil || replay.Revision != released.Revision || replay.Sequence != released.Sequence || replay.OperationID != released.OperationID {
		t.Fatal("same-key release replay changed effect", replay, err)
	}
	if err = admin.QueryRow(ctx, "SELECT count(*) FROM operation_audit WHERE root_id=$1 AND lane='processing'", s.a.RootID).Scan(&releaseCount); err != nil || releaseCount != 1 {
		t.Fatal("replay spent another audit pair", releaseCount, err)
	}
	if p, err := readProof(); err != nil || !p.Valid(time.Now()) || p.Sequence != released.Sequence {
		t.Fatal("independently audited release did not restore current read", p, err)
	}
	refreshPermission()
	if view, err := cases.GetContextCase(ctx, readActor, e.CaseID); err != nil || view.CaseID != e.CaseID || len(view.Artifacts) != 1 {
		t.Fatal("current ordinary case after release", view, err)
	}
	// Reader has no route to initialize, remove retained rules or mint lineage.
	for _, statement := range []string{"UPDATE processing_root SET initialized_at=clock_timestamp()", "DELETE FROM processing_rule", "UPDATE processing_rule SET state='released'", "INSERT INTO context_processing SELECT * FROM context_processing LIMIT 0", "INSERT INTO processing_decision SELECT * FROM processing_decision LIMIT 0"} {
		_, err := pool.Exec(ctx, statement)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatal("processing reader gained mutation authority", statement, err)
		}
	}
	r, err := catalog.ContextDownloadEvidence(ctx, e.Registration.Location.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r.ValidUntil = time.Now().UTC().Add(100 * time.Millisecond)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE", s.recovery.installation); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := reader.ContextProcessing(ctx, r, recovery); done <- err }()
	blocker := tx.Conn().PgConn().PID()
	waitUntil := time.Now().Add(time.Second)
	for {
		var blocked bool
		if err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='processing_read_runtime' AND $1=ANY(pg_blocking_pids(pid)))", blocker).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-done:
			t.Fatal("processing read completed before observed recovery-lock wait", err)
		default:
		}
		if !time.Now().Before(waitUntil) {
			t.Fatal("processing read never reached the held recovery lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if delay := time.Until(r.ValidUntil.Add(25 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("processing proof survived original catalog deadline after lock wait")
	}
	if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", s.recovery.installation); err != nil {
		t.Fatal(err)
	}
	if _, err = readProof(); err == nil {
		t.Fatal("stored processing completeness cleared recovery fence")
	}
}

// These separately credentialed effect consumers must be able to evaluate the
// current processing fence, without gaining any means to erase or release it.
// Enrollment audit and passive locator reads do not evaluate current effects.
func qualifyProcessingWorkerFacets(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool) {
	t.Helper()
	for _, actor := range []struct {
		role, password string
		reads          bool
	}{
		{"worker_enrollment_runtime", "synthetic-worker-enrollment", true},
		{"worker_enrollment_activate_runtime", "synthetic-worker-enrollment-activate", true},
		{"worker_owner_runtime", "synthetic-worker-owner", true},
		{"worker_enrollment_audit_runtime", "synthetic-worker-enrollment-audit", false},
		{"worker_owner_read_runtime", "synthetic-worker-owner-read", false},
	} {
		pool := poolFor(actor.role, actor.password)
		func() {
			defer pool.Close()
			for _, table := range []string{"processing_root", "context_processing", "processing_rule"} {
				_, err := pool.Exec(ctx, "SELECT * FROM "+table+" LIMIT 0")
				if actor.reads {
					if err != nil {
						t.Fatal("processing effect facet cannot read fence", actor.role, table, err)
					}
				} else {
					var pgerr *pgconn.PgError
					if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
						t.Fatal("historical facet gained current processing reads", actor.role, table, err)
					}
				}
				// WHERE false avoids changing data even if the permission boundary
				// regresses; PostgreSQL still checks the actual mutation privilege.
				_, err = pool.Exec(ctx, "DELETE FROM "+table+" WHERE false")
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
					t.Fatal("worker facet gained processing deletion", actor.role, table, err)
				}
			}
			for _, statement := range []string{"UPDATE processing_root SET initialized_at=initialized_at WHERE false", "UPDATE processing_rule SET state='released' WHERE false", "INSERT INTO context_processing SELECT * FROM context_processing LIMIT 0"} {
				_, err := pool.Exec(ctx, statement)
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
					t.Fatal("worker facet gained processing mutation", actor.role, statement, err)
				}
			}
		}()
	}
}

// This proves a previously allowed and prepaid transfer cannot bypass a newly
// committed restriction. Session state and all uncertain charges remain; a
// release permits the original session to continue under fresh authority.
func qualifyProcessingDownloadEffects(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, published artifact.PublishedContext, catalog *postgres.ContextPublications, f *processingTestFixture) {
	// Keep failures at the exact native qualification phase, rather than hiding
	// the entire transfer sequence behind the publication caller's source line.
	runtimePool := poolFor("download_runtime", "synthetic-download")
	defer runtimePool.Close()
	auditPool := poolFor("download_audit_runtime", "synthetic-download-audit")
	defer auditPool.Close()
	configPool := poolFor("download_config_runtime", "synthetic-download-config")
	defer configPool.Close()
	readPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
	defer readPool.Close()
	guards := postgres.DownloadTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}
	runtime, err := postgres.NewDownloads(ctx, runtimePool, s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := postgres.NewDownloads(ctx, auditPool, s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	config, err := postgres.NewDownloads(ctx, configPool, s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	e := published.Expectation
	allocation := artifact.DownloadAllocation{ID: custodyID(), RootID: s.a.RootID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, OutputLimit: 1 << 20, ReadLimit: 256 << 20, SessionLimit: 4, ValidUntil: time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond)}
	if err = config.BindDownloadAllocation(ctx, allocation); err != nil {
		t.Fatal(err)
	}
	scope := artifact.DownloadScope{RootID: s.a.RootID, ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(published.Copies), Principal: s.a.Plan.Input.Executor}
	gate := authorizationapp.ContextDownloadAuthority{RootID: s.a.RootID, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Environment: newDownloadTestEnvironment(t, ctx, readPool, s, e.Registration), Now: time.Now}
	current := func() artifact.DownloadAuthority {
		batch := s.batch
		batch.Initial = nil
		batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
		if err := s.p.RefreshPermissions(ctx, batch); err != nil {
			t.Fatal(err)
		}
		actor := s.a.Eligibility.VerifiedIdentity
		actor.Scopes = []string{"evidence:read", "evidence:download"}
		actor.VerifiedAt = batch.ObservedAt
		actor.ValidUntil = batch.FreshUntil
		gate.Identities = downloadTestIdentity{actor}
		a, err := gate.CheckDownload(ctx, "synthetic-reference", scope)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := current()
	reservation := evidence.DownloadReservation{Session: artifact.DownloadSession{ID: custodyID(), AllocationID: allocation.ID, Scope: scope, RequestDigest: artifact.Digest{37}, State: artifact.DownloadPreparing, CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(5 * time.Minute), OutputLimit: 8192, ReadLimit: 8 << 20, RequestLimit: 4}, IdempotencyDigest: artifact.Digest{38}, Authority: a}
	session, err := runtime.ReserveDownload(ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	objects := &objectstore.DownloadAuditObjects{Store: store, Seal: keys, Open: keys}
	prep, err := runtime.BeginDownloadBatch(ctx, session.ID, a, artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadMetadata, ReadBytes: 2 << 20})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := objects.WriteDownloadIntent(ctx, prep)
	if err != nil {
		t.Fatal(err)
	}
	if err = ack.AcknowledgeDownloadIntent(ctx, prep, receipt); err != nil {
		t.Fatal(err)
	}
	if err = runtime.PermitDownloadBatch(ctx, session.ID, a, prep.Batch.ID, prep.Batch.Generation); err != nil {
		t.Fatal(err)
	}
	outcome, err := runtime.FinishDownloadBatch(ctx, session.ID, prep.Batch.ID, prep.Batch.Generation, 0, true, false)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err = objects.WriteDownloadOutcome(ctx, outcome)
	if err != nil {
		t.Fatal(err)
	}
	if err = ack.AcknowledgeDownloadOutcome(ctx, outcome, receipt); err != nil {
		t.Fatal(err)
	}
	a = current()
	bytes := artifact.DownloadBatch{ID: custodyID(), Purpose: artifact.DownloadContent, OutputBytes: 1024, ReadBytes: 2 << 20}
	pending, err := runtime.BeginDownloadBatch(ctx, session.ID, a, bytes)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err = objects.WriteDownloadIntent(ctx, pending)
	if err != nil {
		t.Fatal(err)
	}
	if err = ack.AcknowledgeDownloadIntent(ctx, pending, receipt); err != nil {
		t.Fatal(err)
	}
	restriction := privacyvalue.ProcessingChange{RequestID: custodyID(), RuleID: custodyID(), Action: "restrict_processing", Scope: privacyvalue.ProcessingScope{Kind: "artifact", Location: e.Registration.Location}}
	if _, err = f.service.Change(ctx, f.actor, restriction); err != nil {
		t.Fatal("commit restriction after paid intent", err)
	}
	if !a.Valid(time.Now()) {
		t.Fatal("fixture expired before contrary processing state was tested")
	}
	if err = runtime.PermitDownloadBatch(ctx, session.ID, a, bytes.ID, pending.Batch.Generation); err == nil {
		t.Fatal("stale processing proof permitted prepaid output")
	}
	next := reservation
	next.Session.ID = custodyID()
	next.IdempotencyDigest = artifact.Digest{39}
	next.Authority = a
	if _, err = runtime.ReserveDownload(ctx, next); err == nil {
		t.Fatal("stale processing proof reserved new session")
	}
	got, err := runtime.LookupDownload(ctx, session.ID, scope.Principal)
	if err != nil || got.ChargedOutput != 1024 || got.EmittedBytes != 0 || got.Active == nil || got.Active.ID != bytes.ID {
		t.Fatal("restriction refunded or replaced uncertain spend", got, err)
	}
	if _, err = gate.CheckDownload(ctx, "synthetic-reference", scope); err == nil {
		t.Fatal("new authority bypassed restriction")
	}
	release := restriction
	release.RequestID = custodyID()
	release.Action = "release_processing"
	release.ExpectedRevision = 1
	if _, err = f.service.Change(ctx, f.actor, release); err != nil {
		t.Fatal("prepaid release", err)
	}
	fresh := current()
	if fresh.Environment.Processing.Sequence <= a.Environment.Processing.Sequence || !identity.Fresh(fresh.CheckedAt, fresh.ValidUntil, time.Now(), 5*time.Second) {
		t.Fatal("release reused old observation")
	}
	if err = runtime.PermitDownloadBatch(ctx, session.ID, fresh, bytes.ID, pending.Batch.Generation); err != nil {
		t.Fatal("fresh authority could not resume exact original prepaid batch", err)
	}
	got, err = runtime.LookupDownload(ctx, session.ID, scope.Principal)
	if err != nil || got.ChargedOutput != 1024 || got.EmittedBytes != 0 || got.Active == nil || got.Active.ID != bytes.ID {
		t.Fatal("resume changed original spend/session", got, err)
	}
}

// Uses the exact pool -> audit row order from ReserveOperation replay while
// the actual ApplyProcessing transaction is blocked. Before the SQL50 fix,
// apply already held the audit row and these two transactions formed a cycle.
// This fixture deliberately owns the barrier transaction; it grants no runtime
// permission and performs no synthetic audit acknowledgement or business write.
type processingReplayLockProbe struct {
	privacyapp.ProcessingDecisions
	admin *pgxpool.Pool
}

func (p processingReplayLockProbe) ApplyProcessing(ctx context.Context, a privacyvalue.ProcessingAuthority, d privacyapp.ProcessingDecision) (privacyvalue.ProcessingReceipt, error) {
	var zero privacyvalue.ProcessingReceipt
	tx, err := p.admin.Begin(ctx)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SELECT root_id FROM operation_audit_pool WHERE root_id=$1 AND lane='processing' FOR UPDATE", d.Intent.RootID); err != nil {
		return zero, err
	}
	type result struct {
		receipt privacyvalue.ProcessingReceipt
		err     error
	}
	done := make(chan result, 1)
	go func() { r, e := p.ProcessingDecisions.ApplyProcessing(ctx, a, d); done <- result{r, e} }()
	joined := false
	defer func() {
		if !joined {
			_ = tx.Rollback(context.Background())
			<-done
		}
	}()
	waitUntil := time.Now().Add(time.Second)
	for {
		var blocked bool
		err = p.admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='processing_decision_runtime' AND $1=ANY(pg_blocking_pids(pid)))", tx.Conn().PgConn().PID()).Scan(&blocked)
		if err != nil {
			return zero, err
		}
		if blocked {
			break
		}
		select {
		case r := <-done:
			joined = true
			return zero, fmt.Errorf("processing apply did not reach pool lock barrier: %w", r.err)
		default:
		}
		if !time.Now().Before(waitUntil) {
			return zero, fmt.Errorf("processing apply never reached held audit pool")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A short diagnostic bound detects the cycle without waiting for PostgreSQL
	// deadlock detection or consuming the operation's whole original deadline.
	lockCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	_, err = tx.Exec(lockCtx, "SELECT id FROM operation_audit WHERE root_id=$1 AND id=$2 FOR UPDATE", d.Intent.RootID, d.Intent.ID)
	cancel()
	if err != nil {
		return zero, fmt.Errorf("pool-to-audit replay lock order blocked behind apply: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return zero, err
	}
	r := <-done
	joined = true
	return r.receipt, r.err
}
