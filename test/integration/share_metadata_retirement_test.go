package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The 65-row unbounded-history reproduction passed at source 2a2bc0f1; its
// archived measurements remain inputs, not a qualified capacity profile.
// This successor exercises current paid-slot effects and their retirement.
// The owned fixture really admits, encrypts, verifies and publishes the artifact;
// the share mutations use the installation's compiled hub role/current adapter.
// Synthetic human/permission inputs and local test crypto remain explicit.
// Public-operation audit and remote provider costs are outside these samples.
func TestShareMetadataSlotsWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) {
			// Select this finite component-test cohort before the first audit.
			// Counts stay unchanged; these synthetic bounds do not qualify IAM,
			// maximum-byte rows or the separate 100-share policy transaction.
			normal := &f.qualification.RootBacking.Normal
			normal.RetainedSeconds = 60
			normal.Policy.History.Layout = auditvalue.ShareOperationHistoryLayout
			normal.Policy.BackupHorizonSeconds = 2
			normal.Policy.CleanupBudgetSeconds = 3
			normal.Policy.ProofWindowSeconds = 2
			backup, wal := normal.Policy.History.SlotBacking(normal.Policy.MaxPurgeLeases)
			normal.Policy.BackupReservedBytes = backup * normal.Policy.MetadataSlots
			normal.Policy.WALReservedBytes = wal * normal.Policy.MetadataSlots
			// Accept the full owner set BEFORE admission/publication. Never widen
			// the immutable audience of an existing artifact for measurement.
			next := f.batch
			next.Bases = slices.Clone(next.Bases)
			for n := 0; n < authorization.ShareMaxManagers; n++ {
				base := next.Bases[0]
				base.Resource.UID = custodyID()
				base.Resource.SpecDigest = sha256.Sum256([]byte(fmt.Sprintf("synthetic-share-owner-%d", n)))
				base.Roles = []string{"evidence-owner"}
				base.ScopeDigest = configapp.PermissionScopeDigest(base)
				next.Bases = append(next.Bases, base)
			}
			next.RequestID, next.InputDigest, next.Initial = custodyID(), artifact.Digest{83}, nil
			next.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
			next.FreshUntil = next.ObservedAt.Add(5 * time.Second)
			accepted, err := f.permission.AcceptPermissions(ctx, next)
			if err != nil {
				t.Fatal("accept original eight-owner audience", err)
			}
			next.ExpectedSequence = accepted.Sequence
			f.batch = next
			for range 2 {
				if err = (auditapp.AuthorityPublisher{Ledger: f.permission, Objects: f.authority}).PublishAuthority(ctx); err != nil {
					t.Fatal("audit original eight-owner audience", err)
				}
			}
		})
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
			t.Fatal("initialize original capacity", err)
		}
		f.open(t)
		o := f.rootObservation(t)
		root, err := f.roots.ReserveCapacityRoot(ctx, o)
		if err != nil {
			t.Fatal("reserve original root", err)
		}
		root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
		if err != nil {
			t.Fatal("back original root", err)
		}
		root, err = f.roots.PublishCapacityRoot(ctx, o, root)
		if err != nil || !root.AdmissionReady(time.Now()) {
			t.Fatal("publish original root", err)
		}
		coordinator := capacityapp.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}
		enrolled, err := coordinator.Reconcile(ctx, f.workloadObservation(t, 0))
		if err != nil {
			t.Fatal("original workload enrollment", err)
		}
		originalPool := f.fixturePool
		var processingPools []*pgxpool.Pool
		f.fixturePool = func(role, password string) *pgxpool.Pool {
			pool := originalPool(role, password)
			processingPools = append(processingPools, pool)
			return pool
		}
		f.initializeManagedProcessing(t, root)
		f.fixturePool = originalPool
		for _, pool := range processingPools {
			pool.Close()
		}
		// The query helper selects 60s retention and requires its own 120s
		// processing profile. This baseline uses the original managed-context
		// 20s retention under the unchanged 60s root instead.
		s, accepted := f.admitManagedContext(t, root, enrolled)
		s, published := publishPreparedQueryLedgerContext(t, f, s, accepted, nil, execution.APIExecution{}, nil, false)
		t.Logf("share_baseline_original_access_remaining_ms=%d", time.Until(published.Expectation.Registration.ExpiresAt).Milliseconds())
		qualifyShareMetadataSlots(t, f, s, published)
	})
}

type shareMetadataSample struct {
	WAL                                           string
	Rows, Active, TupleBytes, MaxTupleBytes       int64
	HeapBytes, IndexBytes, ToastBytes, TotalBytes int64
}

func sampleShareMetadata(t *testing.T, f *capacitySQLFixture, artifactID string) shareMetadataSample {
	t.Helper()
	var s shareMetadataSample
	if err := f.admin.QueryRow(f.ctx, `SELECT pg_current_wal_insert_lsn()::text,
 count(*)::bigint,count(*) FILTER(WHERE revoked_at IS NULL AND expires_at>clock_timestamp())::bigint,
 coalesce(sum(pg_column_size(r)),0)::bigint,coalesce(max(pg_column_size(r)),0)::bigint,
 pg_relation_size('public.evidence_share'),pg_indexes_size('public.evidence_share'),
 (SELECT pg_total_relation_size(reltoastrelid) FROM pg_class WHERE oid='public.evidence_share'::regclass),
 pg_total_relation_size('public.evidence_share')
 FROM evidence_share r WHERE root_id=$1 AND artifact_id=$2`, f.input.PermissionRootID, artifactID).Scan(&s.WAL, &s.Rows, &s.Active, &s.TupleBytes, &s.MaxTupleBytes, &s.HeapBytes, &s.IndexBytes, &s.ToastBytes, &s.TotalBytes); err != nil {
		t.Fatal("share metadata sample", err)
	}
	return s
}

func logShareMetadata(t *testing.T, f *capacitySQLFixture, phase string, before, after shareMetadataSample, elapsed time.Duration) {
	t.Helper()
	var wal int64
	if err := f.admin.QueryRow(f.ctx, `SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint`, after.WAL, before.WAL).Scan(&wal); err != nil || wal < 0 {
		t.Fatal("share WAL observation", err, wal)
	}
	t.Logf("UNQUALIFIED share_business phase=%s elapsed_ms=%d rows=%d active=%d row_delta=%d tuple_bytes=%d max_tuple_bytes=%d heap_bytes=%d indexes_bytes=%d toast_bytes=%d total_bytes=%d heap_growth=%d indexes_growth=%d toast_growth=%d total_growth=%d whole_instance_wal_delta=%d; logical counts are exact-artifact; physical sizes cover entire relations; WAL includes background noise, aborted work and page images; excludes public audit/provider work", phase, elapsed.Milliseconds(), after.Rows, after.Active, after.Rows-before.Rows, after.TupleBytes, after.MaxTupleBytes, after.HeapBytes, after.IndexBytes, after.ToastBytes, after.TotalBytes, after.HeapBytes-before.HeapBytes, after.IndexBytes-before.IndexBytes, after.ToastBytes-before.ToastBytes, after.TotalBytes-before.TotalBytes, wal)
}

// A real positive writer and independent SQL acknowledgement, reused by share
// qualifiers. The MAC and policy are their original already accepted inputs.
func beginPaidShareOperation(t *testing.T, ctx context.Context, gate *auditapp.HealthyOperationAuditor, mac *auditapp.OperationMAC, policy auditvalue.OperationLifecyclePolicy, actor identity.Principal, name, key string, retainedSeconds int64) auditvalue.OperationIntent {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	principal, err := mac.Principal(actor)
	if err != nil {
		t.Fatal(err)
	}
	input, err := mac.Digest("context-input/v1", []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	operation := custodyID()
	in := auditvalue.OperationIntent{ID: operation, RootID: policy.RootID, TraceID: operation, Name: name, InputFormat: "context-input/v1", MACVersion: mac.Version(), AccountVersion: mac.AccountVersion(), Actor: actor, PrincipalDigest: principal, InputDigest: input, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(8 * time.Second), RetainUntil: n.Add(time.Duration(retainedSeconds) * time.Second)}
	if err = gate.Begin(ctx, in); err != nil {
		t.Fatal("actual paid share Begin", name, err)
	}
	bound, err := auditapp.BindOperationLifecycle(in, policy)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func qualifyShareMetadataSlots(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, published artifact.PublishedContext) {
	t.Helper()
	ctx, hub, e := f.ctx, f.roles["hub-runtime"], published.Expectation
	store, err := postgres.NewEvidenceShares(ctx, hub, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := postgres.NewContextPublications(ctx, hub, s.a.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := catalog.ContextDownloadEvidence(ctx, e.Registration.Location.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	profiles := f.readAuditProfiles(t)
	policy := profiles.Normal.Policy
	journal, err := postgres.NewHealthyOperationJournal(ctx, hub, policy, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgements, err := postgres.NewOperationAcknowledgements(ctx, hub, s.a.RootID, "normal", s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	completions, err := postgres.NewOperationLifecycles(ctx, hub, s.a.RootID, "normal", s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := objectstore.NewClosedOperationAuditObjects(f.store, policy.StoreID, f.keys, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := auditapp.NewHealthyOperationAuditor(policy, journal, acknowledgements, &objectstore.OperationAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}, writer, completions, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	material := f.root.value.State.MAC
	mac, err := auditapp.NewOperationMAC(material.InputVersion, material.InputKey, material.AccountVersion, material.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	defer mac.Close()
	creator := s.a.Eligibility.VerifiedIdentity.Principal
	var managers []artifact.AudienceAssignment
	for _, a := range e.Audience {
		if a.Role == "evidence-owner" {
			managers = append(managers, a)
		}
	}
	if len(managers) != 8 {
		t.Fatal("original eight-owner audience", len(managers))
	}
	proof := func() artifact.RecoveryProof {
		t.Helper()
		f.refreshFleet(t)
		p, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	begin := func(name, key string) auditvalue.OperationIntent {
		t.Helper()
		f.refreshFleet(t)
		return beginPaidShareOperation(t, ctx, gate, mac, policy, creator, name, key, profiles.Normal.RetainedSeconds)
	}
	finish := func(in auditvalue.OperationIntent) {
		t.Helper()
		out := auditvalue.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{99}, OutputBytes: 12, MetadataUntil: in.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
		if err := gate.Finish(ctx, out); err != nil {
			t.Fatal("actual share outcome", err)
		}
	}
	request := sharing.Request{Share: authorization.Share{ID: custodyID(), RootID: s.a.RootID, ArtifactID: e.Registration.Location.ArtifactID, CaseID: e.CaseID, Target: s.a.Eligibility.Target, Version: verified.Version, Creator: creator, Management: managers, Recipients: []authorization.ShareRecipient{{Kind: "User", Issuer: creator.Issuer, ID: "synthetic-recipient"}}, ExpiresAt: e.Registration.ExpiresAt}, IdempotencyKey: "finite-original-share", RequestDigest: artifact.Digest{97}}
	// A reserved but unacknowledged normal record cannot fund an effect.
	reserved := begin("create_share", "unacknowledged-source")
	// Begin above proved acknowledgement. A distinct raw journal reservation
	// below is intentionally never written/acknowledged; it is not a fake receipt.
	raw := reserved
	raw.ID = custodyID()
	raw.TraceID = raw.ID
	raw.Lifecycle = nil
	raw, err = auditapp.BindOperationLifecycle(raw, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = journal.ReserveOperation(ctx, raw); err != nil {
		t.Fatal("unacknowledged reservation", err)
	}
	request.OperationID = raw.ID
	if _, _, err = store.CreateShare(ctx, request, proof()); err == nil {
		t.Fatal("unacknowledged operation funded share")
	}
	// The already acknowledged source is current and has not spent a marker.
	request.OperationID = reserved.ID
	before := sampleShareMetadata(t, f, e.Registration.Location.ArtifactID)
	started := time.Now()
	first, replay, err := store.CreateShare(ctx, request, proof())
	if err != nil || replay {
		t.Fatal("paid share create", err, replay)
	}
	logShareMetadata(t, f, "qualified-paid-create", before, sampleShareMetadata(t, f, e.Registration.Location.ArtifactID), time.Since(started))
	another := request
	another.Share.ID = custodyID()
	another.IdempotencyKey = "same-operation-second-share"
	another.RequestDigest = artifact.Digest{98}
	if _, _, err = store.CreateShare(ctx, another, proof()); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("paid source created second share", err)
	}
	var creatorID, lastID string
	var retire time.Time
	if err = f.admin.QueryRow(ctx, `SELECT creating_operation_id::text,last_operation_id::text,retire_by FROM evidence_share WHERE id=$1`, first.ID).Scan(&creatorID, &lastID, &retire); err != nil || creatorID != reserved.ID || lastID != reserved.ID || !retire.Equal(reserved.Lifecycle.LiveRetireBy) {
		t.Fatal("original share dependency", err, creatorID, lastID, retire)
	}
	finish(reserved)
	replayOp := begin("create_share", "business-replay")
	replayRequest := request
	replayRequest.OperationID = replayOp.ID
	replayRequest.Share.ID = custodyID()
	again, replay, err := store.CreateShare(ctx, replayRequest, proof())
	if err != nil || !replay || again.ID != first.ID || !again.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("fresh operation changed original business replay", err, replay)
	}
	finish(replayOp)
	tooLong := begin("create_share", "incompatible-original-cutoff")
	rejected := another
	rejected.OperationID = tooLong.ID
	rejected.Share.ExpiresAt = tooLong.Lifecycle.OriginalPurgeAt.Add(time.Microsecond)
	if _, _, err = store.CreateShare(ctx, rejected, proof()); !errors.Is(err, sharing.ErrRetentionCapacity) {
		t.Fatal("incompatible original effect bound", err)
	}
	transferOp := begin("transfer_share", "one-transfer")
	replacement := slices.Clone(managers)
	slices.Reverse(replacement)
	ids := make([]string, len(managers))
	for n, a := range managers {
		ids[n] = a.AssignmentID
	}
	transfer := sharing.Transfer{OperationID: transferOp.ID, ShareID: first.ID, Actor: creator, Managers: ids, Management: replacement, ExpectedRevision: 1, IdempotencyKey: "first-transfer", RequestDigest: artifact.Digest{96}}
	updated, replay, err := store.TransferShare(ctx, transfer, proof())
	if err != nil || replay {
		t.Fatal("paid transfer", err, replay)
	}
	transfer.IdempotencyKey = "second-transfer"
	transfer.ExpectedRevision = updated.Revision
	transfer.RequestDigest = artifact.Digest{95}
	if _, _, err = store.TransferShare(ctx, transfer, proof()); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("one paid operation transferred twice", err)
	}
	finish(transferOp)
	revokeOp := begin("revoke_share", "revoke-original")
	if _, replay, err = store.RevokeShare(ctx, sharing.Revocation{OperationID: revokeOp.ID, ShareID: first.ID, Actor: creator, ExpectedRevision: updated.Revision, IdempotencyKey: "finite-revoke"}, proof()); err != nil || replay {
		t.Fatal("paid revoke", err, replay)
	}
	finish(revokeOp)
	if _, err = hub.Exec(ctx, `DELETE FROM evidence_share WHERE id=$1`, first.ID); err == nil {
		t.Fatal("hub directly deleted identifying share")
	}
	// The report SQL must honor this share's original cutoff even while the
	// parent processing metadata has a later horizon. This is a query-boundary
	// check with an explicit future observation, not elapsed-time qualification.
	var parentRetire time.Time
	if err = f.admin.QueryRow(ctx, `SELECT retire_by FROM context_processing WHERE artifact_id=$1`, e.Registration.Location.ArtifactID).Scan(&parentRetire); err != nil || !parentRetire.After(retire) {
		t.Fatal("independent parent horizon", err)
	}
	var rootID pgtype.UUID
	_ = rootID.Scan(s.a.RootID)
	rows, err := custodydb.New(hub).ReportProcessingShares(ctx, custodydb.ReportProcessingSharesParams{RootID: rootID, ObservedAt: pgtype.Timestamptz{Time: retire, Valid: true}, CreatedBefore: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, AfterCreatedAt: pgtype.Timestamptz{Time: time.Unix(0, 0), Valid: true}, AfterID: rootID, AfterOrdinal: 0, PageLimit: 4})
	if err != nil || len(rows) != 0 {
		t.Fatal("report renewed share visibility from parent", err, len(rows))
	}
	qualifyPaidShareRetirement(t, f, s, reserved, first.ID, policy)
}

func qualifyPaidShareRetirement(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, in auditvalue.OperationIntent, shareID string, policy auditvalue.OperationLifecyclePolicy) {
	t.Helper()
	ctx := f.ctx
	live, err := readShareRetirementSnapshot(ctx, f.admin, s.a.RootID, "normal", in.PrincipalDigest[:], shareID, in.ID, in.Lifecycle.HistoryReleaseAt, in.Lifecycle.HistoryDeleteBy)
	if err != nil || !live.Share || !live.Operation || !live.Lifecycle || live.AccountCharge == nil || *live.AccountCharge != live.LiveRecords+live.HistoryRecords {
		t.Fatal("paid share original snapshot or charge invariant", err)
	}
	ledgers := make([]*postgres.OperationLifecycles, 0, 3)
	for _, purpose := range []string{"capture-cleanup", "capture-verifier", "capture-finalizer"} {
		l, err := postgres.NewScopedWorkerOperationLifecycles(ctx, f.roles[purpose], s.a.RootID, s.recovery.installation, policy.StoreID, s.recovery.guard)
		if err != nil {
			t.Fatal("compiled worker cleanup facet", purpose, err)
		}
		ledgers = append(ledgers, l)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := jose.NewOperationRetirementSignatures(s.a.RootID, "synthetic-retirement", private, map[string]ed25519.PublicKey{"synthetic-retirement": public})
	if err != nil {
		t.Fatal(err)
	}
	verify, err := jose.NewOperationRetirementSignatures(s.a.RootID, "", nil, map[string]ed25519.PublicKey{"synthetic-retirement": public})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := objectstore.NewOperationAuditCleanupObjects(f.store, policy.StoreID, f.keys, f.keys, sign, verify)
	if err != nil {
		t.Fatal(err)
	}
	checks, err := objectstore.NewOperationAuditCleanupVerifier(f.store, policy.StoreID, f.keys, verify)
	if err != nil {
		t.Fatal(err)
	}
	cleaner := auditapp.OperationCleanup{Journal: ledgers[0], Acknowledgements: ledgers[1], Finalizer: ledgers[2], Objects: objects, Verifier: checks}
	t.Logf("share_retirement_stage=await_original_purge remaining_ms=%d; original source bound unchanged; synthetic local signing/storage credentials do not qualify installed IAM", time.Until(in.Lifecycle.OriginalPurgeAt).Milliseconds())
	// Exercise the installed selector with its compiled cleanup credential,
	// including the normal lane; direct Advance alone cannot prove this path.
	f.refreshFleet(t)
	due, err := ledgers[0].DueWorkerOperations(ctx, "")
	if err != nil || time.Now().Before(in.Lifecycle.OriginalPurgeAt) && slices.Contains(due, in.ID) {
		t.Fatal("worker selected a normal operation before its original purge", err)
	}
	deadline := in.Lifecycle.LiveRetireBy.Add(5 * time.Second)
	removed, selected := false, false
	for time.Now().Before(deadline) {
		f.refreshFleet(t)
		if !selected && !time.Now().Before(in.Lifecycle.OriginalPurgeAt) {
			due, err = ledgers[0].DueWorkerOperations(ctx, "")
			if err != nil || !slices.Contains(due, in.ID) {
				t.Fatal("compiled worker selector omitted the due normal operation", err, due)
			}
			after, e := ledgers[0].DueWorkerOperations(ctx, in.ID)
			if e != nil {
				t.Fatal("compiled worker cursor query", e)
			}
			for _, id := range after {
				if id <= in.ID {
					t.Fatal("worker cursor repeated an earlier operation")
				}
			}
			selected = true
		}
		err = cleaner.Advance(ctx, in.ID)
		state, e := readShareRetirementSnapshot(ctx, f.admin, s.a.RootID, "normal", in.PrincipalDigest[:], shareID, in.ID, in.Lifecycle.HistoryReleaseAt, in.Lifecycle.HistoryDeleteBy)
		if e != nil || state.Share != state.Operation || state.Lifecycle != state.Operation || state.AccountCharge == nil || *state.AccountCharge != state.LiveRecords+state.HistoryRecords {
			t.Fatal("paid share atomic retirement/account snapshot", e)
		}
		if state.Operation && !state.SnapshotAt.Before(in.Lifecycle.LiveRetireBy) {
			t.Fatal("paid share exceeded original live retirement bound")
		}
		if !state.Operation {
			removed = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !removed || !selected {
		t.Fatal("original provider/finalization did not select and retire share", err)
	}
	cooling, err := readShareRetirementSnapshot(ctx, f.admin, s.a.RootID, "normal", in.PrincipalDigest[:], shareID, in.ID, in.Lifecycle.HistoryReleaseAt, in.Lifecycle.HistoryDeleteBy)
	if err != nil || cooling.Share || cooling.Operation || cooling.Lifecycle || cooling.OriginalRecords != 1 || cooling.Eligible == nil || cooling.AccountCharge == nil || !cooling.ObservedAt.Before(*cooling.Eligible) || *cooling.AccountCharge != cooling.LiveRecords+cooling.HistoryRecords {
		t.Fatal("share deletion did not retain original H charge", err)
	}
	eligible, charged := *cooling.Eligible, *cooling.AccountCharge
	t.Logf("share_retirement_stage=child_and_parent_deleted original_H=%d remaining_cooling_ms=%d charged=%d", policy.BackupHorizonSeconds, time.Until(eligible).Milliseconds(), charged)
	for time.Now().Before(eligible) {
		f.refreshFleet(t)
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	f.refreshFleet(t)
	keys, err := ledgers[0].DueOperationHistory(ctx)
	if err != nil || len(keys) != 1 {
		t.Fatal("original cooling selection", err, len(keys))
	}
	if _, err = ledgers[2].ReleaseOperationHistory(ctx, keys[0]); err != nil {
		t.Fatal("original cooling drain", err)
	}
	var after int64
	if err = f.admin.QueryRow(ctx, `SELECT charged FROM operation_audit_account WHERE root_id=$1 AND lane='normal' AND principal_digest=$2`, s.a.RootID, in.PrincipalDigest[:]).Scan(&after); err != nil || after != charged-1 {
		t.Fatal("cooling failed exact original slot release", err, charged, after)
	}
	drained, err := readShareRetirementSnapshot(ctx, f.admin, s.a.RootID, "normal", in.PrincipalDigest[:], shareID, in.ID, in.Lifecycle.HistoryReleaseAt, in.Lifecycle.HistoryDeleteBy)
	if err != nil || drained.Share || drained.Operation || drained.Lifecycle || drained.Eligible != nil || drained.OriginalRecords != 0 || drained.ObservedAt.Before(eligible) || drained.AccountCharge == nil || *drained.AccountCharge != drained.LiveRecords+drained.HistoryRecords {
		t.Fatal("paid share original eligibility/refund snapshot", err)
	}
	// An unmatched principal is a read-only decoder boundary, never an actor
	// or authority: exercise a missing account's NULL without creating one.
	absentPrincipal := append(append([]byte{}, in.PrincipalDigest[:]...), 0)
	absent, err := readShareRetirementSnapshot(ctx, f.admin, s.a.RootID, "normal", absentPrincipal, shareID, in.ID, in.Lifecycle.HistoryReleaseAt, in.Lifecycle.HistoryDeleteBy)
	if err != nil || absent.AccountCharge != nil || absent.LiveRecords+absent.HistoryRecords != 0 || absent.Eligible != nil {
		t.Fatal("absent paid-share account snapshot decoding", err)
	}
	t.Log("share_retirement_stage=original_H_elapsed_exact_one_charge_released")
}
