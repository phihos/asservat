package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	privacyvalue "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The protected installation policy, privacy operator, and measured backing are
// explicit synthetic qualification inputs. Decisions, their audit rows, SQL
// CAS and subsequent restriction reads use actual product components and
// separate real database credentials.
type processingTestPolicy struct{ value privacyvalue.DownloadPolicy }

func (p processingTestPolicy) DownloadPolicy(ctx context.Context) (privacyvalue.DownloadPolicy, error) {
	if ctx.Err() != nil {
		return privacyvalue.DownloadPolicy{}, ctx.Err()
	}
	v := p.value
	n := time.Now().UTC().Truncate(time.Microsecond)
	v.ObservedAt = n
	v.FreshUntil = n.Add(5 * time.Second)
	return v, nil
}

type processingTestIdentity struct{ value identity.Identity }

func (p processingTestIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if ctx.Err() != nil {
		return identity.Identity{}, ctx.Err()
	}
	v := p.value
	n := time.Now().UTC().Truncate(time.Microsecond)
	v.VerifiedAt = n
	v.ValidUntil = n.Add(5 * time.Second)
	return v, nil
}

// shareAuditCohorts holds the normal-lane audit policy and retention that a
// sharing-cohort processing fixture provisioned, keyed by processing root.
// Only the share audit fixture reads it; remove both once sharing writes
// audit_event rows.
var shareAuditCohorts sync.Map

type shareAuditCohort struct {
	policy   audit.OperationLifecyclePolicy
	retained int64
}

type processingTestFixture struct {
	service privacyapp.ProcessingChanges
	actor   processingTestIdentity
	policy  processingTestPolicy
	backing privacyvalue.ProcessingBacking
	pools   []*pgxpool.Pool
	renew   func() error
}

func (f *processingTestFixture) Close() {
	for _, p := range f.pools {
		p.Close()
	}
}
func newProcessingTestFixture(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, e artifact.ContextExpectation, sharingCohort ...bool) *processingTestFixture {
	t.Helper()
	f := &processingTestFixture{}
	open := func(role, password string) *pgxpool.Pool {
		p := poolFor(role, password)
		f.pools = append(f.pools, p)
		return p
	}
	failed := true
	defer func() {
		if failed {
			f.Close()
		}
	}()
	configPool := open("processing_config_runtime", "synthetic-processing-config")
	decisionPool := open("processing_decision_runtime", "synthetic-processing-decision")
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(time.Hour)
	if until.Before(e.Registration.DeleteBy.Add(time.Minute)) {
		until = e.Registration.DeleteBy.Add(time.Minute)
	}
	path := syntheticDownloadPlacement(e.Registration)
	actor := s.a.Eligibility.VerifiedIdentity
	f.actor = processingTestIdentity{actor}
	f.policy = processingTestPolicy{privacyvalue.DownloadPolicy{RootID: s.a.RootID, InstallationID: s.recovery.installation, RecoveryEpoch: s.recovery.observation.issuer, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{3}}, ProtectionDigest: artifact.Digest{4}, PermittedRegions: []string{"synthetic-region"}, Paths: []privacyvalue.DownloadPath{path}, Clients: []privacyvalue.DownloadClient{}, Operators: []privacyvalue.ProcessingOperator{{Issuer: actor.Principal.Issuer, ClientID: actor.Principal.ClientID, Kind: "User", ID: actor.Principal.Subject}}}}
	f.backing = privacyvalue.ProcessingBacking{RootID: s.a.RootID, InstallationID: s.recovery.installation, PolicyID: custodyID(), BackupIdentity: custodyID(), PolicyDigest: artifact.Digest{1}, BackupDigest: artifact.Digest{2}, History: privacyvalue.ProcessingHistoryQualification{Format: privacyvalue.ProcessingHistoryFormat, ID: custodyID(), Digest: artifact.Digest{5}, RowBytes: 128 << 10, TransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}, MaxCaptures: 128, MaxRules: 16, MaxRootTransitions: 64, BackupHorizonSeconds: 2, CleanupSeconds: 5, ValidUntil: until, RetireBy: until.Add(9 * time.Second)}
	var ok bool
	f.backing.BackupBytes, f.backing.WALBytes, ok = f.backing.RequiredBytes()
	if !ok {
		t.Fatal("fixture processing backing")
	}
	if len(sharingCohort) > 0 && sharingCohort[0] {
		provisionShareAuditCohort(t, ctx, open("operation_audit_config_runtime", "synthetic-operation-config"), s, until)
	}
	decisions, err := postgres.NewProcessingDecisions(ctx, decisionPool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	f.service = privacyapp.ProcessingChanges{RootID: s.a.RootID, InstallationID: s.recovery.installation, Policies: f.policy, Decisions: decisions, Now: time.Now}
	epoch := custodyID()
	config, err := postgres.NewProcessingConfiguration(ctx, configPool, f.backing, epoch, f.policy.value.Revision.UID, f.policy.value.ProtectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.policy.DownloadPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = config.AcceptCurrent(ctx, p, 0); err != nil {
		t.Fatal("accept processing backing", err)
	}
	revision := int64(1)
	f.renew = func() error {
		next := f.backing
		next.ValidUntil = next.ValidUntil.Add(time.Minute)
		next.RetireBy = next.RetireBy.Add(time.Minute)
		next.MaxRootTransitions += 8
		var ok bool
		next.BackupBytes, next.WALBytes, ok = next.RequiredBytes()
		if !ok {
			return privacyvalue.ErrUnavailable
		}
		updated, err := postgres.NewProcessingConfiguration(ctx, configPool, next, epoch, f.policy.value.Revision.UID, f.policy.value.ProtectionDigest)
		if err != nil {
			return err
		}
		p, err := f.policy.DownloadPolicy(ctx)
		if err != nil {
			return err
		}
		if err = updated.AcceptCurrent(ctx, p, revision); err != nil {
			return err
		}
		revision++
		f.backing = next
		return nil
	}
	failed = false
	return f
}

// provisionShareAuditCohort keeps the normal-lane pool the share audit
// fixture still uses (original bounded sharing scenario, including negative
// ingress and replays).
func provisionShareAuditCohort(t *testing.T, ctx context.Context, pool *pgxpool.Pool, s captureAdmissionScenario, until time.Time) {
	t.Helper()
	config, err := postgres.New(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	const accounts, records, retained = int64(16), int64(256), int64(7200)
	p := audit.OperationLifecyclePolicy{RootID: s.a.RootID, Lane: "normal", InstallationID: s.recovery.installation, StoreID: custodyID(), PolicyID: custodyID(), BackupProfileID: custodyID(), PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: accounts * records, MaxPurgeLeases: 4, CleanupBudgetSeconds: 8, ProofWindowSeconds: 2, ValidUntil: until}
	// Explicit synthetic per-scenario input. The bounded policy100
	// measurement and production maximum-width qualification are pending.
	p.History = &audit.OperationHistoryQualification{ID: custodyID(), Digest: artifact.Digest{5}, Layout: audit.ShareOperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 2 << 20, BackupCopies: 2, WALCopies: 2}
	bb, ww := p.History.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes = bb * p.MetadataSlots
	p.WALReservedBytes = ww * p.MetadataSlots
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err = config.ProvisionOperationAuditPool(ctx, auditapp.OperationAuditPool{RootID: s.a.RootID, Lane: "normal", AccountVersion: "accounts-v1", Accounts: accounts, RecordsPerAccount: records, RetainedSeconds: retained, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: until}); err != nil {
		t.Fatal("share audit pool", err)
	}
	shareAuditCohorts.Store(s.a.RootID, shareAuditCohort{p, retained})
}

// initializeProcessingTestFixture creates the processing root, which is
// initialized at creation (ADR-335 D1).
func initializeProcessingTestFixture(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, e artifact.ContextExpectation) {
	t.Helper()
	newProcessingTestFixture(t, ctx, poolFor, store, keys, s, e).Close()
}
func syntheticDownloadPlacement(r artifact.Registration) artifact.DownloadPath {
	return artifact.DownloadPath{ID: custodyID(), TargetClusterID: r.Location.ClusterID, StoreID: r.StoreID, StorageRegion: "synthetic-region", AcquisitionClusterID: r.Location.ClusterID, AcquisitionRegion: "synthetic-region", ConnectorClusterID: r.Location.ClusterID, ConnectorRegion: "synthetic-region", HubClusterID: r.Location.ClusterID, HubRegion: "synthetic-region", WorkerConfiguration: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{81}}, HubConfiguration: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{82}}}
}
func newDownloadTestEnvironment(t *testing.T, ctx context.Context, pool *pgxpool.Pool, s captureAdmissionScenario, r artifact.Registration) downloadTestEnvironment {
	t.Helper()
	reader, err := postgres.NewProcessingReads(ctx, pool, s.a.RootID, s.recovery.installation)
	if err != nil {
		t.Fatal(err)
	}
	path := syntheticDownloadPlacement(r)
	return downloadTestEnvironment{root: s.a.RootID, installation: s.recovery.installation, epoch: s.recovery.observation.issuer, registration: r, processing: reader, path: &path}
}

var _ authorizationapp.DownloadEnvironmentReader = downloadTestEnvironment{}
