package integration

import (
	"bytes"
	"context"
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
// explicit synthetic qualification inputs. The initialization, encrypted pair,
// independent acknowledgement, SQL completeness/CAS and subsequent restriction
// reads use actual product components and separate real database credentials.
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

type processingTestFixture struct {
	service privacyapp.ProcessingChanges
	actor   processingTestIdentity
	policy  processingTestPolicy
	backing privacyvalue.ProcessingBacking
	pools   []*pgxpool.Pool
	mac     *auditapp.OperationMAC
	renew   func() error
}

func (f *processingTestFixture) Close() {
	for _, p := range f.pools {
		p.Close()
	}
	f.mac.Close()
}
func newProcessingTestFixture(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, e artifact.ContextExpectation) *processingTestFixture {
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
	auditConfigPool := open("operation_audit_config_runtime", "synthetic-operation-config")
	normalPool := open("operation_audit_runtime", "synthetic-operation-journal")
	normalAck := open("operation_audit_ack_runtime", "synthetic-operation-ack")
	releasePool := open("operation_audit_runtime", "synthetic-operation-journal")
	releaseAck := open("operation_audit_ack_runtime", "synthetic-operation-ack")
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(time.Hour)
	if until.Before(e.Registration.DeleteBy.Add(time.Minute)) {
		until = e.Registration.DeleteBy.Add(time.Minute)
	}
	path := syntheticDownloadPlacement(e.Registration)
	actor := s.a.Eligibility.VerifiedIdentity
	f.actor = processingTestIdentity{actor}
	f.policy = processingTestPolicy{privacyvalue.DownloadPolicy{RootID: s.a.RootID, InstallationID: s.recovery.installation, RecoveryEpoch: s.a.Recovery.IssuerEpoch, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{3}}, ProtectionDigest: artifact.Digest{4}, PermittedRegions: []string{"synthetic-region"}, Paths: []privacyvalue.DownloadPath{path}, Clients: []privacyvalue.DownloadClient{}, Operators: []privacyvalue.ProcessingOperator{{Issuer: actor.Principal.Issuer, ClientID: actor.Principal.ClientID, Kind: "User", ID: actor.Principal.Subject}}}}
	f.backing = privacyvalue.ProcessingBacking{RootID: s.a.RootID, InstallationID: s.recovery.installation, PolicyID: custodyID(), BackupIdentity: custodyID(), PolicyDigest: artifact.Digest{1}, BackupDigest: artifact.Digest{2}, History: privacyvalue.ProcessingHistoryQualification{Format: privacyvalue.ProcessingHistoryFormat, ID: custodyID(), Digest: artifact.Digest{5}, RowBytes: 128 << 10, TransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}, MaxCaptures: 128, MaxRules: 16, MaxRootTransitions: 64, BackupHorizonSeconds: 2, CleanupSeconds: 5, ValidUntil: until, RetireBy: until.Add(9 * time.Second)}
	var ok bool
	f.backing.BackupBytes, f.backing.WALBytes, ok = f.backing.RequiredBytes()
	if !ok {
		t.Fatal("fixture processing backing")
	}
	auditConfig, err := postgres.New(ctx, auditConfigPool)
	if err != nil {
		t.Fatal(err)
	}
	policy := func(lane string, accounts, records int64) audit.OperationLifecyclePolicy {
		p := audit.OperationLifecyclePolicy{RootID: s.a.RootID, Lane: lane, InstallationID: s.recovery.installation, StoreID: custodyID(), PolicyID: custodyID(), BackupProfileID: custodyID(), PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: accounts * records, MaxPurgeLeases: 4, CleanupBudgetSeconds: 8, ProofWindowSeconds: 2, ValidUntil: until}
		layout := audit.OperationVerificationHistoryLayout
		if lane == "processing" {
			layout = audit.ProcessingReleaseHistoryLayout
		}
		p.History = &audit.OperationHistoryQualification{ID: custodyID(), Digest: artifact.Digest{5}, Layout: layout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
		bb, ww := p.History.SlotBacking(p.MaxPurgeLeases)
		p.BackupReservedBytes = bb * p.MetadataSlots
		p.WALReservedBytes = ww * p.MetadataSlots
		now := time.Now().UTC().Truncate(time.Microsecond)
		b := auditapp.OperationAuditPool{RootID: s.a.RootID, Lane: lane, AccountVersion: "accounts-v1", Accounts: accounts, RecordsPerAccount: records, RetainedSeconds: 3600, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: until}
		if lane == "processing" {
			err = auditConfig.ProvisionProcessingReleaseAuditPool(ctx, b, p)
		} else {
			err = auditConfig.ProvisionOperationAuditPool(ctx, b)
		}
		if err != nil {
			t.Fatal("processing audit pool", err)
		}
		return p
	}
	normalPolicy := policy("normal", 2, 2)
	releasePolicy := policy("processing", f.backing.MaxRules, 16)
	makeAudit := func(p audit.OperationLifecyclePolicy, jp, ap *pgxpool.Pool) *auditapp.HealthyOperationAuditor {
		var j *postgres.OperationJournal
		var a *postgres.OperationAcknowledgements
		var l *postgres.OperationLifecycles
		if p.Lane == "processing" {
			j, err = postgres.NewProcessingReleaseJournal(ctx, jp, p, s.recovery.guard)
			if err == nil {
				a, err = postgres.NewProcessingReleaseAcknowledgements(ctx, ap, p, s.recovery.guard)
			}
			if err == nil {
				l, err = postgres.NewProcessingReleaseLifecycles(ctx, jp, p, s.recovery.guard)
			}
		} else {
			j, err = postgres.NewHealthyOperationJournal(ctx, jp, p, s.recovery.guard)
			if err == nil {
				a, err = postgres.NewOperationAcknowledgements(ctx, ap, p.RootID, "normal", s.recovery.guard)
			}
			if err == nil {
				l, err = postgres.NewOperationLifecycles(ctx, jp, p.RootID, "normal", s.recovery.guard)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		objects, err := objectstore.NewClosedOperationAuditObjects(store, p.StoreID, keys, keys)
		if err != nil {
			t.Fatal(err)
		}
		g, err := auditapp.NewHealthyOperationAuditor(p, j, a, &objectstore.OperationAuditObjects{Store: store, Seal: keys, Open: keys}, objects, l, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	f.mac, err = auditapp.NewOperationMAC("input-v1", bytes.Repeat([]byte{31}, 32), "accounts-v1", bytes.Repeat([]byte{32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := postgres.NewProcessingDecisions(ctx, decisionPool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	f.service = privacyapp.ProcessingChanges{RootID: s.a.RootID, InstallationID: s.recovery.installation, Policies: f.policy, Recovery: s.recovery.reader, Decisions: decisions, Audit: makeAudit(normalPolicy, normalPool, normalAck), ReleaseAudit: makeAudit(releasePolicy, releasePool, releaseAck), MAC: f.mac, AuditPolicy: normalPolicy, ReleaseAuditPolicy: releasePolicy, RetainedSeconds: 3600, Now: time.Now}
	epoch := custodyID()
	config, err := postgres.NewProcessingConfiguration(ctx, configPool, f.backing, releasePolicy, epoch, f.policy.value.Revision.UID, f.policy.value.ProtectionDigest, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.policy.DownloadPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = config.AcceptCurrent(ctx, p, r, 0); err != nil {
		t.Fatal("accept processing backing", err)
	}
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
		releasePolicy.BackingRevision++
		releasePolicy.ValidUntil = next.ValidUntil
		n := time.Now().UTC().Truncate(time.Microsecond)
		pool := auditapp.OperationAuditPool{RootID: s.a.RootID, Lane: "processing", AccountVersion: "accounts-v1", Accounts: next.MaxRules, RecordsPerAccount: 16, RetainedSeconds: 3600, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), ValidUntil: next.ValidUntil, ExpectedRevision: releasePolicy.BackingRevision - 1}
		if err := auditConfig.ProvisionProcessingReleaseAuditPool(ctx, pool, releasePolicy); err != nil {
			return err
		}
		updated, err := postgres.NewProcessingConfiguration(ctx, configPool, next, releasePolicy, epoch, f.policy.value.Revision.UID, f.policy.value.ProtectionDigest, s.recovery.guard)
		if err != nil {
			return err
		}
		p, err := f.policy.DownloadPolicy(ctx)
		if err != nil {
			return err
		}
		r, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			return err
		}
		if err = updated.AcceptCurrent(ctx, p, r, releasePolicy.BackingRevision-1); err != nil {
			return err
		}
		f.backing = next
		f.service.ReleaseAuditPolicy = releasePolicy
		f.service.ReleaseAudit = makeAudit(releasePolicy, releasePool, releaseAck)
		return nil
	}
	failed = false
	return f
}
func initializeProcessingTestFixture(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, e artifact.ContextExpectation) {
	t.Helper()
	f := newProcessingTestFixture(t, ctx, poolFor, store, keys, s, e)
	defer f.Close()
	initializeProcessingTestFixtureWith(t, ctx, f)
}
func initializeProcessingTestFixtureWith(t *testing.T, ctx context.Context, f *processingTestFixture) {
	t.Helper()
	if _, err := f.service.Change(ctx, f.actor, privacyvalue.ProcessingChange{RequestID: custodyID(), Action: "initialize_processing"}); err != nil {
		t.Fatal("actual processing initialization", err)
	}
}
func syntheticDownloadPlacement(r artifact.Registration) artifact.DownloadPath {
	return artifact.DownloadPath{ID: custodyID(), TargetClusterID: r.Location.ClusterID, StoreID: r.StoreID, StorageRegion: "synthetic-region", AcquisitionClusterID: r.Location.ClusterID, AcquisitionRegion: "synthetic-region", ConnectorClusterID: r.Location.ClusterID, ConnectorRegion: "synthetic-region", HubClusterID: r.Location.ClusterID, HubRegion: "synthetic-region", WorkerConfiguration: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{81}}, HubConfiguration: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{82}}}
}
func newDownloadTestEnvironment(t *testing.T, ctx context.Context, pool *pgxpool.Pool, s captureAdmissionScenario, r artifact.Registration) downloadTestEnvironment {
	t.Helper()
	reader, err := postgres.NewProcessingReads(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	path := syntheticDownloadPlacement(r)
	return downloadTestEnvironment{root: s.a.RootID, installation: s.recovery.installation, epoch: s.a.Recovery.IssuerEpoch, registration: r, recovery: s.recovery.reader, processing: reader, path: &path}
}

var _ authorizationapp.DownloadEnvironmentReader = downloadTestEnvironment{}
