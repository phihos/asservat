package bootstrap

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"

	"asservat.local/asservat/internal/adapters/mounts"
	app "asservat.local/asservat/internal/application/capacity"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// capacityDerived are the values the installer derives from the objects it
// created or read (ADR-190 decision 5); none comes from the operator.
type capacityDerived struct {
	SharedQueries                      bool
	Root, Installation, AccountVersion string
	SystemPoolUID, ProcessingSourceUID string
	ProcessingProtection               artifact.Digest
	NamespaceGuards                    []app.CapacityNamespaceQualification
	// Now is the setup time; ValidUntil starts there, which keeps the capture
	// root closed until the hub-worker's reserve phase sets its planned date.
	Now time.Time
}

// profileDigest is the SHA-256 of a canonical profile section: each opaque
// evidence digest names exactly the operator input it qualifies.
func profileDigest(section string, v any) artifact.Digest {
	b, _ := json.Marshal(struct {
		Section string `json:"section"`
		Value   any    `json:"value"`
	}{section, v})
	return artifact.Digest(sha256.Sum256(b))
}

// buildCapacityQualification maps the operator's capacity profile, freshly
// minted identities and the derived values to the qualification that
// InitializeCapacity records. It checks the result with the same validators
// the setup and the SQL backing use.
func buildCapacityQualification(p contracts.InstallerCapacitySettings, d capacityDerived, newID func() string) (app.CapacityQualification, error) {
	var zero app.CapacityQualification
	if len(p.Backends) != 1 || !authorization.UUID(d.Root) || !authorization.UUID(d.Installation) {
		// ponytail: one backend, the system pool; more pools add their own.
		return zero, mounts.ErrUnavailable
	}
	now := d.Now.UTC().Truncate(time.Microsecond)
	b := p.Backup
	store, backup := newID(), newID()
	backupDigest := profileDigest("backup", b)
	history := func(layout string, f contracts.InstallerCapacityFootprint) audit.OperationHistoryQualification {
		return audit.OperationHistoryQualification{ID: newID(), Digest: profileDigest("history/"+layout, f), Layout: layout,
			MaximumRowFootprintBytes: f.RowBytes, MaximumTransitionWALBytes: f.TransitionWALBytes, BackupCopies: b.BackupCopies, WALCopies: b.WALCopies}
	}
	capture := history(audit.CaptureOperationHistoryLayout, p.Footprints.Capture)
	lane := func(name string, q audit.OperationHistoryQualification, accounts, records, retained int64) app.RootAuditBacking {
		backupBytes, walBytes := q.SlotBacking(p.PurgeLeases)
		return app.RootAuditBacking{Accounts: accounts, RecordsPerAccount: records, RetainedSeconds: retained, Policy: audit.OperationLifecyclePolicy{
			RootID: d.Root, Lane: name, InstallationID: d.Installation, StoreID: store, PolicyID: newID(), BackupProfileID: backup,
			PolicyDigest: profileDigest("lane/"+name, struct{ Accounts, Records, Retained int64 }{accounts, records, retained}), BackupProfileDigest: backupDigest,
			BackingRevision: 1, MetadataSlots: accounts * records, BackupReservedBytes: accounts * records * backupBytes, WALReservedBytes: accounts * records * walBytes,
			BackupHorizonSeconds: b.HorizonSeconds, CleanupBudgetSeconds: b.CleanupBudgetSeconds, ProofWindowSeconds: b.ProofWindowSeconds,
			ValidUntil: now, MaxPurgeLeases: p.PurgeLeases, History: &q, OverdueTerminal: audit.OperationOverdueTerminal}}
	}
	l := p.Lanes
	in := app.RootBackingInput{Format: app.RootBackingFormat, RootID: d.Root, InstallationID: d.Installation, QualificationID: newID(), QualificationDigest: profileDigest("capacity", p),
		SystemPoolUID: d.SystemPoolUID, AccountVersion: d.AccountVersion, Accounts: p.Accounts, RecordsPerAccount: p.Records, AdmissionSeconds: p.AdmissionSeconds,
		ProcessingEpoch: newID(), ProcessingSourceUID: d.ProcessingSourceUID, ProcessingProtectionDigest: d.ProcessingProtection,
		Capture:             lane("capture", capture, p.Accounts, p.Records, l.CaptureRetainedSeconds),
		Normal:              lane("normal", history(audit.OperationVerificationHistoryLayout, p.Footprints.Operation), l.Normal.Accounts, l.Normal.Records, l.Normal.RetainedSeconds),
		Resolution:          lane("resolution", history(audit.OperationVerificationHistoryLayout, p.Footprints.Operation), l.Resolution.Accounts, l.Resolution.Records, l.Resolution.RetainedSeconds),
		Processing:          lane("processing", history(audit.ProcessingReleaseHistoryLayout, p.Footprints.Processing), l.Processing.Accounts, l.Processing.Records, l.Processing.RetainedSeconds),
		StopRetainedSeconds: p.StopRetainedSeconds,
	}
	f := p.Footprints
	in.ContextHistory = app.ContextBackingHistory{Capture: capture, CapturePurgeLeases: p.PurgeLeases,
		Native: authorization.NativeHistoryQualification{ID: newID(), Digest: profileDigest("native", f.Native), RowBytes: f.Native.RowBytes, TransitionWALBytes: f.Native.TransitionWALBytes, BackupCopies: b.BackupCopies, WALCopies: b.WALCopies},
		Stop: audit.DownloadStopLifecyclePolicy{RootID: d.Root, InstallationID: d.Installation, StoreID: store, PolicyID: newID(), BackupProfileID: backup, QualificationID: newID(),
			PolicyDigest: profileDigest("stop", p.StopRetainedSeconds), BackupProfileDigest: backupDigest, QualificationDigest: profileDigest("stop-history", f.Stop), Layout: audit.DownloadStopHistoryLayout,
			BackupHorizonSeconds: b.HorizonSeconds, CleanupBudgetSeconds: b.CleanupBudgetSeconds, ProofWindowSeconds: b.ProofWindowSeconds,
			MaximumRowFootprintBytes: f.Stop.RowBytes, MaximumTransitionWALBytes: f.Stop.TransitionWALBytes, BackupCopies: b.BackupCopies, WALCopies: b.WALCopies, MaxPurgeLeases: p.PurgeLeases}}
	m := p.Metadata
	in.Metadata = app.RootMetadataQualification{ID: newID(), Layout: app.RootMetadataLayout, Digest: profileDigest("metadata", m), FixedRowBytes: m.FixedRowBytes, AccountRowBytes: m.AccountRowBytes,
		RecordRowBytes: m.RecordRowBytes, RecordWALBytes: m.RecordWALBytes, RecordKeyAttempts: m.RecordKeyAttempts, TransitionWALBytes: m.TransitionWALBytes,
		BackupCopies: b.BackupCopies, WALCopies: b.WALCopies, ConfigurationTransitions: m.ConfigurationTransitions}
	e := p.Envelope
	in.Envelope = app.RootBackingEnvelope{SystemObjects: app.BudgetAmount{Bytes: e.SystemObjects.Bytes, Objects: e.SystemObjects.Objects}, SQLBytes: e.SQLBytes, BackupBytes: e.BackupBytes, WALBytes: e.WALBytes, KeyAttempts: e.KeyAttempts}
	in.ProcessingState = privacy.ProcessingBacking{RootID: d.Root, InstallationID: d.Installation, PolicyID: newID(), BackupIdentity: backup,
		PolicyDigest: profileDigest("processing", p.Processing), BackupDigest: backupDigest,
		History: privacy.ProcessingHistoryQualification{Format: privacy.ProcessingHistoryFormat, ID: newID(), Digest: profileDigest("processing-history", f.ProcessingState),
			RowBytes: f.ProcessingState.RowBytes, TransitionWALBytes: f.ProcessingState.TransitionWALBytes, BackupCopies: b.BackupCopies, WALCopies: b.WALCopies},
		MaxCaptures: p.Accounts * p.Records, MaxRules: p.Processing.MaxRules, MaxRootTransitions: p.Processing.MaxRootTransitions,
		BackupHorizonSeconds: b.HorizonSeconds, CleanupSeconds: b.CleanupBudgetSeconds, ValidUntil: now,
		RetireBy: now.Add(time.Duration(2*b.HorizonSeconds+b.CleanupBudgetSeconds) * time.Second)}
	var ok bool
	if in.ProcessingState.BackupBytes, in.ProcessingState.WALBytes, ok = in.ProcessingState.RequiredBytes(); !ok {
		return zero, mounts.ErrUnavailable
	}
	backend := p.Backends[0]
	q := app.CapacityQualification{ID: in.QualificationID, Digest: in.QualificationDigest, RootBacking: in, NamespaceGuards: d.NamespaceGuards,
		Backends: []app.CapacityBackendQualification{{Layout: app.CapacityBackendLayout, ID: newID(), Digest: profileDigest("backend", backend), PoolUID: d.SystemPoolUID,
			StorageProfile: backend.StorageProfile, CapacityID: newID(), PoolID: newID(), EvidenceStoreID: newID(), AuditStoreID: store,
			Usable: app.BudgetAmount{Bytes: backend.Usable.Bytes, Objects: backend.Usable.Objects}}}}
	if d.SharedQueries {
		x, err := installedQueryBudget(p, newID)
		if err != nil {
			return zero, err
		}
		q.ContextQuery = &x
	}
	if !app.ValidateRootBackingInput(in) || !q.Valid() {
		return zero, mounts.ErrUnavailable
	}
	return q, nil
}

// capacityIDs derives the installer-minted capacity identities from the role
// setup operation (ADR-192): the nth call returns the same UUID on every
// replay of the same binary. They are identities, not secrets.
func capacityIDs(setup string) func() string {
	space, n := uuid.MustParse(setup), 0
	return func() string {
		n++
		return uuid.NewSHA1(space, []byte("capacity/"+strconv.Itoa(n))).String()
	}
}

// buildConnectorBacking derives the installation-wide connector root backing
// (ADR-193) from the operator's connector limits and the capacity backup
// profile. Identities derive from the role setup like capacityIDs, so a
// replay rebuilds the same backing; source reservations are the minimum the
// prepaid-retirement layout's own validator accepts.
func buildConnectorBacking(c contracts.InstallerConnectorSettings, b contracts.InstallerCapacityBackup, root, installation, accountVersion, setup string, now time.Time) (fleetapp.ConnectorIdentityBacking, error) {
	var zero fleetapp.ConnectorIdentityBacking
	if !authorization.UUID(setup) || c.ValidSeconds < 3600 || c.ValidSeconds > 366*86400 {
		return zero, mounts.ErrUnavailable
	}
	space, n := uuid.MustParse(setup), 0
	newID := func() string {
		n++
		return uuid.NewSHA1(space, []byte("connector/"+strconv.Itoa(n))).String()
	}
	q := audit.OperationHistoryQualification{ID: newID(), Digest: profileDigest("history/"+audit.ConnectorRetirementHistoryLayout, c.Footprint), Layout: audit.ConnectorRetirementHistoryLayout,
		MaximumRowFootprintBytes: c.Footprint.RowBytes, MaximumTransitionWALBytes: c.Footprint.TransitionWALBytes, BackupCopies: b.BackupCopies, WALCopies: b.WALCopies}
	slots := c.Accounts * c.RecordsPerAccount
	backupBytes, walBytes := q.SlotBacking(c.PurgeLeases)
	now = now.UTC().Truncate(time.Microsecond)
	out := fleetapp.ConnectorIdentityBacking{AccountVersion: accountVersion, AccountLimit: c.Accounts, RecordsPerAccount: c.RecordsPerAccount, RetainedSeconds: c.RetainedSeconds,
		ProfileLimit: c.Profiles, SourceTransitionLimit: c.SourceTransitions, Policy: audit.OperationLifecyclePolicy{
			RootID: root, Lane: "identity", InstallationID: installation, StoreID: newID(), PolicyID: newID(), BackupProfileID: newID(),
			PolicyDigest: profileDigest("connector", c), BackupProfileDigest: profileDigest("backup", b),
			BackingRevision: 1, MetadataSlots: slots, BackupReservedBytes: slots * backupBytes, WALReservedBytes: slots * walBytes,
			BackupHorizonSeconds: b.HorizonSeconds, CleanupBudgetSeconds: b.CleanupBudgetSeconds, ProofWindowSeconds: b.ProofWindowSeconds,
			ValidUntil: now.Add(time.Duration(c.ValidSeconds) * time.Second), MaxPurgeLeases: c.PurgeLeases, History: &q, OverdueTerminal: audit.OperationOverdueTerminal}}
	// ponytail: at most 256 regional peers and 4096 source transitions each,
	// which keeps the reservation products below int64; raise both with
	// checked multiplication if an installation needs more.
	if c.Accounts < 1 || c.Accounts > 4096 || c.RecordsPerAccount < 2 || c.RecordsPerAccount > 1000000 || c.Profiles < 1 || c.Profiles > 256 || c.Profiles > c.Accounts || c.SourceTransitions < c.Profiles || c.SourceTransitions > 4096 || !q.Valid() {
		return zero, mounts.ErrUnavailable
	}
	rows := 1 + c.Profiles + c.Profiles*(c.SourceTransitions+1)
	out.SourceBackupReservedBytes = rows * 2 * q.MaximumRowFootprintBytes * q.BackupCopies
	out.SourceWALReservedBytes = (2*c.SourceTransitions + fleetapp.ConnectorRetirementTicketTransitions*c.Profiles*(c.SourceTransitions+1)) * q.MaximumTransitionWALBytes * q.WALCopies
	// The process run time is the retention minus two backup horizons, three
	// cleanup budgets, the proof window and a minute; it must cover the fixed
	// regional deployment shape.
	if !out.Valid() || !out.SupportsProcessLimits(contracts.RegionalServingSlots, contracts.RegionalRetainedProcesses) {
		return zero, mounts.ErrUnavailable
	}
	return out, nil
}

// installedQueryBudget declares finite logical work/history under the original
// operator envelope. Actual Job limits remain the installed shared profile; the
// global worker/hub/provider admission limits are not multiplied per query.
// These are configured ceilings, not measured overhead or a new deployment.
func installedQueryBudget(p contracts.InstallerCapacitySettings, newID func() string) (app.ContextQueryQualification, error) {
	rev := identity.Revision{UID: newID(), Generation: 1, Digest: profileDigest("shared-query/v1", p)}
	// Four paid status polls and 32 state transitions bound retained SQL work.
	// One worker intent, one enrollment and two signing audits are independent.
	const polls, controls, signs int64 = 4, 32, 2
	rows := int64(10) + (1 + polls) + controls
	row := max(p.Footprints.Native.RowBytes, p.Metadata.RecordRowBytes)
	wal := max(p.Footprints.Native.TransitionWALBytes, p.Metadata.TransitionWALBytes)
	h := app.QueryHistoryQualification{Layout: app.ContextQueryHistoryLayout, Revision: rev, FixedBytes: p.Metadata.FixedRowBytes, PrincipalBytes: p.Metadata.AccountRowBytes, AllocationBytes: p.Metadata.AccountRowBytes, RowBytes: row, FixedQueryRows: 10, InvocationRows: 1, ControlRows: 1, TransitionWALBytes: wal, BackupCopies: p.Backup.BackupCopies, WALCopies: p.Backup.WALCopies, AuditCipherBytes: 64 << 10, BackupHorizon: time.Duration(p.Backup.HorizonSeconds) * time.Second, RetirementCleanup: time.Duration(p.Backup.CleanupBudgetSeconds) * time.Second}
	profile := query.ContextQueryResourceProfile{ID: newID(), Source: rev, Qualification: rev, Path: query.ContextProjectionPath{Purpose: query.ContextProjectionPurpose}, Lifetime: query.ContextMaxQueryTime, PollLimit: polls, ControlTransitionLimit: controls,
		Worker: query.ContextQueryWorkerLimits{CPUMilli: downloadWorkerCPUMillis, MemoryBytes: downloadWorkerMemoryBytes, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10, ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: query.ContextMaxQueryTime, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Duration(p.Backup.CleanupBudgetSeconds) * time.Second},
		Cost:   query.ContextQueryCost{Workers: 1, ReadBatches: query.ContextMaxReadBatches, ReadBytes: query.ContextMaxReadBatches * query.ContextBatchReadWork, StructuredBytes: query.ContextMaxReadBatches * query.ContextResultBytes, WireBytes: query.ContextMaxReadBatches * query.ContextWireBytes, UnwrapAttempts: 3 * query.ContextMaxReadBatches, ProviderRequests: 100, AuthenticationRequests: 100, SigningAttempts: signs, AuditObjects: 2*(1+polls) + 2 + signs, SQLRows: rows}}
	// Operator values are validated by the complete qualification below. Use
	// checked products here before constructing any persistent declaration.
	product := func(a, b int64) (int64, bool) {
		if a <= 0 || b <= 0 || a > (1<<60)/b {
			return 0, false
		}
		return a * b, true
	}
	var ok bool
	if profile.Cost.SQLBytes, ok = product(rows, row); !ok {
		return app.ContextQueryQualification{}, mounts.ErrUnavailable
	}
	if profile.Cost.BackupBytes, ok = product(profile.Cost.SQLBytes, h.BackupCopies); !ok {
		return app.ContextQueryQualification{}, mounts.ErrUnavailable
	}
	// The existing query counter excludes worker/enrollment/certificate rows.
	// Reserve their configured WAL estimate too, without another counter.
	if profile.Cost.WALBytes, ok = product(controls+9+4*signs, wal); !ok {
		return app.ContextQueryQualification{}, mounts.ErrUnavailable
	}
	if profile.Cost.WALBytes, ok = product(profile.Cost.WALBytes, h.WALCopies); !ok {
		return app.ContextQueryQualification{}, mounts.ErrUnavailable
	}
	total, ok := product(p.Accounts, p.Records)
	if !ok {
		return app.ContextQueryQualification{}, mounts.ErrUnavailable
	}
	q := app.ContextQueryQualification{Format: app.ContextQueryQualificationFormat, CapacityID: newID(), Profile: profile, History: h, RootQueries: total, PrincipalQueries: p.Records, PrincipalAccounts: total, WorkloadAccounts: p.Accounts, WorkloadQueries: p.Records, Admission: time.Duration(p.AdmissionSeconds) * time.Second}
	var err error
	q.Envelope, err = q.Required()
	return q, err
}
