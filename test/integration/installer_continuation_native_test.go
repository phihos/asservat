package integration

import (
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
)

// nativeCapacityProfile is the operator's synthetic capacity profile; its
// footprints and sizes mirror the capacity SQL fixture (ADR-190). Processing
// coverage (ADR-146) requires a capture's deletion date (retention plus the
// deletion budget, about 4200 s here) before the processing root's current
// end, which root renewal sets AdmissionSeconds ahead, so the profile uses the
// one-day maximum (local hold 12). Each renewal also spends one lifetime
// processing root transition and one configuration transition; 8 and 100 with
// 60 s renewals expired the root nine minutes after install (local hold 10).
// Every MCP call, including status polls, charges one normal-lane record to the
// same Keycloak MCP principal until its 10000 s retention; the second workload
// cluster's short journey runs as that principal after the full journey, so
// the normal lane holds 128 records rather than 64.
func nativeCapacityProfile() *contracts.InstallerCapacitySettings {
	f := func(row, wal int64) contracts.InstallerCapacityFootprint {
		return contracts.InstallerCapacityFootprint{RowBytes: row, TransitionWALBytes: wal}
	}
	lane := func(accounts, records int64) contracts.InstallerCapacityLane {
		return contracts.InstallerCapacityLane{Accounts: accounts, Records: records, RetainedSeconds: 10000}
	}
	// Several focuses on one installation each get their own funding: the
	// per-focus records and normal-lane records add up (installedEachFocus).
	var records, normal int64
	installedEachFocus(func() {
		r, n := installedFocusCapacityRecords()
		records, normal = records+r, normal+n
	})
	poolSpec, policySpec := installerDeclaredCapacitySpecs()
	profile := &contracts.InstallerCapacitySettings{Pool: "capacity", Policy: "applications", PoolSpec: poolSpec, PolicySpec: policySpec, NamespaceKeys: []string{"team"}, Accounts: 16, Records: records, AdmissionSeconds: 86400,
		Lanes:               contracts.InstallerCapacityLanes{CaptureRetainedSeconds: 10000, Normal: lane(4, normal*installedKeptRuns()), Resolution: lane(4, 8*installedFundedRuns()), Processing: lane(2, 16)},
		StopRetainedSeconds: 10000,
		Backup:              contracts.InstallerCapacityBackup{HorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 2, WALCopies: 3},
		Footprints:          contracts.InstallerCapacityFootprints{Capture: f(128<<10, 256<<10), Operation: f(128<<10, 256<<10), Processing: f(128<<10, 256<<10), Native: f(64<<10, 128<<10), Stop: f(128<<10, 256<<10), ProcessingState: f(16<<10, 64<<10)},
		PurgeLeases:         4,
		Processing:          contracts.InstallerCapacityProcessing{MaxRules: 2, MaxRootTransitions: 512},
		Metadata:            contracts.InstallerCapacityMetadata{FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, ConfigurationTransitions: 4096},
		Envelope:            contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1 << 50}, SQLBytes: 1 << 50, BackupBytes: 1 << 50, WALBytes: 1 << 50, KeyAttempts: 1 << 50},
		Backends:            []contracts.InstallerCapacityBackend{{StorageProfile: "dedicated", Usable: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
	if installedJourneyFocus() == "share-retirement" {
		// Selected before installation/admission: exercise original finite
		// bounds, never rewrite a running operation to make cleanup due.
		profile.Backup.HorizonSeconds = 2
		// The ten-second cohort did not qualify healthy native retirement.
		// Select thirty seconds before installation for serial native checks
		// and cold provider work; retention and proof requirements stay fixed.
		// This moves original purge 60s earlier and live removal 20s earlier.
		profile.Backup.CleanupBudgetSeconds, profile.Backup.ProofWindowSeconds = 30, 10
		profile.Lanes.Normal.RetainedSeconds = 240
		profile.Lanes.Resolution.RetainedSeconds = 240
		profile.Lanes.CaptureRetainedSeconds = 300
	}
	return profile
}

// installedFocusCapacityRecords is the current focus' records per account
// and normal-lane records (before the keep run's multiplier).
func installedFocusCapacityRecords() (records, normal int64) {
	// The manual profile journey reserves 48 evidence objects for four captures
	// plus history, deriving 12 protocol records. Qualify those records upfront;
	// its single pprof summary still charges ten conservative read-work units.
	records = int64(8)
	if installedLogsFocus() {
		records = installedLogsQueryUnits * installedKeptRuns() // one focus run; a keep run funds its reruns
	}
	if installedJourneyFocus() == "manual-raw" {
		// Two summaries (4 units) plus two independently paid packet queries
		// (8 units) fit an originally accepted sixteen-record backing.
		records = 16
	}
	if installedJourneyFocus() == "manual-profile" {
		records = 12
	}
	if installedJourneyFocus() == "profile-comparison" {
		records = installedProfileComparisonQueries * query.ProfileComparisonQueryUnits
	}
	// The saved-syscall journey performs five distinct paid queries, including
	// the changed-filter cursor refusal. Retiring a worker never refunds a
	// query unit. Arguments additionally funds two four-unit raw queries; the
	// metadata-only focus retains five two-unit source reads.
	if installedJourneyFocus() == "manual-syscall" || installedJourneyFocus() == "manual-arguments" {
		records = installedSyscallProjectionQueries * query.SyscallProjectionQueryUnits
		if installedJourneyFocus() == "manual-arguments" {
			records = installedArgumentQueryUnits
		}
	}
	// Every live list/open/read/update/close is one audited normal-lane
	// operation for the same human; six episodes poll roughly once a second.
	normal = 128
	if installedJourneyFocus() == "live-observation" {
		normal = 512
	}
	return records, normal
}
