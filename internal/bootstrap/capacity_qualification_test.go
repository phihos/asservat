package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

func capacityProfileFixture() contracts.InstallerCapacitySettings {
	f := func(row, wal int64) contracts.InstallerCapacityFootprint {
		return contracts.InstallerCapacityFootprint{RowBytes: row, TransitionWALBytes: wal}
	}
	lane := func(accounts, records int64) contracts.InstallerCapacityLane {
		return contracts.InstallerCapacityLane{Accounts: accounts, Records: records, RetainedSeconds: 10000}
	}
	return contracts.InstallerCapacitySettings{Accounts: 16, Records: 3, AdmissionSeconds: 60,
		Lanes:       contracts.InstallerCapacityLanes{CaptureRetainedSeconds: 10000, Normal: lane(4, 7), Resolution: lane(4, 2)},
		Backup:      contracts.InstallerCapacityBackup{HorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 2, WALCopies: 3},
		Footprints:  contracts.InstallerCapacityFootprints{Capture: f(128<<10, 256<<10), Operation: f(128<<10, 256<<10), Native: f(64<<10, 128<<10), ProcessingState: f(16<<10, 64<<10)},
		PurgeLeases: 4,
		Processing:  contracts.InstallerCapacityProcessing{MaxRules: 2, MaxRootTransitions: 8},
		Metadata:    contracts.InstallerCapacityMetadata{FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, ConfigurationTransitions: 100},
		Envelope:    contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1 << 50}, SQLBytes: 1 << 50, BackupBytes: 1 << 50, WALBytes: 1 << 50, KeyAttempts: 1 << 50},
		Backends:    []contracts.InstallerCapacityBackend{{StorageProfile: "dedicated", Usable: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
}

func capacityDerivedFixture() capacityDerived {
	return capacityDerived{Root: "10000000-0000-4000-8000-000000000001", Installation: "10000000-0000-4000-8000-000000000002", AccountVersion: "setup-account/v1",
		SystemPoolUID: "10000000-0000-4000-8000-000000000003", ProcessingSourceUID: "10000000-0000-4000-8000-000000000004", ProcessingProtection: artifact.Digest{1},
		NamespaceGuards: []app.CapacityNamespaceQualification{{ClusterID: "10000000-0000-4000-8000-000000000005", Digest: artifact.Digest{2}, Keys: []string{"team"}}},
		Now:             time.Now()}
}

func sequentialIDs() func() string {
	n := 100
	return func() string { n++; return fmt.Sprintf("20000000-0000-4000-8000-%012d", n) }
}

// ADR-190: the operator profile plus minted and derived values yields a
// qualification the setup validators accept, with the shared store and a
// closed capture root.
func TestCapacityQualificationFromProfile(t *testing.T) {
	d := capacityDerivedFixture()
	q, err := buildCapacityQualification(capacityProfileFixture(), d, sequentialIDs())
	if err != nil {
		t.Fatal(err)
	}
	in := q.RootBacking
	if q.Backends[0].AuditStoreID != in.Capture.Policy.StoreID || in.Normal.Policy.StoreID != in.Capture.Policy.StoreID ||
		q.Backends[0].PoolUID != d.SystemPoolUID || in.Capture.Policy.MetadataSlots != 48 || !in.Capture.Policy.ValidUntil.Equal(d.Now.UTC().Truncate(time.Microsecond)) ||
		*in.Capture.Policy.History != in.ContextHistory.Capture || in.RootID != d.Root {
		t.Fatal("qualification lost a cross-field invariant", q)
	}
	again, _ := buildCapacityQualification(capacityProfileFixture(), d, sequentialIDs())
	if again.Digest != q.Digest || again.Backends[0].Digest != q.Backends[0].Digest {
		t.Fatal("evidence digests depend on more than the profile")
	}
	for name, change := range map[string]func(*contracts.InstallerCapacitySettings){
		"two backends":    func(p *contracts.InstallerCapacitySettings) { p.Backends = append(p.Backends, p.Backends[0]) },
		"small footprint": func(p *contracts.InstallerCapacitySettings) { p.Footprints.Capture.RowBytes = 1 },
		"no admission":    func(p *contracts.InstallerCapacitySettings) { p.AdmissionSeconds = 0 },
	} {
		p := capacityProfileFixture()
		change(&p)
		if _, err := buildCapacityQualification(p, d, sequentialIDs()); err == nil {
			t.Fatal("accepted an invalid profile:", name)
		}
	}
}

// ADR-192: a replay rebuilds the identical qualification from the same role
// setup, so the committed setup claim's input digest still matches.
func TestCapacityQualificationReplayIsIdentical(t *testing.T) {
	d := capacityDerivedFixture()
	setup := "30000000-0000-4000-8000-000000000001"
	q, err := buildCapacityQualification(capacityProfileFixture(), d, capacityIDs(setup))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(q)
	again, _ := buildCapacityQualification(capacityProfileFixture(), d, capacityIDs(setup))
	b, _ := json.Marshal(again)
	if !bytes.Equal(a, b) {
		t.Fatal("replay built a different qualification")
	}
	other, _ := buildCapacityQualification(capacityProfileFixture(), d, capacityIDs("30000000-0000-4000-8000-000000000002"))
	if other.ID == q.ID || other.Backends[0].EvidenceStoreID == q.Backends[0].EvidenceStoreID {
		t.Fatal("another setup reused the identities")
	}
}

// The installed journey's profile (test/integration nativeCapacityProfile):
// one-day admission, room for about 150 root renewals and enough normal-lane
// records for repeated hold previews must still compile.
func TestCapacityQualificationJourneySizing(t *testing.T) {
	p := capacityProfileFixture()
	p.AdmissionSeconds = 86400
	p.Lanes.Normal.Records = 64
	p.Processing.MaxRootTransitions = 512
	p.Metadata.ConfigurationTransitions = 4096
	if _, err := buildCapacityQualification(p, capacityDerivedFixture(), sequentialIDs()); err != nil {
		t.Fatal("journey capacity profile does not compile", err)
	}
}

func TestInstalledSharedQueryCapacityUsesOriginalEnvelopeAndExactWorkloadBudgets(t *testing.T) {
	d := capacityDerivedFixture()
	d.SharedQueries = true
	q, err := buildCapacityQualification(capacityProfileFixture(), d, sequentialIDs())
	if err != nil {
		t.Fatal(err)
	}
	x := q.ContextQuery
	if x == nil || !x.Profile.SharedBudgetValid() || x.Profile.Lifetime != time.Minute || x.RootQueries != q.RootBacking.Accounts*q.RootBacking.RecordsPerAccount || x.WorkloadAccounts != q.RootBacking.Accounts || x.WorkloadQueries != q.RootBacking.RecordsPerAccount {
		t.Fatal("shared installed query budget missing or root selected target")
	}
	if x.Profile.Worker.CPUMilli != downloadWorkerCPUMillis || x.Profile.Worker.MemoryBytes != downloadWorkerMemoryBytes || x.Profile.Worker.EphemeralStorageBytes != 4<<20 || x.Profile.Cost.AuditObjects != 14 {
		t.Fatal("worker or independent audit budget mismatch")
	}
	need, err := x.Required()
	if err != nil || need != x.Envelope {
		t.Fatal("logical charge not exactly derived", err)
	}
	body, _ := json.Marshal(x)
	for _, field := range []string{"Native", "SourceTransitionLimit", "ReportDigest"} {
		if bytes.Contains(body, []byte(field)) {
			t.Fatal("invented deployment/source engine", field)
		}
	}
}

// Match the installed journey's explicit 16-account/eight-record profile. The
// fixture has no implicit production default; prove a finite exact envelope can
// fund the complete graph and that a one-byte WAL shortfall is refused.
func TestProfileCapacityQualificationFundsRenewalsWithinFiniteEnvelope(t *testing.T) {
	p := capacityProfileFixture()
	p.Records = 8
	p.AdmissionSeconds = 86400
	p.Lanes.Normal.Records = 128
	p.Lanes.Resolution.Records = 8
	p.Processing.MaxRootTransitions = 512
	p.Metadata.ConfigurationTransitions = 4096
	d := capacityDerivedFixture()
	q, err := buildCapacityQualification(p, d, sequentialIDs())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := app.CompileRootBacking(q.RootBacking)
	if err != nil {
		t.Fatal(err)
	}
	totals := plan.Totals()
	u := (artifact.Registration{NativeLimit: artifact.MaxContextBytes}).ReservedBytes()
	work, err := app.CompileContextProtocolBacking(app.BudgetAmount{Bytes: p.Records * u, Objects: p.Records * 4}, q.RootBacking.ContextHistory)
	if err != nil {
		t.Fatal(err)
	}
	if work.NativeWALBytes != 909<<20 || work.NativeBackupBytes != 10<<20 || work.NativeTransitionsPerRow != 267 {
		t.Fatalf("unexpected installed native budget: %+v", work)
	}
	p.Envelope = contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: totals.SystemObjects.Bytes, Objects: totals.SystemObjects.Objects}, SQLBytes: totals.SQLBytes, BackupBytes: totals.BackupBytes, WALBytes: totals.WALBytes, KeyAttempts: totals.KeyAttempts}
	if _, err := buildCapacityQualification(p, d, sequentialIDs()); err != nil {
		t.Fatal("exact finite envelope refused", err)
	}
	p.Envelope.WALBytes--
	if _, err := buildCapacityQualification(p, d, sequentialIDs()); err == nil {
		t.Fatal("underfunded renewal graph accepted")
	}
	t.Logf("installed complete root: accounts=%d records/account=%d SQL=%d backup=%d WAL=%d nativeWAL/workload=%d nativeBackup/workload=%d", p.Accounts, p.Records, totals.SQLBytes, totals.BackupBytes, totals.WALBytes, work.NativeWALBytes, work.NativeBackupBytes)
}
