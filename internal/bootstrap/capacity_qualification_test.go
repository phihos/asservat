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
	return contracts.InstallerCapacitySettings{Pool: "capacity", Policy: "applications", NamespaceKeys: []string{"team"}, Accounts: 16, Records: 3, AdmissionSeconds: 60,
		Lanes:               contracts.InstallerCapacityLanes{CaptureRetainedSeconds: 10000, Normal: lane(4, 7), Resolution: lane(4, 2), Processing: lane(2, 16)},
		StopRetainedSeconds: 10000,
		Backup:              contracts.InstallerCapacityBackup{HorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 2, WALCopies: 3},
		Footprints:          contracts.InstallerCapacityFootprints{Capture: f(128<<10, 256<<10), Operation: f(128<<10, 256<<10), Processing: f(128<<10, 256<<10), Native: f(64<<10, 128<<10), Stop: f(128<<10, 256<<10), ProcessingState: f(16<<10, 64<<10)},
		PurgeLeases:         4,
		Processing:          contracts.InstallerCapacityProcessing{MaxRules: 2, MaxRootTransitions: 8},
		Metadata:            contracts.InstallerCapacityMetadata{FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, ConfigurationTransitions: 100},
		Envelope:            contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1 << 50}, SQLBytes: 1 << 50, BackupBytes: 1 << 50, WALBytes: 1 << 50, KeyAttempts: 1 << 50},
		Backends:            []contracts.InstallerCapacityBackend{{StorageProfile: "dedicated", Usable: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
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
	if q.Backends[0].AuditStoreID != in.Capture.Policy.StoreID || in.Normal.Policy.StoreID != in.Capture.Policy.StoreID || in.ContextHistory.Stop.StoreID != in.Capture.Policy.StoreID ||
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

// ADR-193: the connector backing derives from the role setup and satisfies
// the prepaid-retirement validator; a replay is identical and oversized
// profiles are refused.
func TestConnectorBackingDerivation(t *testing.T) {
	c := contracts.InstallerConnectorSettings{Accounts: 4, RecordsPerAccount: 256, RetainedSeconds: 15000, Profiles: 4, SourceTransitions: 64, PurgeLeases: 2, ValidSeconds: 7200,
		Footprint: contracts.InstallerCapacityFootprint{RowBytes: 1 << 20, TransitionWALBytes: 1 << 20}}
	backup := capacityProfileFixture().Backup
	root, installation, setup := "30000000-0000-4000-8000-000000000003", "30000000-0000-4000-8000-000000000004", "30000000-0000-4000-8000-000000000001"
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	b, err := buildConnectorBacking(c, backup, root, installation, "setup-account/v1", setup, now)
	if err != nil || !b.Valid() || b.Policy.RootID != root || !b.Policy.ValidUntil.Equal(now.Add(2*time.Hour)) {
		t.Fatal("connector backing", err)
	}
	again, _ := buildConnectorBacking(c, backup, root, installation, "setup-account/v1", setup, now)
	x, _ := json.Marshal(b)
	y, _ := json.Marshal(again)
	if !bytes.Equal(x, y) {
		t.Fatal("replay built a different backing")
	}
	for i, mutate := range []func(*contracts.InstallerConnectorSettings){
		func(c *contracts.InstallerConnectorSettings) { c.Profiles = 257 },
		func(c *contracts.InstallerConnectorSettings) { c.SourceTransitions = 4097 },
		func(c *contracts.InstallerConnectorSettings) { c.ValidSeconds = 60 },
		func(c *contracts.InstallerConnectorSettings) { c.Footprint.RowBytes = 1 << 10 },
		// Continuation run 52: a 3600-second retention with a 3600-second
		// backup horizon leaves no process run time for the regional shape.
		func(c *contracts.InstallerConnectorSettings) { c.RetainedSeconds = 3600 },
	} {
		bad := c
		mutate(&bad)
		if _, err := buildConnectorBacking(bad, backup, root, installation, "setup-account/v1", setup, now); err == nil {
			t.Fatalf("oversized or invalid connector profile %d accepted", i)
		}
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
