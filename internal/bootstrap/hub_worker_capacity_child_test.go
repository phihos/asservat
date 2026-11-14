package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
)

func hubWorkerCapacityIDs() contracts.InstallationIDs {
	return contracts.InstallationIDs{InstallationID: "30000000-0000-4000-8000-000000000001", ClusterID: "30000000-0000-4000-8000-000000000002",
		IssuerEpoch: "30000000-0000-4000-8000-000000000003", PermissionRootID: "30000000-0000-4000-8000-000000000004", BrowserRootID: "30000000-0000-4000-8000-000000000005",
		SessionEpoch: "30000000-0000-4000-8000-000000000006", RoleSetupID: "30000000-0000-4000-8000-000000000007", PeerID: "30000000-0000-4000-8000-000000000008"}
}

func hubWorkerCapacityFixture() *contracts.HubWorkerCapacity {
	return &contracts.HubWorkerCapacity{InstallerCapacitySettings: capacityProfileFixture(), ProcessingSource: "asservat-processing"}
}

func TestHubWorkerCapacitySectionValidation(t *testing.T) {
	ids := hubWorkerCapacityIDs()
	if err := validateHubWorkerCapacity(hubWorkerCapacityFixture(), ids, "asservat"); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*contracts.HubWorkerCapacity){
		"pool":       func(c *contracts.HubWorkerCapacity) { c.Pool = "Bad_Name" },
		"policy":     func(c *contracts.HubWorkerCapacity) { c.Policy = "" },
		"processing": func(c *contracts.HubWorkerCapacity) { c.ProcessingSource = "" },
		"keys":       func(c *contracts.HubWorkerCapacity) { c.NamespaceKeys = nil },
		"backends": func(c *contracts.HubWorkerCapacity) {
			c.Backends = append(c.Backends, c.Backends[0])
		},
		"accounts": func(c *contracts.HubWorkerCapacity) { c.Accounts = 0 },
		"path":     func(c *contracts.HubWorkerCapacity) { c.Paths = []contracts.DownloadEnvironmentPath{{ID: "x"}} },
	} {
		c := hubWorkerCapacityFixture()
		edit(c)
		if !errors.Is(validateHubWorkerCapacity(c, ids, "asservat"), errHubWorkerCapacityConfig) {
			t.Error(name, "accepted")
		}
	}
	if validateHubWorkerCapacity(nil, ids, "asservat") == nil {
		t.Fatal("nil section accepted")
	}
}

// The section is the Helm `capacity` values plus the processing source name:
// a rendered document decodes with no unknown field.
func TestHubWorkerCapacitySectionDecodes(t *testing.T) {
	raw, err := json.Marshal(hubWorkerCapacityFixture())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"pool":"capacity"`)) || !bytes.Contains(raw, []byte(`"processingSource":"asservat-processing"`)) {
		t.Fatalf("settings are not inline: %s", raw)
	}
	doc := `{"format":"` + contracts.HubWorkerConfigFormat + `","capacity":` + string(raw) + `}`
	c, err := contracts.DecodeHubWorkerConfig(strings.NewReader(doc))
	if err != nil || c.Capacity == nil || !reflect.DeepEqual(*c.Capacity, *hubWorkerCapacityFixture()) {
		t.Fatal("capacity section did not round-trip", err)
	}
}

var capacityTestInitialized = time.Date(2026, 11, 14, 10, 0, 0, 123456789, time.UTC)

// Every retry and restart builds the same qualification from the same
// settings and IDs; CR specs and key order do not change it.
func TestHubWorkerQualificationIsDeterministic(t *testing.T) {
	ids := hubWorkerCapacityIDs()
	a, err := buildHubWorkerQualification(hubWorkerCapacityFixture(), ids, "asservat", "30000000-0000-4000-8000-0000000000a1", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
	if err != nil {
		t.Fatal(err)
	}
	c := hubWorkerCapacityFixture()
	c.NamespaceKeys = []string{"z", "team"}
	b, _ := buildHubWorkerQualification(c, ids, "asservat", "30000000-0000-4000-8000-0000000000a1", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
	c.NamespaceKeys = []string{"team", "z"}
	d, _ := buildHubWorkerQualification(c, ids, "asservat", "30000000-0000-4000-8000-0000000000a1", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
	again, _ := buildHubWorkerQualification(hubWorkerCapacityFixture(), ids, "asservat", "30000000-0000-4000-8000-0000000000a1", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(again)
	if !bytes.Equal(x, y) || !reflect.DeepEqual(b, d) {
		t.Fatal("qualification is not deterministic")
	}
	r := a.RootBacking
	if r.RootID != ids.PermissionRootID || r.InstallationID != ids.InstallationID || r.AccountVersion != ids.RoleSetupID+"-account/v1" ||
		r.ProcessingProtectionDigest != contracts.ConfigMapSourceDigest(ids.ClusterID, "asservat", "asservat-processing") ||
		a.NamespaceGuards[0].Digest != contracts.NamespaceSourceDigest(ids.ClusterID, "asservat") || a.NamespaceGuards[0].ClusterID != ids.ClusterID ||
		a.Backends[0].PoolUID != "30000000-0000-4000-8000-0000000000a1" || r.ProcessingSourceUID != "30000000-0000-4000-8000-0000000000a2" {
		t.Fatal("derived values not bound", r)
	}
	withSpec := hubWorkerCapacityFixture()
	withSpec.WorkloadKeys = &contracts.InstallerWorkloadKeys{Labels: []string{"a"}}
	z, _ := buildHubWorkerQualification(withSpec, ids, "asservat", "30000000-0000-4000-8000-0000000000a1", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
	if z.Digest != a.Digest {
		t.Fatal("workload keys changed the qualification")
	}
}

// fakeCapacityRoots models initialize_capacity_source: insert once, then
// report present for equal inputs and different otherwise.
type fakeCapacityRoots struct {
	pending int
	rows    map[string]postgres.CapacityInitialization
	inserts int
}

func (f *fakeCapacityRoots) InitializeCapacity(_ context.Context, in postgres.CapacityInitialization) (postgres.CapacityInitialized, error) {
	if f.pending > 0 {
		f.pending--
		return "", postgres.ErrCapacityPermissionPending
	}
	root := in.Qualification.RootBacking.RootID
	if old, ok := f.rows[root]; ok {
		if reflect.DeepEqual(old, in) {
			return postgres.CapacityPresent, nil
		}
		return postgres.CapacityDifferent, nil
	}
	f.rows[root] = in
	f.inserts++
	return postgres.CapacityCreated, nil
}

func TestCapacityInitializationIsIdempotent(t *testing.T) {
	ids := hubWorkerCapacityIDs()
	input := func() postgres.CapacityInitialization {
		q, err := buildHubWorkerQualification(hubWorkerCapacityFixture(), ids, "asservat", "30000000-0000-4000-8000-0000000000a1", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
		if err != nil {
			t.Fatal(err)
		}
		return postgres.CapacityInitialization{ClusterID: ids.ClusterID, NamespaceUID: "ns-uid", SourceDigest: contracts.NamespaceSourceDigest(ids.ClusterID, "asservat"), AccountVersion: capacityAccountVersion(ids), Qualification: q}
	}
	store := &fakeCapacityRoots{pending: 2, rows: map[string]postgres.CapacityInitialization{}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := initializeCapacityRoot(ctx, store, input(), time.Millisecond); err != nil || store.inserts != 1 {
		t.Fatal("first run", err, store.inserts)
	}
	// A restart builds the input again: nothing is inserted and it compares
	// equal to the stored row.
	second := input()
	if outcome, _ := store.InitializeCapacity(ctx, second); outcome != postgres.CapacityPresent {
		t.Fatal("second input differs", outcome)
	}
	if err := initializeCapacityRoot(ctx, store, second, time.Millisecond); err != nil || store.inserts != 1 {
		t.Fatal("second run inserted", err, store.inserts)
	}
	stopped, stop := context.WithCancel(t.Context())
	stop()
	if err := initializeCapacityRoot(stopped, &fakeCapacityRoots{pending: 1 << 30, rows: map[string]postgres.CapacityInitialization{}}, input(), time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatal("pending initialization did not stop with its context", err)
	}
}

func TestPlatformCapacityProtectionIsFresh(t *testing.T) {
	ids := hubWorkerCapacityIDs()
	p := platformCapacityProtection{clusterID: ids.ClusterID, namespaceUID: "ns-uid", digest: contracts.NamespaceSourceDigest(ids.ClusterID, "asservat"), keys: []string{"team"}}
	s, err := p.CapacityProtection(t.Context())
	if err != nil || !s.Valid(time.Now()) {
		t.Fatal("source protection", err, s)
	}
	n, err := p.CapacityNamespaceProtection(t.Context())
	if err != nil || !n.Valid(time.Now()) || n.Digest != p.digest {
		t.Fatal("namespace protection", err, n)
	}
}

// Context deletion waits for the evidence store ID that the capacity child
// publishes from its stored qualification; a later different ID is refused.
func TestHubWorkerPublishesEvidenceStoreIDForContextDeletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &hubWorker{root: ctx}
	if _, ok := w.EvidenceStoreID(); ok {
		t.Fatal("evidence store ID available before the capacity child read it")
	}
	const store = "30000000-0000-4000-8000-000000000007"
	if err := w.publishEvidenceStoreID(store); err != nil {
		t.Fatal(err)
	}
	if err := w.publishEvidenceStoreID(store); err != nil {
		t.Fatal("same ID refused on a capacity restart", err)
	}
	if err := w.publishEvidenceStoreID("30000000-0000-4000-8000-000000000008"); err == nil {
		t.Fatal("different evidence store ID replaced the published one")
	}
	if got, ok := w.EvidenceStoreID(); !ok || got != store {
		t.Fatal("published evidence store ID not returned", got)
	}
	cancel()
	if _, ok := w.EvidenceStoreID(); ok {
		t.Fatal("evidence store ID returned after the process ended")
	}
}

// The first initialization time is the qualification's setup time; a restart
// reads it back from the stored qualification and rebuilds the identical
// qualification, so SQL reports it present instead of different.
func TestHubWorkerQualificationRebuildsFromStoredInitializationTime(t *testing.T) {
	ids := hubWorkerCapacityIDs()
	first := time.Now()
	q, err := buildHubWorkerQualification(hubWorkerCapacityFixture(), ids, "asservat", "30000000-0000-4000-8000-0000000000a1", "30000000-0000-4000-8000-0000000000a2", first)
	if err != nil {
		t.Fatal(err)
	}
	if p := q.RootBacking.Capture.Policy; p.ValidUntil.Before(first.Add(-time.Microsecond)) || p.ValidUntil.After(first) || q.RootBacking.ProcessingState.RetireBy.Before(first) {
		t.Fatal("qualification not built at its first initialization time", p.ValidUntil, q.RootBacking.ProcessingState.RetireBy)
	}
	raw, _ := json.Marshal(q)
	var stored app.CapacityQualification
	if err = json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	again, err := buildHubWorkerQualification(hubWorkerCapacityFixture(), ids, "asservat", "30000000-0000-4000-8000-0000000000a1", "30000000-0000-4000-8000-0000000000a2", capacityInitializedAt(stored))
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt, _ := json.Marshal(again); !bytes.Equal(raw, rebuilt) {
		t.Fatal("restart did not rebuild the stored qualification")
	}
}
