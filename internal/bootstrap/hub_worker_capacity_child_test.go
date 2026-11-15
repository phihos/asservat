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

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
)

func hubWorkerCapacityIDs() contracts.InstallationIDs {
	return contracts.InstallationIDs{InstallationID: "30000000-0000-4000-8000-000000000001", ClusterID: "30000000-0000-4000-8000-000000000002",
		IssuerEpoch: "30000000-0000-4000-8000-000000000003", PermissionRootID: "30000000-0000-4000-8000-000000000004", BrowserRootID: "30000000-0000-4000-8000-000000000005",
		SessionEpoch: "30000000-0000-4000-8000-000000000006", RoleSetupID: "30000000-0000-4000-8000-000000000007", PeerID: "30000000-0000-4000-8000-000000000008"}
}

func hubWorkerCapacityFixture() *contracts.HubWorkerCapacity {
	return &contracts.HubWorkerCapacity{CapacityValues: contracts.CapacityValues{EvidenceStorage: "128Gi", Workload: contracts.CapacityWorkloadValues{Share: "16Gi", Limit: "32Gi"}}, Revision: 1, ProcessingSource: "asservat-processing"}
}

func TestHubWorkerCapacitySectionValidation(t *testing.T) {
	ids := hubWorkerCapacityIDs()
	if err := validateHubWorkerCapacity(hubWorkerCapacityFixture(), ids, "asservat"); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*contracts.HubWorkerCapacity){
		"processing": func(c *contracts.HubWorkerCapacity) { c.ProcessingSource = "" },
		"revision":   func(c *contracts.HubWorkerCapacity) { c.Revision = 0 },
		"storage":    func(c *contracts.HubWorkerCapacity) { c.EvidenceStorage = "" },
		"share":      func(c *contracts.HubWorkerCapacity) { c.Workload.Share = "200Gi" },
		"percent":    func(c *contracts.HubWorkerCapacity) { c.Workload.Limit = "101%" },
		"path":       func(c *contracts.HubWorkerCapacity) { c.Paths = []contracts.DownloadEnvironmentPath{{ID: "x"}} },
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

// The section is the Helm `capacity` values plus the derived names.
func TestHubWorkerCapacitySectionDecodes(t *testing.T) {
	raw, err := json.Marshal(hubWorkerCapacityFixture())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"evidenceStorage":"128Gi"`)) || !bytes.Contains(raw, []byte(`"processingSource":"asservat-processing"`)) {
		t.Fatalf("settings are not inline: %s", raw)
	}
	doc := `{"format":"` + contracts.HubWorkerConfigFormat + `","capacity":` + string(raw) + `}`
	c, err := contracts.DecodeHubWorkerConfig(strings.NewReader(doc))
	if err != nil || c.Capacity == nil || !reflect.DeepEqual(*c.Capacity, *hubWorkerCapacityFixture()) {
		t.Fatal("capacity section did not round-trip", err)
	}
}

// The values become the SQL settings: reserve 1/16, default limit 10 %.
func TestCapacityValuesBytes(t *testing.T) {
	v, err := capacityValues(contracts.CapacityValues{EvidenceStorage: "128Gi", NamespaceLimit: "25%", Workload: contracts.CapacityWorkloadValues{Share: "16Gi"}})
	if err != nil || v.EvidenceBytes != 128<<30 || v.ReserveBytes != 8<<30 || v.ShareBytes != 16<<30 || v.LimitBytes != 16<<30 || v.NamespaceLimitBytes != 32<<30 || v.MaxConcurrentExpensive != 1 || v.OnFull != "RejectNewExpensive" {
		t.Fatal(v, err)
	}
}

func TestCapacityValuesRefuseShareAboveLimit(t *testing.T) {
	if _, err := capacityValues(contracts.CapacityValues{EvidenceStorage: "128Gi", Workload: contracts.CapacityWorkloadValues{Share: "16Gi", Limit: "8Gi"}}); err == nil {
		t.Fatal("share above limit accepted")
	}
}

var capacityTestInitialized = time.Date(2026, 11, 14, 10, 0, 0, 123456789, time.UTC)

// Every restart builds the same qualification from the same IDs; the
// capacity values do not change it.
func TestHubWorkerQualificationIsDeterministic(t *testing.T) {
	ids := hubWorkerCapacityIDs()
	a, err := buildHubWorkerQualification(hubWorkerCapacityFixture(), ids, "asservat", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
	if err != nil {
		t.Fatal(err)
	}
	c := hubWorkerCapacityFixture()
	c.EvidenceStorage = "1Ti"
	b, _ := buildHubWorkerQualification(c, ids, "asservat", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
	again, _ := buildHubWorkerQualification(hubWorkerCapacityFixture(), ids, "asservat", "30000000-0000-4000-8000-0000000000a2", capacityTestInitialized)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(again)
	if !bytes.Equal(x, y) || b.Digest != a.Digest {
		t.Fatal("qualification is not deterministic")
	}
	r := a.RootBacking
	if r.RootID != ids.PermissionRootID || r.InstallationID != ids.InstallationID || r.AccountVersion != ids.RoleSetupID+"-account/v1" ||
		r.ProcessingProtectionDigest != contracts.ConfigMapSourceDigest(ids.ClusterID, "asservat", "asservat-processing") || r.ProcessingSourceUID != "30000000-0000-4000-8000-0000000000a2" ||
		a.Backends[0].PoolUID != r.SystemPoolUID || !app.ValidateRootBackingInput(r) {
		t.Fatal("derived values not bound", r)
	}
	if !r.Capture.Policy.ValidUntil.Equal(capacityTestInitialized.Truncate(time.Microsecond)) {
		t.Fatal("restart cannot rebuild from the stored initialization time")
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
