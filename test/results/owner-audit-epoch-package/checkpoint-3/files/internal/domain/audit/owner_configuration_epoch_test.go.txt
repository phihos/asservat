package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
)

func ownerEpochAuditFacts(t *testing.T) OwnerConfigurationEpoch {
	t.Helper()
	c, _, _ := ownerReceiptVersionFacts(t)
	const id = "11111111-1111-4111-8111-111111111111"
	anchor := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	p := fleet.OwnerAuditEpochPolicy{EpochInterval: 5 * time.Minute, AdmissionWindow: 10 * time.Minute, MaxDependencyLifetime: 30 * time.Minute, RetainAfterDependencies: time.Hour, DeleteBudget: time.Hour, MetadataAfterDeletion: time.Hour, ResidualAfterMetadata: time.Hour, MaxOpenEpochs: 64, MaxUncertainEpochs: 2, MaxDependenciesPerEpoch: 32, PerEpoch: fleet.OwnerAuditEpochBudget{CiphertextBytes: 1 << 20, DataVersions: 4, DeleteMarkers: 4, MultipartUploads: 2, MultipartParts: 4, MetadataBytes: 1 << 16}}
	reserve := fleet.OwnerControlAuditReserveReference{ID: id, InstallationRootID: id, InstallationID: id, ClusterID: id, SourceUID: id, StoreID: id, CapacityID: id, PoolID: id, AllocationID: id, QualificationID: id, RootDigest: artifact.Digest{1}, QualificationDigest: artifact.Digest{2}, PolicyDigest: artifact.Digest{3}, ProvisionedAt: anchor.Add(-time.Minute), Policy: p}
	dates, ok := fleet.OwnerAuditEpochDates(anchor, p)
	r := OwnerConfigurationEpoch{Format: OwnerConfigurationEpochFormat, Epoch: fleet.OwnerAuditEpoch{ID: "22222222-2222-4222-8222-222222222222", AttemptID: "33333333-3333-4333-8333-333333333333", Ordinal: 1, Reserve: reserve, Configuration: c, ClaimedAt: anchor, Deadlines: dates}}
	if !ok || !r.Valid() {
		t.Fatal("invalid synthetic epoch record")
	}
	return r
}

func TestOwnerConfigurationEpochReceiptIsSeparateFromV1(t *testing.T) {
	r := ownerEpochAuditFacts(t)
	const id = "11111111-1111-4111-8111-111111111111"
	oldKey := "hub-owner-configuration/v1/" + id + "/" + id + "/" + id + "/1"
	if OwnerConfigurationAuditKey(r.Epoch.Configuration) != oldKey {
		t.Fatal("v1 key changed")
	}
	key := "hub-owner-configuration-epoch/v1/" + id + "/" + id + "/" + id + "/" + id + "/1/22222222-2222-4222-8222-222222222222"
	if OwnerConfigurationEpochKey(r) != key || strings.Contains(key, "33333333") {
		t.Fatal("closed epoch key changed")
	}
	receipt := Receipt{Key: oldKey, Version: "original-version", ETag: "original", Bytes: 17, SHA256: artifact.Digest{9}}
	// Exact legacy receipt bytes are checked directly against the unchanged v1
	// type. This fixture is synthetic and is not an acknowledged production row.
	expected := `{"Key":"` + oldKey + `","Version":"original-version","ETag":"original","Bytes":17,"SHA256":[9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	raw, err := json.Marshal(receipt)
	if err != nil || string(raw) != expected || !receipt.ValidOwnerConfiguration(r.Epoch.Configuration) || receipt.ValidOwnerConfigurationEpoch(r) {
		t.Fatal("v1 bytes or separation changed", err)
	}
	originalConfig, err := json.Marshal(r.Epoch.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Key = key
	if !receipt.ValidOwnerConfigurationEpoch(r) || receipt.ValidOwnerConfiguration(r.Epoch.Configuration) {
		t.Fatal("new/legacy receipt formats confused")
	}
	copied := r.Clone()
	copied.Epoch.Configuration.IssuerRoots[0][0]++
	again, err := json.Marshal(r.Epoch.Configuration)
	if err != nil || !bytes.Equal(originalConfig, again) || copied.Equal(r) {
		t.Fatal("epoch copy mutated v1 configuration", err)
	}
	// A new format inside the old record cannot select it. No decoder or runtime
	// branch exists for this proposed format.
	copied = r.Clone()
	copied.Format = "asservat-hub-owner-configuration-audit/v1"
	if copied.Valid() || OwnerConfigurationEpochKey(copied) != "" || receipt.ValidOwnerConfigurationEpoch(copied) {
		t.Fatal("mixed format accepted")
	}
}

func TestOwnerConfigurationEpochRejectsInvalidReceiptAndScope(t *testing.T) {
	record := ownerEpochAuditFacts(t)
	good := Receipt{Key: OwnerConfigurationEpochKey(record), Version: "original-version", ETag: "original", Bytes: 17, SHA256: artifact.Digest{1}}
	for name, change := range map[string]func(*Receipt){
		"missing-version": func(r *Receipt) { r.Version = "" }, "null-version": func(r *Receipt) { r.Version = "null" }, "oversized-version": func(r *Receipt) { r.Version = strings.Repeat("x", 1025) }, "invalid-etag": func(r *Receipt) { r.ETag = "\x00" }, "empty-body": func(r *Receipt) { r.Bytes = 0 }, "oversized-body": func(r *Receipt) { r.Bytes = 128<<10 + 1 }, "empty-digest": func(r *Receipt) { r.SHA256 = artifact.Digest{} }, "foreign-key": func(r *Receipt) { r.Key += "/foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			r := good
			change(&r)
			if r.ValidOwnerConfigurationEpoch(record) {
				t.Fatal("invalid current receipt accepted")
			}
		})
	}
	for name, change := range map[string]func(*OwnerConfigurationEpoch){
		"epoch": func(r *OwnerConfigurationEpoch) { r.Epoch.ID = "44444444-4444-4444-8444-444444444444" }, "ordinal": func(r *OwnerConfigurationEpoch) { r.Epoch.Ordinal++ }, "reserve": func(r *OwnerConfigurationEpoch) { r.Epoch.Reserve.ID = "44444444-4444-4444-8444-444444444444" }, "missing-format": func(r *OwnerConfigurationEpoch) { r.Format = "" }, "out-of-original-budget": func(r *OwnerConfigurationEpoch) { r.Epoch.Reserve.Policy.PerEpoch.CiphertextBytes = 16 },
	} {
		t.Run(name, func(t *testing.T) {
			r := record.Clone()
			change(&r)
			if good.ValidOwnerConfigurationEpoch(r) {
				t.Fatal("foreign/malformed scope accepted")
			}
		})
	}
}
