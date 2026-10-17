package framed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func epochCodecRecord(t *testing.T) audit.OwnerConfigurationEpoch {
	t.Helper()
	const id = "11111111-1111-4111-8111-111111111111"
	anchor := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	policy := fleet.OwnerAuditEpochPolicy{EpochInterval: 5 * time.Minute, AdmissionWindow: 10 * time.Minute, MaxDependencyLifetime: 30 * time.Minute, RetainAfterDependencies: time.Hour, DeleteBudget: time.Hour, MetadataAfterDeletion: time.Hour, ResidualAfterMetadata: time.Hour, MaxOpenEpochs: 64, MaxUncertainEpochs: 2, MaxDependenciesPerEpoch: 32, PerEpoch: fleet.OwnerAuditEpochBudget{CiphertextBytes: 1 << 20, DataVersions: 4, DeleteMarkers: 4, MultipartUploads: 2, MultipartParts: 4, MetadataBytes: 1 << 16}}
	reserve := fleet.OwnerControlAuditReserveReference{ID: id, InstallationRootID: id, InstallationID: id, ClusterID: id, SourceUID: id, StoreID: id, CapacityID: id, PoolID: id, AllocationID: id, QualificationID: id, RootDigest: artifact.Digest{1}, QualificationDigest: artifact.Digest{2}, PolicyDigest: artifact.Digest{3}, ProvisionedAt: anchor.Add(-time.Minute), Policy: policy}
	configuration := fleet.OwnerConfiguration{Pool: fleet.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{[]byte("synthetic-public-root")}}
	dates, ok := fleet.OwnerAuditEpochDates(anchor, policy)
	record := audit.OwnerConfigurationEpoch{Format: audit.OwnerConfigurationEpochFormat, Epoch: fleet.OwnerAuditEpoch{ID: "22222222-2222-4222-8222-222222222222", AttemptID: "33333333-3333-4333-8333-333333333333", Ordinal: 1, Reserve: reserve, Configuration: configuration, ClaimedAt: anchor, Deadlines: dates}}
	if !ok || !record.Valid() {
		t.Fatal("invalid synthetic epoch")
	}
	return record
}

func TestOwnerEpochCodecExactSnapshotAndPurpose(t *testing.T) {
	r := epochCodecRecord(t)
	ctx := context.Background()
	k := &countingKeys{testKeys: keys(t)}
	encoded, err := SealOwnerConfigurationEpoch(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if k.wraps != 1 || k.unwraps != 0 || k.maxKeyBytes == 0 || k.maxKeyBytes > 4096 {
		t.Fatal("encryption must use one bounded wrap-only key operation")
	}
	for _, cleartext := range [][]byte{[]byte("IssuerRoots"), []byte(r.Epoch.AttemptID), r.Epoch.Configuration.IssuerRoots[0]} {
		if bytes.Contains(encoded, cleartext) {
			t.Fatal("clear snapshot in envelope")
		}
	}
	if err = VerifyOwnerConfigurationEpoch(ctx, k, r, encoded); err != nil || k.unwraps != 1 {
		t.Fatal("original epoch readback", err)
	}
	const other = "44444444-4444-4444-8444-444444444444"
	for name, change := range map[string]func(*audit.OwnerConfigurationEpoch){
		"epoch":   func(v *audit.OwnerConfigurationEpoch) { v.Epoch.ID = other },
		"attempt": func(v *audit.OwnerConfigurationEpoch) { v.Epoch.AttemptID = other },
		"ordinal": func(v *audit.OwnerConfigurationEpoch) { v.Epoch.Ordinal++ },
		"reserve": func(v *audit.OwnerConfigurationEpoch) { v.Epoch.Reserve.ID = other },
		"installation": func(v *audit.OwnerConfigurationEpoch) {
			v.Epoch.Reserve.InstallationID = other
			v.Epoch.Configuration.Pool.InstallationID = other
		},
		"source": func(v *audit.OwnerConfigurationEpoch) {
			v.Epoch.Reserve.SourceUID = other
			v.Epoch.Configuration.Revision.UID = other
		},
		"allocation":        func(v *audit.OwnerConfigurationEpoch) { v.Epoch.Reserve.AllocationID = other },
		"backing":           func(v *audit.OwnerConfigurationEpoch) { v.Epoch.Reserve.QualificationDigest[0]++ },
		"policy":            func(v *audit.OwnerConfigurationEpoch) { v.Epoch.Reserve.Policy.MaxDependenciesPerEpoch++ },
		"source-generation": func(v *audit.OwnerConfigurationEpoch) { v.Epoch.Configuration.Revision.Generation++ },
		"issuer-roots":      func(v *audit.OwnerConfigurationEpoch) { v.Epoch.Configuration.IssuerRoots[0][0]++ },
		"lifecycle": func(v *audit.OwnerConfigurationEpoch) {
			v.Epoch.ClaimedAt = v.Epoch.ClaimedAt.Add(time.Second)
			v.Epoch.Deadlines, _ = fleet.OwnerAuditEpochDates(v.Epoch.ClaimedAt, v.Epoch.Reserve.Policy)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := r.Clone()
			change(&changed)
			if !changed.Valid() {
				t.Fatal("negative must reach authenticated binding, not shape rejection")
			}
			if VerifyOwnerConfigurationEpoch(ctx, k, changed, encoded) == nil {
				t.Fatal("substituted original snapshot accepted")
			}
		})
	}
	legacy, err := SealOwnerConfiguration(ctx, k, r.Epoch.Configuration)
	if err != nil || VerifyOwnerConfiguration(ctx, k, r.Epoch.Configuration, legacy) != nil {
		t.Fatal("legacy format no longer works", err)
	}
	if VerifyOwnerConfigurationEpoch(ctx, k, r, legacy) == nil || VerifyOwnerConfiguration(ctx, k, r.Epoch.Configuration, encoded) == nil {
		t.Fatal("legacy and epoch ciphertext are interchangeable")
	}
	wrongPurpose, err := sealControlAudit(ctx, k, "asservat-hub-owner-configuration-audit/v1", r.Epoch.Reserve.InstallationID, audit.OwnerConfigurationEpochKey(r), r, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	wrongPurpose = bytes.ReplaceAll(wrongPurpose, []byte("asservat-hub-owner-configuration-audit/v1"), []byte(ownerConfigurationEpochAuditFormat))
	if VerifyOwnerConfigurationEpoch(ctx, k, r, wrongPurpose) == nil {
		t.Fatal("rewriting envelope format bypassed authenticated purpose")
	}
}

func TestOwnerEpochCodecRejectsMalformedBeforeKeyUse(t *testing.T) {
	r := epochCodecRecord(t)
	ctx := context.Background()
	k := &countingKeys{testKeys: keys(t)}
	encoded, err := SealOwnerConfigurationEpoch(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"empty":     nil,
		"oversized": bytes.Repeat([]byte("x"), (128<<10)+1),
		"truncated": encoded[:len(encoded)-1],
		"duplicate": append([]byte(`{"format":"duplicate",`), encoded[1:]...),
		"unknown":   append([]byte(`{"unexpected":true,`), encoded[1:]...),
		"trailing":  append(bytes.Clone(encoded), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			before := k.unwraps
			if VerifyOwnerConfigurationEpoch(ctx, k, r, raw) == nil || k.unwraps != before {
				t.Fatal("malformed envelope reached key provider or was accepted")
			}
		})
	}
	var envelope authorityEnvelope
	if err = json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[len(envelope.Ciphertext)/2] ^= 1
	tampered, _ := json.Marshal(envelope)
	if VerifyOwnerConfigurationEpoch(ctx, k, r, tampered) == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	invalid := r.Clone()
	invalid.Epoch.Reserve.Policy.PerEpoch.CiphertextBytes = 1
	if !invalid.Valid() {
		t.Fatal("expected arithmetically valid undersized storage budget")
	}
	if b, err := SealOwnerConfigurationEpoch(ctx, k, invalid); !errors.Is(err, artifact.ErrLimit) || b != nil {
		t.Fatal("ciphertext exceeded declared original allocation", err)
	}
	before := k.unwraps
	if VerifyOwnerConfigurationEpoch(ctx, k, invalid, encoded) == nil || k.unwraps != before {
		t.Fatal("oversized stored record reached key provider")
	}
	if _, err = SealOwnerConfigurationEpoch(ctx, nil, r); !errors.Is(err, artifact.ErrInvalid) {
		t.Fatal("missing sealer accepted")
	}
	if err = VerifyOwnerConfigurationEpoch(ctx, nil, r, encoded); !errors.Is(err, artifact.ErrInvalid) {
		t.Fatal("missing opener accepted")
	}
}

func TestOwnerEpochCodecMaximumConfigurationRemainsBounded(t *testing.T) {
	r := epochCodecRecord(t)
	// The domain allows at most 32 KiB of roots, with 16 KiB per root. These
	// synthetic bytes qualify serialization size, not X.509/provider acceptance.
	r.Epoch.Configuration.IssuerRoots = [][]byte{bytes.Repeat([]byte("a"), 16<<10), bytes.Repeat([]byte("b"), 16<<10)}
	if !r.Valid() {
		t.Fatal("maximum configuration shape rejected")
	}
	k := &countingKeys{testKeys: keys(t)}
	b, err := SealOwnerConfigurationEpoch(context.Background(), k, r)
	if err != nil || len(b) > 128<<10 || k.wraps != 1 || k.unwraps != 0 || k.maxKeyBytes > 4096 {
		t.Fatal("largest supported configuration exceeded fixed envelope/key bounds", err)
	}
	if err = VerifyOwnerConfigurationEpoch(context.Background(), k, r, b); err != nil || k.unwraps != 1 {
		t.Fatal("maximum configuration readback", err)
	}
}

type epochCancelKeys struct {
	*countingKeys
	cancel context.CancelFunc
}

func (k epochCancelKeys) Seal(ctx context.Context, b, ad []byte) (artifact.SealedKey, error) {
	key, err := k.countingKeys.Seal(ctx, b, ad)
	k.cancel()
	return key, err
}
func (k epochCancelKeys) Open(ctx context.Context, key artifact.SealedKey, ad []byte) ([]byte, error) {
	b, err := k.countingKeys.Open(ctx, key, ad)
	k.cancel()
	return b, err
}

func TestOwnerEpochCodecPreservesCancellationAcrossKeyCalls(t *testing.T) {
	r := epochCodecRecord(t)
	k := &countingKeys{testKeys: keys(t)}
	encoded, err := SealOwnerConfigurationEpoch(context.Background(), k, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"before", "during"} {
		for _, operation := range []string{"seal", "verify"} {
			t.Run(phase+"/"+operation, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if phase == "before" {
					cancel()
				}
				beforeWrap, beforeOpen := k.wraps, k.unwraps
				keys := epochCancelKeys{k, cancel}
				if operation == "seal" {
					b, err := SealOwnerConfigurationEpoch(ctx, keys, r)
					if !errors.Is(err, context.Canceled) || b != nil {
						t.Fatal("canceled seal returned success", err)
					}
				} else if err := VerifyOwnerConfigurationEpoch(ctx, keys, r, encoded); !errors.Is(err, context.Canceled) {
					t.Fatal("canceled verification returned success", err)
				}
				want := 0
				if phase == "during" {
					want = 1
				}
				if k.wraps-beforeWrap+k.unwraps-beforeOpen != want {
					t.Fatal("cancellation repeated or unexpectedly started key operation")
				}
			})
		}
	}
}
