package framed

import (
	"bytes"
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

// ADR-193: the generation-1 audit is sealed under its own purpose and key; any
// changed binding, purpose or tampered byte fails verification.
func TestClusterBootstrapAuditExactPurposeAndRecord(t *testing.T) {
	id := testBinding.ClusterID
	r := audit.ClusterBootstrap{InstallationID: id, BootstrapID: id, RootID: id, ClusterID: id, PeerID: id, IssuerEpoch: id, LineageID: id, KeyDigest: artifact.Digest{1}, ClaimAuditDigest: artifact.Digest{2},
		SourceUID: id, SourceGeneration: 1, ProtectionDigest: artifact.Digest{3}, ReservedAt: time.Now().UTC().Truncate(time.Microsecond)}
	k := keys(t)
	ctx := context.Background()
	b, err := SealClusterBootstrap(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyClusterBootstrap(ctx, k, r, b); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*audit.ClusterBootstrap){
		"key":        func(v *audit.ClusterBootstrap) { v.KeyDigest[0] ^= 1 },
		"source":     func(v *audit.ClusterBootstrap) { v.SourceGeneration++ },
		"claim":      func(v *audit.ClusterBootstrap) { v.ClaimAuditDigest[0] ^= 1 },
		"protection": func(v *audit.ClusterBootstrap) { v.ProtectionDigest[0] ^= 1 },
	} {
		changed := r
		change(&changed)
		if VerifyClusterBootstrap(ctx, k, changed, b) == nil {
			t.Fatal("changed record verified:", name)
		}
	}
	tampered := bytes.Clone(b)
	tampered[len(tampered)-1] ^= 1
	if VerifyClusterBootstrap(ctx, k, r, tampered) == nil {
		t.Fatal("tampered audit verified")
	}
}
