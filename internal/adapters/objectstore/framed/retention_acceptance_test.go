package framed

import (
	"bytes"
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

func TestRetentionAcceptanceEncryptedExactPurposeAndHistory(t *testing.T) {
	id := testBinding.ClusterID
	r := audit.RetentionAcceptance{ID: id, RootID: id, Epoch: id, SourceClusterID: id, ControlNamespaceUID: "control", Hub: true, Sequence: 1, ProtectionDigest: artifact.Digest{1}, CheckpointDigest: artifact.Digest{2}, CreatedAt: time.Now().UTC(), Policies: []artifact.RetentionRule{}, Bootstrap: &audit.RetentionBootstrap{PoliciesDigest: artifact.Digest{3}}}
	k := keys(t)
	ctx := context.Background()
	b, err := SealRetentionAcceptance(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("CheckpointDigest")) || bytes.Contains(b, []byte("control")) {
		t.Fatal("plaintext provenance in envelope")
	}
	if err = VerifyRetentionAcceptance(ctx, k, r, b); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"root", "policy", "epoch", "sequence", "corrupt", "format", "duplicate-json"} {
		t.Run(mode, func(t *testing.T) {
			changed := r
			body := bytes.Clone(b)
			switch mode {
			case "root":
				changed.RootID = "22222222-2222-4222-8222-222222222222"
			case "policy":
				changed.CheckpointDigest = artifact.Digest{9}
			case "epoch":
				changed.Epoch = "22222222-2222-4222-8222-222222222222"
			case "sequence":
				changed.Sequence = 2
				changed.PreviousDigest = artifact.Digest{6}
				changed.Bootstrap = nil
			case "corrupt":
				body[len(body)/2] ^= 1
			case "format":
				body = bytes.ReplaceAll(body, []byte(retentionAcceptanceFormat), []byte(auditFormat))
			case "duplicate-json":
				body = append([]byte(`{"format":"asservat-retention-acceptance/v1",`), body[1:]...)
			}
			if VerifyRetentionAcceptance(ctx, k, changed, body) == nil {
				t.Fatal("mismatched encrypted checkpoint accepted")
			}
		})
	}
}
