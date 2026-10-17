package audit

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type exactIntentFixture struct {
	snapshot CaptureIntentSnapshot
	ids      []string
	after    func()
}

func (f *exactIntentFixture) ReadCaptureIntent(ctx context.Context, id string) (CaptureIntentSnapshot, error) {
	f.ids = append(f.ids, id)
	if f.after != nil {
		f.after()
	}
	return f.snapshot, ctx.Err()
}

func TestExactCaptureIntentReusesOnlyAcknowledgedOriginal(t *testing.T) {
	for _, mode := range []string{"valid", "pending", "wrong-root", "wrong-capture", "wrong-key", "expired-after-read", "cancelled-after-read"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			id := "00000000-0000-4000-8000-000000000001"
			root := "00000000-0000-4000-8000-000000000002"
			r := value.CaptureIntent{RootID: root, CaptureID: id, CaseID: id, OccurrenceID: id, ArtifactID: id, AttemptID: id, Actor: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}, Target: authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: id, PermissionSequence: 1, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{4}}, CreatedAt: now.Add(-2 * time.Hour), Deadline: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour), ReservedBytes: 1 << 20}
			receipt := value.Receipt{Key: value.CaptureIntentKey(root, id), Version: "synthetic-version", ETag: "synthetic", Bytes: 100, SHA256: artifact.Digest{1}}
			f := &exactIntentFixture{snapshot: CaptureIntentSnapshot{Intent: r, Receipt: &receipt}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "pending":
				f.snapshot.Receipt = nil
			case "wrong-root":
				f.snapshot.Intent.RootID = id
			case "wrong-capture":
				f.snapshot.Intent.CaptureID = root
			case "wrong-key":
				receipt.Key = value.CaptureIntentKey(root, root)
			case "expired-after-read":
				f.after = func() { now = now.Add(6 * time.Second) }
			case "cancelled-after-read":
				f.after = cancel
			}
			p := ExactCaptureIntentPublication{RootID: root, Reader: f, Now: func() time.Time { return now }}
			got, err := p.AcknowledgedCaptureIntent(ctx, id)
			if len(f.ids) != 1 || f.ids[0] != id {
				t.Fatal("exact selection lost")
			}
			if mode != "valid" {
				if err == nil {
					t.Fatal("unavailable acknowledgement accepted")
				}
				return
			}
			if err != nil || got != r {
				t.Fatal("historical acknowledged receipt not reused", err)
			}
			// No writer/KMS/storage port exists in this read-only composition.
		})
	}
}
