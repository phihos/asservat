package framed

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

func TestDownloadAuditPinsRangeActorGenerationAndPurpose(t *testing.T) {
	ctx := context.Background()
	k := keys(t)
	now := time.Now().UTC()
	id := testBinding.ArtifactID
	scope := artifact.DownloadScope{RootID: testBinding.ClusterID, ArtifactID: id, CaptureID: id, ClusterID: testBinding.ClusterID, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{2}, DecisionDigest: artifact.Digest{3}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{4}}, CheckedAt: now, ValidUntil: now.Add(time.Second), AccessUntil: now.Add(time.Minute)}
	r := audit.DownloadIntent{SessionID: id, Batch: artifact.DownloadBatch{ID: testBinding.AttemptID, Generation: 1, Purpose: artifact.DownloadContent, Offset: 10, OutputBytes: 100, ReadBytes: 1024, StartedAt: now, LeaseUntil: a.ValidUntil, Authority: a}}
	b, err := SealDownloadIntent(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyDownloadIntent(ctx, k, r, b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*audit.DownloadIntent){
		func(r *audit.DownloadIntent) { r.Batch.Authority.Scope.Principal.ClientID = "other" },
		func(r *audit.DownloadIntent) { r.Batch.Authority.Scope.Principal.Subject = "other" },
		func(r *audit.DownloadIntent) { r.Batch.Authority.Scope.Version[0]++ },
		func(r *audit.DownloadIntent) { r.Batch.Offset++ },
		func(r *audit.DownloadIntent) { r.Batch.OutputBytes++ },
		func(r *audit.DownloadIntent) { r.Batch.ReadBytes++ },
		func(r *audit.DownloadIntent) { r.Batch.Generation++ },
		func(r *audit.DownloadIntent) { r.Batch.Authority.PermissionSequence++ },
	} {
		bad := r
		change(&bad)
		if VerifyDownloadIntent(ctx, k, bad, b) == nil {
			t.Fatal("audit accepted changed authority/spend")
		}
	}
	o := audit.DownloadOutcome{Intent: r, EmittedBytes: 100, Success: true, RecordedAt: now}
	if VerifyDownloadOutcome(ctx, k, o, b) == nil {
		t.Fatal("intent accepted as outcome")
	}
	cipher, err := SealDownloadOutcome(ctx, k, o)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyDownloadOutcome(ctx, k, o, cipher); err != nil {
		t.Fatal(err)
	}
	o.EmittedBytes--
	o.Success = false
	if VerifyDownloadOutcome(ctx, k, o, cipher) == nil {
		t.Fatal("changed outcome accepted")
	}
	cipher[len(cipher)-2] ^= 1
	if VerifyDownloadOutcome(ctx, k, o, cipher) == nil {
		t.Fatal("corrupt outcome accepted")
	}
	k.fail = true
	if _, err = SealDownloadIntent(ctx, k, r); err == nil {
		t.Fatal("plaintext fallback")
	}
}
