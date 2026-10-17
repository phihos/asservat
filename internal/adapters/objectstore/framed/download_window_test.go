package framed

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

func windowAuditFixture() audit.DownloadWindowIntent {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod", Version: artifact.Digest{1}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{2}, DecisionDigest: artifact.Digest{3}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{4}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(time.Minute)}
	r := artifact.DownloadResponse{ID: id, SessionID: id, OwnerID: id, Generation: 2, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: 100}, WholeFile: true, WindowReadLimit: 1024}, StartedAt: now, Until: now.Add(time.Minute), WindowCount: 1, ActiveWindowID: id}
	w := artifact.DownloadWindow{ID: id, ResponseID: id, SessionID: id, OwnerID: id, AuditStoreID: id, Generation: 2, Ordinal: 1, Length: 100, ReadLimit: 1024, StartedAt: now, WriteUntil: now.Add(2 * time.Minute), Authority: a}
	return audit.DownloadWindowIntent{Response: r, Window: w}
}

func TestDownloadWindowAuditPinsResponseRangeOwnerAndPhase(t *testing.T) {
	i := windowAuditFixture()
	k := keys(t)
	ctx := context.Background()
	sealed, e := SealDownloadWindowIntent(ctx, k, i)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyDownloadWindowIntent(ctx, k, i, sealed); e != nil {
		t.Fatal(e)
	}
	changes := []func(*audit.DownloadWindowIntent){func(v *audit.DownloadWindowIntent) { v.Window.Authority.Scope.Principal.Subject = "other" }, func(v *audit.DownloadWindowIntent) {
		v.Response.OwnerID = "22222222-2222-4222-8222-222222222222"
		v.Window.OwnerID = v.Response.OwnerID
	}, func(v *audit.DownloadWindowIntent) { v.Response.Generation++; v.Window.Generation++ }, func(v *audit.DownloadWindowIntent) { v.Window.ReadLimit++ }, func(v *audit.DownloadWindowIntent) { v.Window.AuditStoreID = "22222222-2222-4222-8222-222222222222" }}
	for _, change := range changes {
		bad := i
		change(&bad)
		if VerifyDownloadWindowIntent(ctx, k, bad, sealed) == nil {
			t.Fatal("changed immutable intent accepted")
		}
	}
	o := audit.DownloadWindowAuditOutcome{Intent: i, Outcome: artifact.DownloadWindowOutcome{EmittedBytes: 100, Success: true, VerifiedFinal: true, RecordedAt: i.Window.StartedAt}}
	if VerifyDownloadWindowOutcome(ctx, k, o, sealed) == nil {
		t.Fatal("intent accepted as outcome")
	}
	cipher, e := SealDownloadWindowOutcome(ctx, k, o)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyDownloadWindowOutcome(ctx, k, o, cipher); e != nil {
		t.Fatal(e)
	}
	o.Outcome.VerifiedFinal = false
	if VerifyDownloadWindowOutcome(ctx, k, o, cipher) == nil {
		t.Fatal("final verification changed")
	}
	k.fail = true
	if _, e = SealDownloadWindowIntent(ctx, k, i); e == nil {
		t.Fatal("plaintext fallback")
	}
}
