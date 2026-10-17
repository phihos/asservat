package audit_test

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
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

func TestDownloadWindowCompletionCannotChangePurposeOrBackedStore(t *testing.T) {
	i := windowAuditFixture()
	if !i.Valid() {
		t.Fatal("fixture")
	}
	r := audit.Receipt{Key: audit.DownloadWindowAuditKey(i.Window.Authority.Scope.RootID, i.Response.ID, i.Window.ID, "intent"), Version: "synthetic-original-version", ETag: "synthetic", Bytes: 123, SHA256: artifact.Digest{2}}
	c := audit.DownloadWindowWriteCompletion{RootID: i.Window.Authority.Scope.RootID, ResponseID: i.Response.ID, WindowID: i.Window.ID, StoreID: i.Window.AuditStoreID, Phase: "intent", RecordDigest: artifact.Digest{5}, Receipt: r, CompletedAt: i.Window.StartedAt.Add(time.Second)}
	if !c.Valid(i, nil) {
		t.Fatal("completion")
	}
	for _, change := range []func(*audit.DownloadWindowWriteCompletion){func(v *audit.DownloadWindowWriteCompletion) { v.Phase = "outcome" }, func(v *audit.DownloadWindowWriteCompletion) { v.StoreID = "22222222-2222-4222-8222-222222222222" }, func(v *audit.DownloadWindowWriteCompletion) { v.CompletedAt = i.Window.WriteUntil }} {
		bad := c
		change(&bad)
		if bad.Valid(i, nil) {
			t.Fatal("changed completion accepted")
		}
	}
	if i.Response.Plan.AuditBytes() != 2*artifact.DownloadWindowAuditBytes {
		t.Fatal("audit slots not finite")
	}
}
