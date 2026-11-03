package audit

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// A grouped intent names an initiator exactly when a policy executes it: a
// recording save child; an ADR-276 composition child runs as the human.
func TestGroupedIntentInitiatorFollowsExecutor(t *testing.T) {
	now := time.Now()
	human := identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "browser", Kind: identity.Human}
	id := func(n byte) string {
		return "00000000-0000-4000-8000-0000000000" + string([]byte{'0' + n/10, '0' + n%10})
	}
	r := CaptureIntent{RootID: id(1), CaptureID: id(2), CaseID: id(3), OccurrenceID: id(4), ArtifactID: id(5), AttemptID: id(6), Actor: human, Target: authorization.Target{ClusterID: id(7), NamespaceUID: "ns", WorkloadUID: "wl", PodUID: "pod"}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: id(8), PermissionSequence: 1, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{4}}, CreatedAt: now, Deadline: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour), ReservedBytes: 4096}
	for _, limit := range []int64{16 << 20, artifact.MaxPprofBytes, artifact.MaxGoTraceBytes} {
		profile := r
		profile.ReservedBytes = (artifact.Registration{NativeLimit: limit}).ReservedBytes()
		if !profile.Valid() {
			t.Fatal("supported profile final reservation refused", limit)
		}
	}
	oversized := r
	oversized.ReservedBytes = (artifact.Registration{NativeLimit: artifact.MaxGoTraceBytes}).ReservedBytes() + 1
	if oversized.Valid() {
		t.Fatal("capture audit accepted unsupported reservation")
	}
	r.Group = &CaptureGroupBinding{ParentCaptureID: id(9), SelectionDigest: r.ScopeDigest, ChildIndex: 0, ChildCount: 2}
	if !r.Valid() {
		t.Fatal("human composition child refused")
	}
	initiator := human
	r.Initiator = &initiator
	if r.Valid() {
		t.Fatal("a human group child named a separate initiator")
	}
}
