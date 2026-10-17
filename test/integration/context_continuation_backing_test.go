package integration

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"testing"
	"time"
)

func TestNativeContinuationAuditBackingCoversOriginalWriteInterval(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	root, id := custodyID(), custodyID()
	mac, err := auditapp.NewOperationMAC("capture-input-v1", bytes.Repeat([]byte{41}, 32), "capture-accounts-v1", bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer mac.Close()
	account := nativeContinuationAuditAccount(t, root, custodyID(), custodyID(), now, mac)
	c := auditvalue.CaptureIntent{RootID: root, CaptureID: id, CaseID: root, OccurrenceID: id, ArtifactID: root, AttemptID: id, Actor: identity.Principal{Issuer: "https://issuer.example", Subject: "subject", ClientID: "browser", Kind: identity.Human}, Target: authorization.Target{ClusterID: root, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: root, PermissionSequence: 1, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{4}}, CreatedAt: now, Deadline: now.Add(30 * time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute), ReservedBytes: 4096}
	if !c.Valid() || !account.Valid() {
		t.Fatal("invalid synthetic fixture inputs")
	}
	in, err := auditapp.PrepareCaptureOperation(c, account, mac, now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("actual continuation fixture backing cannot fund original 30s write interval: %v", err)
	}
	if !in.WriteUntil.Equal(c.Deadline) || !in.Lifecycle.OriginalPurgeAt.After(c.Deadline) {
		t.Fatal("fixture shortened original write interval or overlapped cleanup")
	}
	// At H=0, B=15 and P=1 the original purge is RetainedSeconds-46.
	// +76s reaches exactly +30s and remains invalid; +77s is the first
	// whole-second retention that funds a later purge without changing write.
	for _, seconds := range []int64{60, 76, 77} {
		a := account
		a.RetainedSeconds = seconds
		got, err := auditapp.PrepareCaptureOperation(c, a, mac, now.Add(5*time.Second))
		if seconds <= 76 {
			if err != auditapp.ErrUnavailable {
				t.Fatal("underfunded original lifecycle accepted", seconds, err)
			}
			continue
		}
		if err != nil || !got.WriteUntil.Equal(c.Deadline) || !got.Lifecycle.OriginalPurgeAt.Equal(now.Add(31*time.Second)) {
			t.Fatal("funded boundary changed original interval", err)
		}
	}
}
