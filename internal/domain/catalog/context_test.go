package catalog

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"testing"
	"time"
)

func TestCaseViewRequiresBoundedUniqueCurrentlyReadableArtifacts(t *testing.T) {
	n := time.Now().UTC()
	id := "11111111-1111-4111-8111-111111111111"
	base := ContextCase{CaseID: id, ObservedAt: n, ValidUntil: n.Add(time.Second), Artifacts: []ContextCaseArtifact{{ArtifactID: id, CaptureID: id, Target: authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod"}, Version: artifact.Digest{1}, ExpiresAt: n.Add(time.Hour), DeleteBy: n.Add(2 * time.Hour)}}}
	if !base.Valid(n) {
		t.Fatal("valid metadata rejected")
	}
	for _, which := range []string{"empty", "duplicate", "expiry", "delete", "version", "interval", "identity"} {
		c := base
		c.Artifacts = append([]ContextCaseArtifact(nil), base.Artifacts...)
		switch which {
		case "empty":
			c.Artifacts = nil
		case "duplicate":
			c.Artifacts = append(c.Artifacts, c.Artifacts[0])
		case "expiry":
			c.Artifacts[0].ExpiresAt = n
		case "delete":
			c.Artifacts[0].DeleteBy = c.Artifacts[0].ExpiresAt
		case "version":
			c.Artifacts[0].Version = artifact.Digest{}
		case "interval":
			c.ValidUntil = n.Add(6 * time.Second)
		case "identity":
			c.Artifacts[0].CaptureID = "invalid"
		}
		if c.Valid(n) {
			t.Fatal("invalid view accepted", which)
		}
	}
}
