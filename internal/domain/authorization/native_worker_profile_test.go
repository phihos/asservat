package authorization

import (
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func TestNativeWorkerProfileHasSeparateMemoryFloor(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	p := DownloadWorkerProfile{Configuration: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, InstallationID: id, ClusterID: id, Namespace: "workers", NamespaceUID: id, ServiceAccount: "acquisition", ServiceAccountUID: id, Image: "example.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "worker", ControlConfigUID: id, PriorityClass: "worker", PriorityClassUID: id, ControlDigest: artifact.Digest{2}, CPUMillis: 100, MemoryBytes: 16 << 20, MaxRuntime: time.Minute}
	if !p.Valid() {
		t.Fatal("legacy credential-only profile rejected")
	}
	p.StoreCredentialSecret, p.StoreCredentialSecretUID = "native-store", id
	for _, test := range []struct {
		memory int64
		valid  bool
	}{{16 << 20, false}, {64<<20 - 1, false}, {64 << 20, true}, {128 << 20, true}, {8<<30 + 1, false}} {
		p.MemoryBytes = test.memory
		if p.Valid() != test.valid {
			t.Fatalf("native memory=%d accepted=%t", test.memory, p.Valid())
		}
	}
}
