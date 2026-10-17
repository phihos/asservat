package evidence

import (
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

// Fixed historical framed/v1 bytes, independently written before using the
// shared authority helper. Encoding and decoding agreeing alone is insufficient
// to prove that already persisted encrypted artifacts remain readable.
func TestArtifactKeyBindingPreservesFramedV1(t *testing.T) {
	b := artifact.Binding{ClusterID: "00000000-0000-4000-8000-000000000001", ArtifactID: "00000000-0000-4000-8000-000000000002", AttemptID: "00000000-0000-4000-8000-000000000003", MediaType: "application/json"}
	expected := `{"artifactID":"00000000-0000-4000-8000-000000000002","attemptID":"00000000-0000-4000-8000-000000000003","clusterID":"00000000-0000-4000-8000-000000000001","codec":"none","format":"asservat-framed/v1","mediaType":"application/json","nativeBytes":0,"nativeOffset":0,"role":"data-key","schema":"artifact/v1","sequence":0}`
	for _, role := range []string{"data-key", "index-key", "manifest-key"} {
		want := strings.Replace(expected, `"role":"data-key"`, `"role":"`+role+`"`, 1)
		if role == "manifest-key" {
			want = strings.Replace(want, `"mediaType":"application/json"`, `"mediaType":"application/vnd.asservat.manifest+json"`, 1)
		}
		got, err := ArtifactKeyBinding(b, role)
		if err != nil || string(got) != want {
			t.Fatalf("%s binding changed: %s (%v)", role, got, err)
		}
	}
	if _, err := ArtifactKeyBinding(b, "data"); err == nil {
		t.Fatal("stream role confused with key role")
	}
}
