package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"strings"
	"testing"
)

func TestBootstrapCurrentAuditRequiresImmutableVersion(t *testing.T) {
	const root = "30000000-0000-4000-8000-000000000001"
	const event = "30000000-0000-4000-8000-000000000002"
	original := Receipt{Key: BootstrapIssueKey(root, event), Version: "original-version", ETag: "original-etag", Bytes: 1024, SHA256: artifact.Digest{1}}
	for _, tc := range []struct {
		name, version string
		want          bool
	}{
		{"original", "original-version", true}, {"empty", "", false}, {"literal-null", "null", false},
		{"maximum", strings.Repeat("v", 1024), true}, {"oversized", strings.Repeat("v", 1025), false}, {"control", "v\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := original
			r.Version = tc.version
			before := r
			if r.ValidBootstrapIssue(root, event) != tc.want {
				t.Fatal("unexpected immutable-version decision")
			}
			if r != before {
				t.Fatal("historical receipt rewritten")
			}
		})
	}
}
