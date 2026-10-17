package audit_test

import (
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

func TestRetentionCurrentAuditRequiresImmutableVersions(t *testing.T) {
	root, event := "20000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000002"
	for _, purpose := range []struct {
		name, key string
		max       int64
		valid     func(audit.Receipt) bool
	}{
		{"checkpoint", audit.RetentionAcceptanceKey(root, event), 512 << 10, func(r audit.Receipt) bool { return r.ValidRetentionAcceptance(root, event) }},
		{"lifecycle", audit.LifecycleKey(root, event), 128 << 10, func(r audit.Receipt) bool { return r.ValidLifecycle(root, event) }},
	} {
		for _, tc := range []struct {
			name, version string
			want          bool
		}{
			{"original", "original", true}, {"empty", "", false}, {"null", "null", false},
			{"maximum", strings.Repeat("v", 1024), true}, {"oversize", strings.Repeat("v", 1025), false},
			{"unicode-control", "v\u0085", false}, {"unicode-printable", "v\u00a0", true},
		} {
			t.Run(purpose.name+"/"+tc.name, func(t *testing.T) {
				r := audit.Receipt{Key: purpose.key, Version: tc.version, ETag: "original", Bytes: purpose.max, SHA256: artifact.Digest{1}}
				if got := purpose.valid(r); got != tc.want {
					t.Fatalf("current receipt=%v want %v", got, tc.want)
				}
				r.Bytes++
				if purpose.valid(r) {
					t.Fatal("oversize receipt accepted")
				}
			})
		}
	}
}
