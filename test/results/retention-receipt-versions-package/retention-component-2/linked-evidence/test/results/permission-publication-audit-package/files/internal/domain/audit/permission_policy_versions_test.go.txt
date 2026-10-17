package audit_test

import (
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

func TestPermissionPolicyAuditRequiresImmutableVersions(t *testing.T) {
	root, event := "20000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000002"
	for _, purpose := range []struct {
		name, key string
		valid     func(audit.Receipt) bool
	}{
		{"permission", audit.AuthorityKey(root, event), func(r audit.Receipt) bool { return r.Valid(root, event) }},
		{"policy", audit.PolicyAcceptanceKey(root, event), func(r audit.Receipt) bool { return r.ValidPolicyAcceptance(root, event) }},
	} {
		for _, tc := range []struct {
			name, version string
			want          bool
		}{
			{"original", "original", true}, {"empty", "", false}, {"null", "null", false},
			{"maximum", strings.Repeat("v", 1024), true}, {"oversize", strings.Repeat("v", 1025), false},
		} {
			t.Run(purpose.name+"/"+tc.name, func(t *testing.T) {
				r := audit.Receipt{Key: purpose.key, Version: tc.version, ETag: "original", Bytes: 64, SHA256: artifact.Digest{1}}
				if got := purpose.valid(r); got != tc.want {
					t.Fatalf("current permission/policy receipt=%v, want %v", got, tc.want)
				}
			})
		}
	}
}
