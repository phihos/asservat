package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"strings"
	"testing"
)

func TestContextEffectReceiptsRequireImmutableVersions(t *testing.T) {
	root, id := "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"
	for _, family := range []struct {
		name, key string
		valid     func(Receipt) bool
	}{
		{"capture", CaptureIntentKey(root, id), func(r Receipt) bool { return r.ValidCaptureIntent(root, id) }},
		{"verification", ContextVerificationKey(root, id), func(r Receipt) bool { return r.ValidContextVerification(root, id) }},
	} {
		for _, tc := range []struct {
			name, version string
			valid         bool
		}{{"empty", "", false}, {"null", "null", false}, {"valid", "version-1", true}, {"max", strings.Repeat("v", 1024), true}, {"oversize", strings.Repeat("v", 1025), false}, {"newline", "v\nx", false}} {
			t.Run(family.name+"/"+tc.name, func(t *testing.T) {
				r := Receipt{Key: family.key, Version: tc.version, ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{1}}
				if got := family.valid(r); got != tc.valid {
					t.Fatalf("current receipt validity=%v, want %v", got, tc.valid)
				}
			})
		}
	}
}
