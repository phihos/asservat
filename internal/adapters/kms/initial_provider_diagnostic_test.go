package kms

import (
	"context"
	"testing"
	"time"
)

func TestInitialProviderPinnedACLReadMetadata(t *testing.T) {
	f := newInitialProviderFixture(t)
	f.policyMetadata = map[string]any{"version": 1, "cas_required": false, "allow_wildcards_in_identity_templates": false, "allow_slashes_in_identity_templates": false, "modified": "2026-10-01T00:00:00Z"}
	if _, _, e := f.issuer.Check(context.Background(), time.Now().Add(time.Hour)); e != nil {
		t.Fatal("pinned OpenBao ACL response rejected", e)
	}
}
