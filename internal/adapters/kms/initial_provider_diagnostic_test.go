package kms

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestInitialProviderCheckDiagnosticHidesValues(t *testing.T) {
	f := newInitialProviderFixture(t)
	f.roleChange = func(v *initialTokenRole) { v.Type = "DO-NOT-LEAK-provider-value" }
	_, _, e := f.issuer.Check(context.Background(), time.Now().Add(time.Hour))
	if !errors.Is(e, ErrKeyService) || InitialProviderCheckStage(e) != "wrap-role" || strings.Contains(e.Error(), "DO-NOT-LEAK") {
		t.Fatal("unsafe provider diagnostic")
	}
	if InitialProviderCheckStage(errors.New("raw failure")) != "" {
		t.Fatal("unknown error exposed")
	}
}

func TestInitialProviderPinnedACLReadMetadata(t *testing.T) {
	f := newInitialProviderFixture(t)
	f.policyMetadata = map[string]any{"version": 1, "cas_required": false, "allow_wildcards_in_identity_templates": false, "allow_slashes_in_identity_templates": false, "modified": "2026-10-01T00:00:00Z"}
	if _, _, e := f.issuer.Check(context.Background(), time.Now().Add(time.Hour)); e != nil {
		t.Fatal("pinned OpenBao ACL response rejected", e)
	}
}

func TestInitialProviderRejectsUnsupportedACLMetadata(t *testing.T) {
	for _, metadata := range []map[string]any{
		{"allow_wildcards_in_identity_templates": true}, {"allow_slashes_in_identity_templates": true},
		{"expiration": "2030-01-01T00:00:00Z"}, {"expiration": "2020-01-01T00:00:00Z"},
		{"version": -1}, {"version": 1.5}, {"version": "1"}, {"modified": "invalid"}, {"new_unknown_authority": "forbidden"},
	} {
		f := newInitialProviderFixture(t)
		f.policyMetadata = metadata
		if _, _, e := f.issuer.Check(context.Background(), time.Now().Add(time.Hour)); !errors.Is(e, ErrKeyService) || InitialProviderCheckStage(e) != "policies" {
			t.Fatal("unsupported policy metadata accepted", e)
		}
		f.mu.Lock()
		issued := f.posts
		f.mu.Unlock()
		if issued != 0 {
			t.Fatal("preflight created credential")
		}
	}
}
