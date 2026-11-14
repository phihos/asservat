package kubernetes

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func projectionEffectCounts(f *ownerProjectionOperationFixture) [4]int32 {
	return [4]int32{f.journalWrites.Load(), f.creates[0].Load(), f.creates[1].Load(), f.launches.Load()}
}

func projectionReplaceChild(t *testing.T, f *ownerProjectionOperationFixture, index int, field string) {
	t.Helper()
	path := "/api/v1/namespaces/" + f.root.input.Namespace.Name
	if index == 0 {
		path += "/secrets/" + f.resources.names.OwnerProviders
	} else {
		path += "/configmaps/" + f.resources.names.OwnerInputs
	}
	f.api.mu.Lock()
	defer f.api.mu.Unlock()
	original := f.api.objects[path]
	if original == nil {
		t.Fatal("missing original child")
	}
	if field == "uid" {
		original["metadata"].(map[string]any)[field] = ownerID(9831 + index)
	} else {
		original["metadata"].(map[string]any)[field] = "9831"
	}
}

// A legacy verifier is explicit synthetic input to the public legacy factory;
// its already-created helper must still be fenced at the shared root boundary.
type projectionLegacyVerifier struct {
	snapshot contracts.OwnerIdentityRoleSnapshot
}

func (s projectionLegacyVerifier) VerifyOwnerIdentityRoles(context.Context) (contracts.OwnerIdentityRoleSnapshot, error) {
	return s.snapshot, nil
}
