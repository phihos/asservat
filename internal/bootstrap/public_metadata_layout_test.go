package bootstrap

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestPublicSharedCredentialLeavesOtherCredentialsIndependent(t *testing.T) {
	if limit, ok := contracts.PublicRuntimeRolePoolLimit("hub-runtime"); !ok || limit != 20 {
		t.Fatal("metadata pool lost aggregate concurrency")
	}
	for _, purpose := range contracts.PublicRuntimeRolePurposes() {
		if purpose == "hub-runtime" {
			continue
		}
		if limit, ok := contracts.PublicRuntimeRolePoolLimit(purpose); !ok || limit != 1 {
			t.Fatal("unrelated pool limit changed", purpose)
		}
	}
	if _, ok := contracts.PublicRuntimeRolePoolLimit("permission-read"); ok {
		t.Fatal("old metadata credential remained selectable")
	}
}
