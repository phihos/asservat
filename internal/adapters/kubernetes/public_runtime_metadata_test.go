package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestPublicRuntimeOldLayoutCannotReplaceRetainedJournal(t *testing.T) {
	f := newPublicRoleRootFixture(t, false, false)
	original, err := f.root.OpenPublicRuntimeRoles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	old := original.State
	old.Input.LayoutDigest = strings.Repeat("2", 64)
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.object.Data["state.json"] = raw
	writes := f.writes.Load()
	f.mu.Unlock()
	_, err = f.root.OpenPublicRuntimeRoles(context.Background())
	if !errors.Is(err, cfg.ErrChanged) || !strings.Contains(err.Error(), "unsupported development SQL credential layout") {
		t.Fatal("old layout was adopted or lacked a fixed refusal", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writes.Load() != writes || !bytes.Equal(f.object.Data["state.json"], raw) || string(f.object.UID) != original.UID {
		t.Fatal("unsupported retained journal was rewritten or replaced")
	}
}

func TestPublicMetadataProjectionContainsOneCredential(t *testing.T) {
	state := contracts.PublicRuntimeRoleState{}
	for _, purpose := range contracts.PublicRuntimeHubRolePurposes() {
		state.Roles = append(state.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: purpose, Password: "synthetic", Claim: &contracts.PublicRuntimeRoleClaim{}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: purpose}})
	}
	data, err := runtimeProjectionData(state)
	if err != nil {
		t.Fatal(err)
	}
	defer clearRuntimeProjection(data)
	if len(data) != 46 || len(data["sql-public-hub-metadata-read.json"]) == 0 {
		t.Fatal("metadata projection retained separate credentials")
	}
	for _, old := range []string{"permission-read", "retention-read", "storage-read", "progress-read", "case-read", "processing-read", "catalog-read"} {
		if _, ok := data["sql-public-"+old+".json"]; ok {
			t.Fatal("retired metadata credential still projected", old)
		}
	}
}
