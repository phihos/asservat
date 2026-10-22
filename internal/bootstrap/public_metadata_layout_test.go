package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

func TestPublicRuntimeUnsupportedLayoutPreservesMountedState(t *testing.T) {
	in, dir, c := ownerInputFixture(t)
	m := publicManifestFixture(c)
	m.Input.LayoutDigest = strings.Repeat("0", 64)
	writeOwnerJSON(t, dir, contracts.PublicRuntimeCredentialManifestFile, m)
	path := filepath.Join(dir, contracts.PublicRuntimeCredentialManifestFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readPublicRuntimeManifest(context.Background(), in, in.providerInputs)
	if !errors.Is(err, mounts.ErrUnavailable) || !strings.Contains(err.Error(), "unsupported development SQL credential layout") {
		t.Fatal("unsupported development layout lacked an actionable refusal", err)
	}
	after, e := os.ReadFile(path)
	if e != nil || string(before) != string(after) {
		t.Fatal("unsupported state was rewritten or removed", e)
	}
	line := OwnerStartupDiagnostic(ownerStartupError(startupPublicPools, "none", err))
	if !strings.Contains(line, "reason=unsupported-development-layout ") {
		t.Fatal("startup lost the fixed layout diagnostic", line)
	}
	if _, ok := OwnerStartupDiagnosticLine(line); !ok {
		t.Fatal("fixed layout diagnostic was rejected")
	}
}

func TestPublicMetadataPoolLimitLeavesOtherCredentialsIndependent(t *testing.T) {
	if limit, ok := contracts.PublicRuntimeRolePoolLimit("hub-metadata-read"); !ok || limit != 7 {
		t.Fatal("metadata pool lost aggregate concurrency")
	}
	for _, purpose := range contracts.PublicRuntimeRolePurposes() {
		if purpose == "hub-metadata-read" {
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
