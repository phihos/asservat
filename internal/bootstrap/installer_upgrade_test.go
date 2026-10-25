package bootstrap

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// installer-upgrade refuses missing, extra or malformed inputs before any SQL.
func TestInstallerUpgradeRefusesIncompleteInputs(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{nil, {"--inputs"}, {"--inputs", dir, "extra"}, {"--inputs", filepath.Join(dir, "missing")}, {"--inputs", dir}} {
		if err := RunInstallerUpgrade(context.Background(), args, io.Discard); err == nil {
			t.Fatal("accepted", args)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "postgres-endpoint.json"), []byte(`{"host":"db.example.test","port":5432,"database":"asservat"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunInstallerUpgrade(context.Background(), []string{"--inputs", dir}, io.Discard); err == nil {
		t.Fatal("endpoint without trust roots accepted")
	}
}
