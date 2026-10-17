package bootstrap

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"golang.org/x/sys/unix"
)

func bootstrapProjectionFilesFixture(t *testing.T) (*bootstrapProjectionFiles, *os.Root) {
	t.Helper()
	// Exercise the actual memory-filesystem and flock requirements without a
	// privileged mount. The native runner's memory volume is qualified separately.
	dir, err := os.MkdirTemp("/dev/shm", "asservat-bootstrap-projection-")
	if err != nil {
		t.Skip("private existing tmpfs unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	files, err := openBootstrapProjectionFiles(root)
	if err != nil {
		t.Fatal("private tmpfs projection rejected", err)
	}
	t.Cleanup(files.Close)
	return files, root
}

func TestInitialBootstrapProjectionUsesContractSpecificLimits(t *testing.T) {
	files, root := bootstrapProjectionFilesFixture(t)
	// The public observation includes desired input plus retained public pins
	// and has a distinct 64 KiB contract, larger than deployment's 48 KiB.
	observation := bytes.Repeat([]byte("x"), contracts.InitialBootstrapObservationMaxBytes)
	if err := files.write(context.Background(), "schema", "observation.json", observation); err != nil {
		t.Fatal("valid observation contract bound was narrowed to deployment size", err)
	}
	for _, pair := range [][2]string{{"schema", "deployment.json"}, {"preparer", "administrator-token"}, {"preparer", "sql-maintenance.json"}} {
		if err := files.write(context.Background(), pair[0], pair[1], observation); err == nil {
			t.Fatal("unrelated file inherited observation's larger limit", pair)
		}
	}
	if err := files.write(context.Background(), "schema", "observation.json", append(observation, 'x')); err == nil {
		t.Fatal("oversized observation accepted")
	}
	got, err := root.ReadFile("schema/observation.json")
	if err != nil || !bytes.Equal(got, observation) {
		t.Fatal("failed oversized write replaced original projection", err)
	}
}

func TestInitialBootstrapProjectionCompartmentsAndAtomicReplacement(t *testing.T) {
	files, root := bootstrapProjectionFilesFixture(t)
	ctx := context.Background()
	for _, pair := range [][2]string{{"schema", "sql-maintenance.json"}, {"schema", "sql-history.json"}, {"schema", "postgres-ddl.json"}, {"preparer", "postgres-administrator.json"}, {"preparer", "provider-material.json"}, {"../elsewhere", "deployment.json"}, {"preparer", "../deployment.json"}} {
		if err := files.write(ctx, pair[0], pair[1], []byte("synthetic")); err == nil {
			t.Fatal("unrequested credential/path crossed fixed phase boundary", pair)
		}
	}
	if err := files.write(ctx, "preparer", "sql-maintenance.json", []byte("first-synthetic-value")); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("preparer/.pending-sql-maintenance.json", []byte("interrupted-synthetic-value"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := files.write(ctx, "preparer", "sql-maintenance.json", []byte("second-synthetic-value")); err != nil {
		t.Fatal(err)
	}
	got, err := root.ReadFile("preparer/sql-maintenance.json")
	info, statErr := root.Stat("preparer/sql-maintenance.json")
	if err != nil || statErr != nil || string(got) != "second-synthetic-value" || info.Mode().Perm() != 0600 {
		t.Fatal("fixed replacement or private file mode lost")
	}
	if _, err := root.Stat("preparer/.pending-sql-maintenance.json"); !os.IsNotExist(err) {
		t.Fatal("temporary credential copy retained")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if files.write(cancelled, "preparer", "sql-maintenance.json", []byte("late")) == nil {
		t.Fatal("cancelled writer changed projected material")
	}
	if err := root.Symlink("preparer", "schema"); err != nil {
		t.Fatal(err)
	}
	if files.write(ctx, "schema", "deployment.json", []byte("aliased")) == nil {
		t.Fatal("same-root alias merged phase compartments")
	}
	if _, err := openBootstrapProjectionFiles(root); err == nil {
		t.Fatal("second producer bypassed exclusive original directory ownership")
	}
	if err := files.removeMaintenance(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Stat("preparer/sql-maintenance.json"); !os.IsNotExist(err) {
		t.Fatal("passive projection retained maintenance credential")
	}
	files.Close()
	if files.write(ctx, "preparer", "deployment.json", []byte("late")) == nil {
		t.Fatal("retained writer survived closure")
	}
}

func TestInitialBootstrapProjectionRefusesUnqualifiedFilesystem(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var fs unix.Statfs_t
	if err := unix.Statfs(filepath.Clean(dir), &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != unix.TMPFS_MAGIC {
		if files, err := openBootstrapProjectionFiles(root); err == nil {
			files.Close()
			t.Fatal("disk-backed private projection accepted")
		}
	}
	if err := root.Chmod(".", 0777); err != nil {
		t.Fatal(err)
	}
	if files, err := openBootstrapProjectionFiles(root); err == nil {
		files.Close()
		t.Fatal("shared-writable private projection accepted")
	}
}
