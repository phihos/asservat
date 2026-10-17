package mtls

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestProjectedWorkerTokenRotationAndBounds(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	for path, token := range map[string]string{first: "synthetic.first.token", second: "synthetic.second.token"} {
		if err := os.WriteFile(path, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
	}
	link, next := filepath.Join(dir, "token"), filepath.Join(dir, "replacement")
	if err := os.Symlink(filepath.Base(first), link); err != nil {
		t.Fatal(err)
	}
	reader := projectedWorkerToken{link} // private path override in test only
	before, err := reader.ReadDownloadPeerToken(context.Background())
	if err != nil || string(before) != "synthetic.first.token" {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(second), next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, link); err != nil {
		t.Fatal(err)
	}
	after, err := reader.ReadDownloadPeerToken(context.Background())
	if err != nil || string(after) != "synthetic.second.token" || string(before) != "synthetic.first.token" {
		t.Fatal("rotation used a stale/shared buffer", err)
	}
	clear(after)
	again, err := reader.ReadDownloadPeerToken(context.Background())
	if err != nil || string(again) != "synthetic.second.token" {
		t.Fatal("consumer clear mutated credential", err)
	}
	for _, invalid := range [][]byte{nil, []byte("synthetic.token\n"), bytes.Repeat([]byte("x"), contracts.WorkerEnrollmentMaxToken+1)} {
		if err := os.WriteFile(second, invalid, 0600); err != nil {
			t.Fatal(err)
		}
		if b, err := reader.ReadDownloadPeerToken(context.Background()); err == nil || b != nil {
			t.Fatal("invalid token returned")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.ReadDownloadPeerToken(ctx); err == nil {
		t.Fatal("cancelled read")
	}
	if _, err := (projectedWorkerToken{dir}).ReadDownloadPeerToken(context.Background()); err == nil {
		t.Fatal("directory token accepted")
	}
}
