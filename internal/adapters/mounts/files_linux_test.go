//go:build linux

package mounts

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMountedFilesConfinementAndRotation(t *testing.T) {
	dir := t.TempDir()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for name, value := range map[string]string{"first": "one", "second": "two"} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Symlink("first", filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}
	first, err := Read(context.Background(), r, "token", 4)
	if err != nil || string(first) != "one" {
		t.Fatal(err)
	}
	if err = os.Symlink("second", filepath.Join(dir, "next")); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(filepath.Join(dir, "next"), filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}
	second, err := Read(context.Background(), r, "token", 4)
	if err != nil || string(second) != "two" || string(first) != "one" {
		t.Fatal("stale projection", err)
	}
	if err = os.Symlink(filepath.Join(dir, "first"), filepath.Join(dir, "absolute")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../first", "absolute", ".", "absent"} {
		if b, err := Read(context.Background(), r, name, 4); err == nil || b != nil {
			t.Fatal("unsafe file accepted", name)
		}
	}
	if _, err = Read(context.Background(), r, "token", 2); err == nil {
		t.Fatal("oversized file accepted")
	}
	if err = os.Chmod(filepath.Join(dir, "second"), 0660); err != nil {
		t.Fatal(err)
	}
	if _, err = Read(context.Background(), r, "token", 4); err == nil {
		t.Fatal("group-writable credential accepted")
	}
}
