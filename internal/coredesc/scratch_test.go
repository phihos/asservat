package coredesc

import (
	"os"
	"path/filepath"
	"testing"
)

// scratchDir is a scratch directory as an agent has one: where the test
// is root, and gdb therefore nobody in root's group, that group may pass
// through the directory above it, which the testing package keeps to root.
func scratchDir(t *testing.T) string {
	dir := t.TempDir()
	if os.Geteuid() == 0 {
		os.Chmod(filepath.Dir(dir), 0o750)
	}
	return dir
}
