package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"golang.org/x/sys/unix"
)

const InitialBootstrapRoot = "/run/asservat/initial-bootstrap"
const InitialBootstrapScratchRoot = "/run/asservat/initial-bootstrap-work"
const InitialBootstrapProjectionRoot = InitialBootstrapScratchRoot + "/projection"

// bootstrapProjectionFiles owns only a fixed memory-backed output directory.
// It is private installation material, never a public/evidence artifact. The
// parent Job mounts schema/preparer subdirectories into their separate phases.
type bootstrapProjectionFiles struct {
	root *os.Root
	lock *os.File
}

func openBootstrapProjectionFiles(root *os.Root) (*bootstrapProjectionFiles, error) {
	if root == nil {
		return nil, mounts.ErrUnavailable
	}
	f, err := root.Open(".")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	var fs unix.Statfs_t
	st, statErr := f.Stat()
	if statErr != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 || unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, mounts.ErrUnavailable
	}
	return &bootstrapProjectionFiles{root: root, lock: f}, nil
}
func (s *bootstrapProjectionFiles) Close() {
	if s != nil && s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		_ = s.lock.Close()
		s.lock = nil
	}
}

func bootstrapOutputLimit(phase, name string) int {
	if phase != "schema" && phase != "preparer" {
		return 0
	}
	switch name {
	case "deployment.json":
		return contracts.InitialPreparationMaxBytes
	case "administrator-token":
		return contracts.WorkerEnrollmentMaxToken
	case "observation.json":
		return contracts.InitialBootstrapObservationMaxBytes
	case "sql-history.json", "sql-maintenance.json":
		if phase == "preparer" {
			return 16 << 10
		}
	}
	return 0
}

func (s *bootstrapProjectionFiles) write(ctx context.Context, phase, name string, body []byte) error {
	if s == nil || s.root == nil || s.lock == nil || ctx == nil || ctx.Err() != nil || len(body) == 0 || len(body) > bootstrapOutputLimit(phase, name) {
		return mounts.ErrUnavailable
	}
	if err := s.root.Mkdir(phase, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return mounts.ErrUnavailable
	}
	// Each compartment must be its own real directory. An in-root alias is
	// confined by os.Root but would defeat the schema/preparer mount split.
	entry, err := s.root.Lstat(phase)
	if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
		return mounts.ErrUnavailable
	}
	dir, err := s.root.OpenRoot(phase)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer dir.Close()
	st, err := dir.Stat(".")
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return mounts.ErrUnavailable
	}
	// The directory lock joins all writes from the one producer process. An
	// interrupted fixed temporary file can be removed; it is never a receipt or
	// authority to start a later init phase. The command must finish successfully.
	temporary := ".pending-" + name
	if err = dir.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return mounts.ErrUnavailable
	}
	f, err := dir.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer dir.Remove(temporary)
	n, err := f.Write(body)
	closeErr := f.Close()
	if err != nil || n != len(body) || closeErr != nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	if err = dir.Rename(temporary, name); err != nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	return nil
}

func (s *bootstrapProjectionFiles) removeMaintenance(ctx context.Context) error {
	if s == nil || s.lock == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	err := s.root.Remove("preparer/sql-maintenance.json")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return mounts.ErrUnavailable
	}
	return ctx.Err()
}

func (s *bootstrapProjectionFiles) common(ctx context.Context, c contracts.InitialPreparer, observation contracts.InitialBootstrapObservation, administrator []byte, history contracts.OwnerSQLCredential) error {
	if !contracts.ValidWorkerToken(administrator) {
		return mounts.ErrUnavailable
	}
	public, err := json.Marshal(c)
	if err != nil {
		return mounts.ErrUnavailable
	}
	observed, err := json.Marshal(observation)
	if err != nil || len(observed) > contracts.InitialBootstrapObservationMaxBytes {
		return mounts.ErrUnavailable
	}
	for _, phase := range []string{"schema", "preparer"} {
		for _, file := range []struct {
			name string
			body []byte
		}{{"deployment.json", public}, {"observation.json", observed}, {"administrator-token", administrator}} {
			if err = s.write(ctx, phase, file.name, file.body); err != nil {
				return err
			}
		}
	}
	b, err := json.Marshal(history)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer clear(b)
	return s.write(ctx, "preparer", "sql-history.json", b)
}
