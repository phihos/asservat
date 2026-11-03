package syscalls

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"syscall"
	"time"

	"asservat.local/asservat/internal/domain/artifact"

	igsyscalls "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"golang.org/x/sys/unix"
)

// ABI is the only syscall table this package names. The Inspektor Gadget
// table is selected by GOARCH (syscalls_amd64.go) and noReturn uses x86_64
// numbers, so callers must not record on other architectures.
const ABI = "x86_64"

// Name is the x86_64 syscall name; unknown numbers are "syscall_<hex>" (as
// strace and Inspektor Gadget print them).
func Name(nr uint16) string { return igsyscalls.SyscallGetName(nr) }

// Errno classifies a raw return value. Linux returns -errno in [-4095, -1];
// everything else (including addresses from mmap) is success.
func Errno(ret int64) (name string, failed bool) {
	if ret >= 0 || ret < -4095 {
		return "", false
	}
	n := -ret
	if s := unix.ErrnoName(syscall.Errno(n)); s != "" {
		return s, true
	}
	// Kernel-internal restart codes are visible at the sys_exit tracepoint
	// before signal delivery rewrites them (include/linux/errno.h).
	switch n {
	case 512:
		return "ERESTARTSYS", true
	case 513:
		return "ERESTARTNOINTR", true
	case 514:
		return "ERESTARTNOHAND", true
	case 515:
		return "ENOIOCTLCMD", true
	case 516:
		return "ERESTART_RESTARTBLOCK", true
	}
	return "errno_" + strconv.FormatInt(n, 10), true
}

// Meta binds encoded events to their source.
type Meta struct {
	PodUID      string
	SourceEpoch string    // collector source epoch; makes pids unambiguous across restarts
	BootWall    time.Time // wall-clock instant of CLOCK_BOOTTIME zero on the node
}

var ErrMeta = errors.New("syscalls: invalid encoding metadata")

const maxDuration = artifact.MaxSyscallDurationNS // schema maximum (JSON safe integer)

type identity = artifact.SyscallMetadataIdentity
type event = artifact.SyscallMetadataEvent

// EncodeJSONLines writes one schema event per call, each ending in '\n',
// stamped at m.BootWall plus the call's boot-clock time.
func EncodeJSONLines(w io.Writer, calls []Call, m Meta) error {
	if m.BootWall.IsZero() {
		return ErrMeta
	}
	for _, c := range calls {
		b, err := AppendEvent(nil, c, m.BootWall.Add(time.Duration(c.Time())), m.PodUID, m.SourceEpoch)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// AppendEvent appends one schema event line for c observed at at. Traceloop
// has no thread id, so thread_ref equals process_ref. Nonreturning calls
// have outcome "unknown" (the schema has no nonreturning outcome).
func AppendEvent(b []byte, c Call, at time.Time, podUID, sourceEpoch string) ([]byte, error) {
	if podUID == "" || len(podUID) > 64 || sourceEpoch == "" || len(sourceEpoch) > 112 || at.IsZero() {
		return nil, ErrMeta
	}
	ref := "pid:" + strconv.FormatUint(uint64(c.PID), 10) + "@" + sourceEpoch
	ev := event{
		Identity:  identity{ProcessRef: ref, ThreadRef: ref, PodUID: podUID},
		Syscall:   Name(c.Number),
		ABI:       ABI,
		Timestamp: at.UTC().Format(time.RFC3339Nano),
	}
	switch c.Status {
	case Returned:
		ev.Outcome = "success"
		if name, failed := Errno(c.Ret); failed {
			ev.Outcome, ev.Errno = "error", name
		}
		if c.ExitedBoot >= c.EnteredBoot && c.ExitedBoot-c.EnteredBoot <= maxDuration {
			d := c.ExitedBoot - c.EnteredBoot
			ev.DurationNS = &d
		}
	case NoReturn:
		ev.Outcome = "unknown"
	case Unfinished:
		ev.Outcome = "unfinished"
	case Unmatched:
		ev.Outcome = "unmatched"
	default:
		return nil, ErrRecord
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	return append(append(b, line...), '\n'), nil
}

// Numbers resolves sorted syscall names for this build's ABI. An unknown
// name refuses the whole selection.
func Numbers(names []string) ([]uint16, bool) {
	if len(names) == 0 {
		return nil, true
	}
	out := make([]uint16, 0, len(names))
	for _, n := range names {
		nr, ok := igsyscalls.GetSyscallNumberByName(n)
		if !ok || nr < 0 || nr > 0xffff {
			return nil, false
		}
		out = append(out, uint16(nr))
	}
	return out, true
}
