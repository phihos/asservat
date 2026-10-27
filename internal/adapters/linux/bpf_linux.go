//go:build linux

package linux

import (
	"errors"
	"math"

	"asservat.local/asservat/internal/domain/collector"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func statfsType(path string) (int64, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return 0, err
	}
	return int64(s.Type), nil
}

func support(err error) collector.Support {
	switch {
	case err == nil:
		return collector.Supported
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return collector.Denied
	case errors.Is(err, ebpf.ErrNotSupported), errors.Is(err, unix.EINVAL):
		return collector.Unsupported
	}
	return collector.SupportUnknown
}

// ProbeBPF loads one two-instruction sched_cls program (return 0), and
// creates a TCX ingress link for it against an interface index that cannot
// exist: a kernel with TCX reaches the device lookup and answers ENODEV
// without attaching anything; a kernel without TCX rejects the link type.
// The program is closed before returning. This needs CAP_BPF (and
// CAP_NET_ADMIN for the link) and runs only in the collector process.
func ProbeBPF() (bpf, tc, tcx collector.Support) {
	_ = rlimit.RemoveMemlock() // needed only before Linux 5.11 memcg accounting
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "Apache-2.0",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
	if err != nil {
		s := support(err)
		return s, s, s
	}
	defer prog.Close()
	l, err := link.AttachTCX(link.TCXOptions{Interface: math.MaxInt32, Program: prog, Attach: ebpf.AttachTCXIngress})
	switch {
	case err == nil:
		l.Close()
		tcx = collector.Supported
	case errors.Is(err, unix.ENODEV):
		tcx = collector.Supported
	default:
		tcx = support(err)
	}
	return collector.Supported, collector.Supported, tcx
}
