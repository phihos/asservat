// Package linux holds the node collector's host probes (ADR-246, C-23). The
// file probes only read procfs/sysfs and statfs well-known paths; ProbeBPF
// in bpf_linux.go loads one trivial program and is called only by the
// privileged collector process, never by tests.
package linux

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"asservat.local/asservat/internal/domain/collector"
)

// Filesystem magic numbers (linux/magic.h).
const (
	magicCgroup2 = 0x63677270
	magicDebugFS = 0x64626720
	magicTraceFS = 0x74726163
	magicBPFFS   = 0xcafe4a11
)

// maxProcesses bounds the /proc scan for runtime and host-PID detection.
const maxProcesses = 8192

// FileProbe reads facts under Root ("/" in the collector).
type FileProbe struct {
	Root   string
	statfs func(path string) (int64, error)
}

func NewFileProbe(root string) FileProbe { return FileProbe{Root: root, statfs: statfsType} }

func (p FileProbe) path(rel string) string { return filepath.Join(p.Root, rel) }

func readSmall(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, max+1)
	n, err := f.Read(b)
	if err != nil && n == 0 {
		return nil, err
	}
	if n > max {
		return nil, fs.ErrInvalid
	}
	return bytes.TrimSpace(b[:n]), nil
}

// BootID reads the kernel boot ID (a UUID string).
func (p FileProbe) BootID() (string, error) {
	b, err := readSmall(p.path("proc/sys/kernel/random/boot_id"), 64)
	if err != nil || len(b) != 36 {
		return "", fs.ErrInvalid
	}
	return string(b), nil
}

func (p FileProbe) magic(path string, want int64) collector.Support {
	m, err := p.statfs(p.path(path))
	switch {
	case err == nil && m == want:
		return collector.Supported
	case err == nil, os.IsNotExist(err):
		return collector.Unsupported
	case os.IsPermission(err):
		return collector.Denied
	}
	return collector.SupportUnknown
}

// Facts returns every file-observable fact. BPF, TCX, TC and Engine stay
// unknown here; the collector fills them from ProbeBPF and the engine.
func (p FileProbe) Facts() collector.Facts {
	f := collector.Facts{BPF: collector.SupportUnknown, TCX: collector.SupportUnknown, TC: collector.SupportUnknown, Runtime: collector.RuntimeUnknown}
	if b, err := readSmall(p.path("proc/sys/kernel/osrelease"), 128); err == nil {
		f.KernelRelease = string(b)
		f.Kernel, _ = collector.ParseKernelRelease(f.KernelRelease)
	}
	switch st, err := os.Stat(p.path("sys/kernel/btf/vmlinux")); {
	case err == nil && st.Mode().IsRegular() && st.Size() > 0:
		f.BTF = collector.Supported
	case err == nil, os.IsNotExist(err):
		f.BTF = collector.Unsupported
	case os.IsPermission(err):
		f.BTF = collector.Denied
	default:
		f.BTF = collector.SupportUnknown
	}
	f.CgroupV2 = p.magic("sys/fs/cgroup", magicCgroup2)
	f.DebugFS = p.magic("sys/kernel/debug", magicDebugFS)
	f.TraceFS = p.magic("sys/kernel/tracing", magicTraceFS)
	if f.TraceFS != collector.Supported {
		if alt := p.magic("sys/kernel/debug/tracing", magicTraceFS); alt == collector.Supported {
			f.TraceFS = alt
		}
	}
	f.BPFFS = p.magic("sys/fs/bpf", magicBPFFS)
	names := p.processNames()
	f.Runtime = collector.RuntimeFromProcesses(names)
	f.HostProcesses = collector.HostProcessesVisible(names)
	return f
}

// processNames reads /proc/<pid>/comm of at most maxProcesses processes.
func (p FileProbe) processNames() []string {
	entries, err := os.ReadDir(p.path("proc"))
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if len(names) >= maxProcesses {
			break
		}
		if _, err := strconv.ParseUint(e.Name(), 10, 32); err != nil || !e.IsDir() {
			continue
		}
		if b, err := readSmall(p.path("proc/"+e.Name()+"/comm"), 64); err == nil {
			names = append(names, string(b))
		}
	}
	return names
}
