package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/collector"
)

// The probe reads a synthetic root; no host file, statfs or BPF call is made.
func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestFileProbeReadsSyntheticRoot(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"proc/sys/kernel/osrelease":      "6.11.0-1018-azure\n",
		"proc/sys/kernel/random/boot_id": "0f1e2d3c-4b5a-4968-8776-655443322110\n",
		"sys/kernel/btf/vmlinux":         "BTF",
		"proc/1/comm":                    "systemd\n",
		"proc/412/comm":                  "containerd\n",
		"proc/530/comm":                  "kubelet\n",
		"proc/self/comm":                 "asservat\n",
		"proc/notapid/comm":              "crio\n",
	})
	magics := map[string]int64{"sys/fs/cgroup": magicCgroup2, "sys/kernel/debug": magicDebugFS, "sys/kernel/tracing": 0x62656572, "sys/kernel/debug/tracing": magicTraceFS, "sys/fs/bpf": magicBPFFS}
	p := FileProbe{Root: root, statfs: func(path string) (int64, error) {
		rel := strings.TrimPrefix(path, root+"/")
		if m, ok := magics[rel]; ok {
			return m, nil
		}
		return 0, os.ErrNotExist
	}}
	f := p.Facts()
	if f.KernelRelease != "6.11.0-1018-azure" || f.Kernel != (collector.KernelVersion{Major: 6, Minor: 11, Patch: 0}) {
		t.Fatalf("kernel %q %v", f.KernelRelease, f.Kernel)
	}
	want := map[string][2]collector.Support{"btf": {f.BTF, collector.Supported}, "cgroup": {f.CgroupV2, collector.Supported}, "debugfs": {f.DebugFS, collector.Supported},
		"tracefs via debugfs": {f.TraceFS, collector.Supported}, "bpffs": {f.BPFFS, collector.Supported}, "host processes": {f.HostProcesses, collector.Supported},
		"bpf left to ProbeBPF": {f.BPF, collector.SupportUnknown}, "tcx left to ProbeBPF": {f.TCX, collector.SupportUnknown}}
	for name, got := range want {
		if got[0] != got[1] {
			t.Fatalf("%s: %s", name, got[0])
		}
	}
	if f.Runtime != collector.RuntimeContainerd {
		t.Fatalf("runtime %s (a non-numeric /proc entry must be ignored)", f.Runtime)
	}
	if boot, err := p.BootID(); err != nil || boot != "0f1e2d3c-4b5a-4968-8776-655443322110" {
		t.Fatalf("boot %q %v", boot, err)
	}

	// A container view: cgroup v1 tmpfs, no BTF, no debug/trace mounts and no
	// host processes. Every missing fact is reported, none assumed.
	bare := fakeRoot(t, map[string]string{"proc/sys/kernel/osrelease": "5.4.0-200-generic", "proc/1/comm": "asservat"})
	f = FileProbe{Root: bare, statfs: func(path string) (int64, error) {
		if strings.HasSuffix(path, "sys/fs/cgroup") {
			return 0x01021994, nil
		}
		return 0, os.ErrPermission
	}}.Facts()
	if f.BTF != collector.Unsupported || f.CgroupV2 != collector.Unsupported || f.DebugFS != collector.Denied || f.TraceFS != collector.Denied ||
		f.HostProcesses != collector.Unsupported || f.Runtime != collector.RuntimeUnknown || f.Kernel.AtLeast(5, 15) {
		t.Fatalf("bare facts %+v", f)
	}
	reasons := collector.Assess(f)[0].Reasons
	for _, r := range []collector.Reason{collector.ReasonKernelTooOld, collector.ReasonBTFMissing, collector.ReasonCgroupV1, collector.ReasonHostProcessesHidden, collector.ReasonRuntimeUnknown} {
		found := false
		for _, x := range reasons {
			found = found || x == r
		}
		if !found {
			t.Fatalf("missing reason %s in %v", r, reasons)
		}
	}
	if _, err := (FileProbe{Root: bare}).BootID(); err == nil {
		t.Fatal("missing boot ID accepted")
	}
}
