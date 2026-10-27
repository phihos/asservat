package collector

import (
	"slices"
	"testing"
)

func TestParseKernelRelease(t *testing.T) {
	for in, want := range map[string]KernelVersion{
		"6.8.0-1017-azure":   {6, 8, 0},
		"6.11.0-1018-azure":  {6, 11, 0},
		"5.15.0":             {5, 15, 0},
		"6.6":                {6, 6, 0},
		"7.2.9-2-cachyos":    {7, 2, 9},
		"4.19.0+":            {4, 19, 0},
		"6.1.0-rc3":          {6, 1, 0},
		"6.12.10-200.fc41.x": {6, 12, 10},
	} {
		got, err := ParseKernelRelease(in)
		if err != nil || got != want {
			t.Fatalf("%q: got %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "6", "linux-6.8", "6..8", "6.8.0.1", "06.8", "1.2.3", "6.8 0", "6.8\n", "6.99999.0", string(make([]byte, 129))} {
		if _, err := ParseKernelRelease(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

func passing() Facts {
	return Facts{KernelRelease: "6.8.0", Kernel: KernelVersion{6, 8, 0}, BTF: Supported, CgroupV2: Supported, BPF: Supported, TCX: Supported, TC: Supported,
		DebugFS: Supported, TraceFS: Supported, BPFFS: Supported, HostProcesses: Supported, Runtime: RuntimeContainerd, Engine: Engine{Linked: true, Initialized: true, Version: "v0.57.0"}}
}

func TestAssessPassingProbeOffersOnlyThePacketRecorder(t *testing.T) {
	out := Assess(passing())
	if len(out) != 2 || out[0].Mechanism != MechanismPacket || out[1].Mechanism != MechanismSyscall {
		t.Fatalf("mechanisms %+v", out)
	}
	if a := out[0]; !a.Prerequisites || a.Adapter != AdapterAvailable || len(a.Reasons) != 0 || a.Hook != HookTC {
		t.Fatalf("packet recorder (ADR-248, tc hook of the gadget): %+v", a)
	}
	if a := out[1]; !a.Prerequisites || a.Adapter != AdapterUnavailable || !slices.Equal(a.Reasons, []Reason{ReasonRecorderNotImplemented}) {
		t.Fatalf("increment 4 has no syscall recorder: %+v", a)
	}
}

func TestAssessReportsEveryMissingFact(t *testing.T) {
	f := passing()
	f.TCX = Unsupported
	if a := Assess(f)[0]; a.Hook != HookTC || !a.Prerequisites {
		t.Fatalf("the gadget needs tc, not TCX: %+v", a)
	}
	cases := []struct {
		edit   func(*Facts)
		reason Reason
		packet bool
		sys    bool
	}{
		{func(f *Facts) { f.Kernel = KernelVersion{5, 10, 0} }, ReasonKernelTooOld, true, true},
		{func(f *Facts) { f.BTF = Unsupported }, ReasonBTFMissing, true, true},
		{func(f *Facts) { f.CgroupV2 = SupportUnknown }, ReasonCgroupV1, true, true},
		{func(f *Facts) { f.BPF = Denied }, ReasonBPFUnavailable, true, true},
		{func(f *Facts) { f.TCX, f.TC = Denied, Unsupported }, ReasonNoTrafficHook, true, false},
		{func(f *Facts) { f.TraceFS = Unsupported }, ReasonTracingUnavailable, false, true},
		{func(f *Facts) { f.HostProcesses = Unsupported }, ReasonHostProcessesHidden, true, true},
		{func(f *Facts) { f.Runtime = RuntimeUnknown }, ReasonRuntimeUnknown, true, true},
		{func(f *Facts) { f.Engine.Initialized = false }, ReasonEngineUnavailable, true, true},
		{func(f *Facts) { f.Engine = Engine{} }, ReasonEngineUnavailable, true, true},
	}
	for _, c := range cases {
		f := passing()
		c.edit(&f)
		out := Assess(f)
		for i, want := range []bool{c.packet, c.sys} {
			has := slices.Contains(out[i].Reasons, c.reason)
			if has != want || (want && (out[i].Prerequisites || out[i].Adapter != AdapterUnavailable)) {
				t.Fatalf("%s mechanism %d: %+v", c.reason, i, out[i])
			}
		}
	}
}

func TestRuntimeAndHostProcesses(t *testing.T) {
	if RuntimeFromProcesses([]string{"systemd", "containerd\n", "kubelet"}) != RuntimeContainerd || RuntimeFromProcesses([]string{"crio"}) != RuntimeCRIO {
		t.Fatal("runtime")
	}
	for _, names := range [][]string{nil, {"containerd", "crio"}, {"containerd-shim"}, {"dockerd"}} {
		if RuntimeFromProcesses(names) != RuntimeUnknown {
			t.Fatalf("%v classified", names)
		}
	}
	if HostProcessesVisible([]string{"asservat"}) != Unsupported || HostProcessesVisible([]string{"kubelet\n"}) != Supported {
		t.Fatal("host processes")
	}
}
