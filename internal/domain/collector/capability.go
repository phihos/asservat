// Package collector holds the pure node-collector values (ADR-246): kernel
// capability facts and their assessment, node ring/frozen/upload budgets,
// the status cadence and the closed work/receipt vocabulary of the private
// node work channel. It performs no I/O and reads no clock.
package collector

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrInvalid  = errors.New("collector: invalid value")
	ErrExceeded = errors.New("collector: budget exceeded")
)

// Support is one probed kernel or host facility. Denied means the probe ran
// without the privilege it needs; it is never reported as Unsupported.
type Support string

const (
	SupportUnknown Support = "unknown"
	Supported      Support = "supported"
	Unsupported    Support = "unsupported"
	Denied         Support = "denied"
)

func (s Support) Valid() bool {
	return s == SupportUnknown || s == Supported || s == Unsupported || s == Denied
}

// KernelVersion is the numeric prefix of a kernel release string.
type KernelVersion struct{ Major, Minor, Patch int }

func (v KernelVersion) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

func (v KernelVersion) AtLeast(major, minor int) bool {
	return v.Major > major || (v.Major == major && v.Minor >= minor)
}

// ParseKernelRelease reads the leading "major.minor[.patch]" of a release
// string such as "6.8.0-1017-azure" or "6.11.0+". The suffix is ignored; the
// whole string must be short printable ASCII.
func ParseKernelRelease(release string) (KernelVersion, error) {
	if release == "" || len(release) > 128 {
		return KernelVersion{}, ErrInvalid
	}
	for i := 0; i < len(release); i++ {
		if release[i] < 0x21 || release[i] > 0x7e {
			return KernelVersion{}, ErrInvalid
		}
	}
	end := len(release)
	for i := 0; i < len(release); i++ {
		if (release[i] < '0' || release[i] > '9') && release[i] != '.' {
			end = i
			break
		}
	}
	parts := strings.Split(release[:end], ".")
	if len(parts) < 2 || len(parts) > 3 {
		return KernelVersion{}, ErrInvalid
	}
	var n [3]int
	for i, p := range parts {
		if p == "" || len(p) > 4 || (len(p) > 1 && p[0] == '0') {
			return KernelVersion{}, ErrInvalid
		}
		v, err := strconv.Atoi(p)
		if err != nil {
			return KernelVersion{}, ErrInvalid
		}
		n[i] = v
	}
	if n[0] < 2 {
		return KernelVersion{}, ErrInvalid
	}
	return KernelVersion{n[0], n[1], n[2]}, nil
}

// Runtime is the container runtime whose daemon process the node observes.
type Runtime string

const (
	RuntimeUnknown    Runtime = "unknown"
	RuntimeContainerd Runtime = "containerd"
	RuntimeCRIO       Runtime = "cri-o"
)

// Engine is the embedded observation engine (S1): whether it is linked into
// this build, whether its runtime initialized and its pinned version.
type Engine struct {
	Linked      bool
	Initialized bool
	Version     string
}

// Facts are one node's probed facts. Nothing here is a capture or a promise
// that a hook works for a particular Pod; see Assess.
type Facts struct {
	KernelRelease string
	Kernel        KernelVersion
	BTF           Support // /sys/kernel/btf/vmlinux
	CgroupV2      Support // unified hierarchy at /sys/fs/cgroup
	BPF           Support // a minimal sched_cls program loads
	TCX           Support // TCX link creation reaches the device check
	TC            Support // sched_cls (cls_bpf/clsact path) is loadable
	DebugFS       Support
	TraceFS       Support
	BPFFS         Support
	HostProcesses Support // host PID namespace processes are visible
	Runtime       Runtime
	Engine        Engine
}

// Reason is a closed cause of AdapterUnavailable.
type Reason string

const (
	ReasonKernelTooOld           Reason = "KernelTooOld"
	ReasonBTFMissing             Reason = "BTFMissing"
	ReasonCgroupV1               Reason = "CgroupV2Missing"
	ReasonBPFUnavailable         Reason = "BPFUnavailable"
	ReasonNoTrafficHook          Reason = "TrafficHookUnavailable"
	ReasonTracingUnavailable     Reason = "TracingUnavailable"
	ReasonHostProcessesHidden    Reason = "HostProcessesHidden"
	ReasonRuntimeUnknown         Reason = "RuntimeUnknown"
	ReasonEngineUnavailable      Reason = "EngineUnavailable"
	ReasonRecorderNotImplemented Reason = "RecorderNotImplemented"
	// Work receipts only.
	ReasonWorkExpired Reason = "WorkExpired"
	ReasonWorkUnknown Reason = "WorkUnknown"
	// Packet capture receipts and results (ADR-248).
	ReasonTargetNotFound    Reason = "TargetNotFound"
	ReasonTargetHostNet     Reason = "TargetHostNetwork"
	ReasonFilterUnsupported Reason = "FilterUnsupported"
	ReasonCaptureBusy       Reason = "CaptureBusy"
	ReasonCaptureFailed     Reason = "CaptureFailed"
)

func (r Reason) Valid() bool {
	switch r {
	case ReasonKernelTooOld, ReasonBTFMissing, ReasonCgroupV1, ReasonBPFUnavailable, ReasonNoTrafficHook, ReasonTracingUnavailable, ReasonHostProcessesHidden, ReasonRuntimeUnknown, ReasonEngineUnavailable, ReasonRecorderNotImplemented, ReasonWorkExpired, ReasonWorkUnknown,
		ReasonTargetNotFound, ReasonTargetHostNet, ReasonFilterUnsupported, ReasonCaptureBusy, ReasonCaptureFailed:
		return true
	}
	return false
}

// Mechanism is a node-side recording mechanism.
type Mechanism string

const (
	MechanismPacket  Mechanism = "packetCapture"
	MechanismSyscall Mechanism = "syscallTrace"
)

// Hook is the traffic attachment a packet recorder would use.
type Hook string

const (
	HookNone Hook = ""
	HookTCX  Hook = "tcx"
	HookTC   Hook = "tc"
)

// Adapter is the outcome reported per mechanism.
type Adapter string

const (
	AdapterAvailable   Adapter = "Available"
	AdapterUnavailable Adapter = "AdapterUnavailable"
)

// MinimumKernel is the lowest kernel the node adapters accept (plan §2 P1).
var MinimumKernel = KernelVersion{5, 15, 0}

// Availability is one mechanism's assessment. Prerequisites reports whether
// every probed fact the mechanism needs is present; Adapter is Available only
// when the prerequisites hold and the recorder is implemented.
type Availability struct {
	Mechanism     Mechanism
	Prerequisites bool
	Adapter       Adapter
	Hook          Hook
	Reasons       []Reason
}

// implemented lists recorders this build provides. Increment 4 (ADR-248)
// provides the manual networkHeaders packet recorder; it still needs a linked
// and initialized engine (ReasonEngineUnavailable otherwise). Syscall
// recording arrives with increment 10.
var implemented = map[Mechanism]bool{MechanismPacket: true}

// Assess derives each mechanism's availability from the facts. A fact that
// is unknown or denied counts as missing; nothing is assumed.
func Assess(f Facts) []Availability {
	common := []Reason{}
	if !f.Kernel.AtLeast(MinimumKernel.Major, MinimumKernel.Minor) {
		common = append(common, ReasonKernelTooOld)
	}
	if f.BTF != Supported {
		common = append(common, ReasonBTFMissing)
	}
	if f.CgroupV2 != Supported {
		common = append(common, ReasonCgroupV1)
	}
	if f.BPF != Supported {
		common = append(common, ReasonBPFUnavailable)
	}
	if f.HostProcesses != Supported {
		common = append(common, ReasonHostProcessesHidden)
	}
	if f.Runtime != RuntimeContainerd && f.Runtime != RuntimeCRIO {
		common = append(common, ReasonRuntimeUnknown)
	}
	if !f.Engine.Linked || !f.Engine.Initialized {
		common = append(common, ReasonEngineUnavailable)
	}
	// The packet recorder is Inspektor Gadget's tcpdump gadget (ADR-248),
	// which attaches classic tc (clsact) classifiers; TCX alone is not
	// enough for it.
	packet := Availability{Mechanism: MechanismPacket, Reasons: append([]Reason{}, common...)}
	if f.TC == Supported {
		packet.Hook = HookTC
	} else {
		packet.Reasons = append(packet.Reasons, ReasonNoTrafficHook)
	}
	syscall := Availability{Mechanism: MechanismSyscall, Reasons: append([]Reason{}, common...)}
	if f.TraceFS != Supported {
		syscall.Reasons = append(syscall.Reasons, ReasonTracingUnavailable)
	}
	out := []Availability{packet, syscall}
	for i := range out {
		out[i].Prerequisites = len(out[i].Reasons) == 0
		out[i].Adapter = AdapterUnavailable
		if !implemented[out[i].Mechanism] {
			out[i].Reasons = append(out[i].Reasons, ReasonRecorderNotImplemented)
		} else if out[i].Prerequisites {
			out[i].Adapter = AdapterAvailable
		}
	}
	return out
}

// RuntimeFromProcesses classifies the runtime from observed process names
// (/proc/<pid>/comm). Exactly one known daemon must be present.
func RuntimeFromProcesses(names []string) Runtime {
	containerd, crio := false, false
	for _, n := range names {
		switch strings.TrimSpace(n) {
		case "containerd":
			containerd = true
		case "crio":
			crio = true
		}
	}
	switch {
	case containerd && !crio:
		return RuntimeContainerd
	case crio && !containerd:
		return RuntimeCRIO
	}
	return RuntimeUnknown
}

// HostProcessesVisible reports whether the node agent's processes are in view,
// which only holds in the host PID namespace.
func HostProcessesVisible(names []string) Support {
	for _, n := range names {
		if strings.TrimSpace(n) == "kubelet" {
			return Supported
		}
	}
	return Unsupported
}
