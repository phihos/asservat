package artifact

// ADR-248: the accepted node recording of a manual networkHeaders packet
// capture. It is part of the expectation, so the expectation digest binds the
// exact hub-compiled filter program, duration and output cap the node runs.
// It confers no authority; the start still needs the committed local start.

// RecordingNativeLimit is the interim per-capture output cap: one storage
// frame (8 MiB). The streaming lift is a named follow-up.
const RecordingNativeLimit = FrameBytes

// RecordingSnaplen is the gadget's capture length for networkHeaders:
// Ethernet (14) + the largest IPv4 header (60) + the largest TCP header (60).
const RecordingSnaplen = 14 + 60 + 60

// MaxRecordingEventsPerSecond is the compiler's syscall rate bound
// (maxEventsPerSecond 1 to 100,000), shared by the node payload.
const MaxRecordingEventsPerSecond = 100_000

// MaxRawSnaplen is the largest raw packet prefix the pinned gadget captures
// (ADR-279); larger caps are refused, never narrowed silently.
const MaxRawSnaplen = 1500

// maxRawRecordingMillis bounds a finite raw recording (ADR-261/279).
const maxRawRecordingMillis = 15_000

// RecordingSyscallSnaplen is the fixed per-call metadata record size of a
// syscall recording (internal/adapters/syscalls.RecordSize).
const RecordingSyscallSnaplen = 32

const (
	// maxSyscallRecordingMillis matches the compiler's finite syscall
	// after-window bound (ADR-273, specs/syscalls.md).
	maxSyscallRecordingMillis  = 60 * 1000
	maxRecordingDurationMillis = 5 * 60 * 1000
	minRecordingBytes          = 64 << 10
	maxRecordingProgram        = 256
	maxRecordingComposition    = 32 << 10
)

// FilterInstruction is one classic BPF instruction (struct sock_filter).
type FilterInstruction struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// RecordingFilter is the frozen hub-compiled filter of the recording's
// packet action: the normalized expression and its libpcap program.
type RecordingFilter struct {
	Expression string
	Program    []FilterInstruction
}

// Recording is the node work of an accepted recorder capture. Composition is
// the canonical JSON of the authored profile composition (the planning layer
// owns its type), so the hub can recompile the exact accepted plan.
type Recording struct {
	Kind           string // "packetCapture" or "syscallTrace"
	Profile        string // "networkHeaders", "rawPackets" or "metadata"
	Composition    []byte
	Filter         *RecordingFilter `json:",omitempty"`
	DurationMillis int64
	MaxBytes       int64
	Snaplen        int
	// RequireApproval records that the installation required approval of
	// this recording (ADR-249); the recompiled plan binds it.
	RequireApproval bool `json:",omitempty"`
	// Syscalls is a finite syscall metadata recording's selection and
	// budgets (B3); nil for packets, so packet expectation digests are
	// unchanged.
	Syscalls *RecordingSyscalls `json:",omitempty"`
	// ProtocolSnaplen are a rawPackets recording's per-transport byte caps
	// over Snaplen (ADR-279); nil otherwise, so other digests are unchanged.
	ProtocolSnaplen *RecordingProtocolSnaplen `json:",omitempty"`
}

// RecordingProtocolSnaplen caps the captured prefix per transport; zero
// means the recording's default Snaplen applies.
type RecordingProtocolSnaplen struct {
	TCP  int `json:",omitempty"`
	UDP  int `json:",omitempty"`
	ICMP int `json:",omitempty"`
}

func (p *RecordingProtocolSnaplen) valid() bool {
	if p == nil {
		return true
	}
	for _, v := range []int{p.TCP, p.UDP, p.ICMP} {
		if v < 0 || v > MaxRawSnaplen {
			return false
		}
	}
	return p.TCP+p.UDP+p.ICMP > 0
}

// RecordingSyscalls mirrors the source collector.SyscallFilter for a finite
// manual run: sorted names (empty records every call) and its budgets.
type RecordingSyscalls struct {
	Names              []string `json:",omitempty"`
	ErrorsOnly         bool     `json:",omitempty"`
	MaxEvents          int64
	MaxEventsPerSecond int64
	MaxTrackedThreads  int64
}

func (s *RecordingSyscalls) valid() bool {
	if s == nil || len(s.Names) > 128 || s.MaxEvents < 1 || s.MaxEvents > 1_000_000 || s.MaxEventsPerSecond < 1 || s.MaxEventsPerSecond > MaxRecordingEventsPerSecond || s.MaxTrackedThreads < 1 || s.MaxTrackedThreads > 16_384 {
		return false
	}
	for i, n := range s.Names {
		if n == "" || len(n) > 64 || i > 0 && s.Names[i-1] >= n {
			return false
		}
	}
	return true
}

// Valid checks the recording's own bounds.
func (r *Recording) Valid() bool {
	if r == nil || len(r.Composition) < 2 || len(r.Composition) > maxRecordingComposition || r.DurationMillis < 1000 || r.MaxBytes < minRecordingBytes || r.MaxBytes > RecordingNativeLimit {
		return false
	}
	switch {
	case r.Kind == "syscallTrace":
		return r.Profile == "metadata" && r.Filter == nil && r.Snaplen == RecordingSyscallSnaplen && r.DurationMillis <= maxSyscallRecordingMillis && r.Syscalls.valid()
	case r.Kind == "packetCapture" && r.Profile == "rawPackets":
		if r.Syscalls != nil || r.DurationMillis > maxRawRecordingMillis || r.Snaplen < 1 || r.Snaplen > MaxRawSnaplen || !r.ProtocolSnaplen.valid() {
			return false
		}
	case r.Kind != "packetCapture" || r.Profile != "networkHeaders" || r.Syscalls != nil || r.ProtocolSnaplen != nil || r.DurationMillis > maxRecordingDurationMillis || r.Snaplen != RecordingSnaplen:
		return false
	}
	if f := r.Filter; f != nil {
		if len(f.Expression) < 1 || len(f.Expression) > 4096 || len(f.Program) < 1 || len(f.Program) > maxRecordingProgram {
			return false
		}
	}
	return true
}

// Clone returns an independent copy.
func (r *Recording) Clone() *Recording {
	if r == nil {
		return nil
	}
	out := *r
	out.Composition = append([]byte(nil), r.Composition...)
	if r.Filter != nil {
		f := *r.Filter
		f.Program = append([]FilterInstruction(nil), r.Filter.Program...)
		out.Filter = &f
	}
	if r.Syscalls != nil {
		s := *r.Syscalls
		s.Names = append([]string(nil), r.Syscalls.Names...)
		out.Syscalls = &s
	}
	if r.ProtocolSnaplen != nil {
		p := *r.ProtocolSnaplen
		out.ProtocolSnaplen = &p
	}
	return &out
}

// recorderActionID is the generated action ID shape of a composed recorder
// action ("a" + 24 lowercase hex digits, ADR-243).
func recorderActionID(s string) bool {
	if len(s) != 25 || s[0] != 'a' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
