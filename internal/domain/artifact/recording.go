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

const (
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
	Kind           string // "packetCapture"
	Profile        string // "networkHeaders"
	Composition    []byte
	Filter         *RecordingFilter `json:",omitempty"`
	DurationMillis int64
	MaxBytes       int64
	Snaplen        int
	// RequireApproval records that the installation required approval of
	// this recording (ADR-249); the recompiled plan binds it.
	RequireApproval bool `json:",omitempty"`
}

// Valid checks the recording's own bounds.
func (r *Recording) Valid() bool {
	if r == nil || r.Kind != "packetCapture" || r.Profile != "networkHeaders" || len(r.Composition) < 2 || len(r.Composition) > maxRecordingComposition ||
		r.DurationMillis < 1000 || r.DurationMillis > maxRecordingDurationMillis || r.MaxBytes < minRecordingBytes || r.MaxBytes > RecordingNativeLimit || r.Snaplen != RecordingSnaplen {
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
