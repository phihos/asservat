package collector

import (
	"time"

	"asservat.local/asservat/internal/domain/planning"
)

// Channel timing (ADR-246, plan S9). One batched report per node every 15
// seconds plus an immediate report after enrollment and on stop/loss; a node
// whose last report is older than three intervals is no longer current.
const (
	StatusInterval       = 15 * time.Second
	StatusStaleAfter     = 3 * StatusInterval
	StatusMinimumSpacing = time.Second
	PollHold             = 25 * time.Second
	CertificateLifetime  = 20 * time.Minute
	CertificateRenewal   = time.Minute
	MaxQueuedWork        = 64
	MaxWorkPerPoll       = 16
	MaxReceipts          = 64
)

// StatusCadence decides when the next report is due. Urgent reports (stop,
// loss) are sent at once but never closer than StatusMinimumSpacing, which
// the connector also enforces.
type StatusCadence struct {
	last    time.Time
	sent    bool
	pending bool
}

func (s *StatusCadence) Urgent() { s.pending = true }

// Wait returns how long until a report is due at now; zero means send now.
func (s *StatusCadence) Wait(now time.Time) time.Duration {
	if !s.sent {
		return 0
	}
	next := s.last.Add(StatusInterval)
	if s.pending {
		next = s.last.Add(StatusMinimumSpacing)
	}
	if !now.Before(next) {
		return 0
	}
	return next.Sub(now)
}

// Sent records a successful report at the time it was sent.
func (s *StatusCadence) Sent(at time.Time) {
	s.last, s.sent, s.pending = at, true, false
}

// WorkKind is the closed set of connector-to-node work items (I-02).
type WorkKind string

const (
	WorkArmSource      WorkKind = "armSource"
	WorkStopSource     WorkKind = "stopSource"
	WorkSnapshot       WorkKind = "snapshot"
	WorkPeerGeneration WorkKind = "peerGeneration"
	// WorkPacketCapture is one finite manual networkHeaders capture
	// (ADR-248). It is the only kind with a typed payload in this version.
	WorkPacketCapture    WorkKind = "packetCapture"
	WorkPacketSource     WorkKind = "packetSource"
	WorkStopPacketSource WorkKind = "stopPacketSource"
)

func (k WorkKind) Valid() bool {
	return k == WorkArmSource || k == WorkStopSource || k == WorkSnapshot || k == WorkPeerGeneration || k == WorkPacketCapture || k == WorkPacketSource || k == WorkStopPacketSource
}

// Work is one item the connector queued for one node process. Sequence is
// assigned per node process and only grows; NotAfter bounds when the node may
// still act on it.
type Work struct {
	ID       string
	Sequence uint64
	Kind     WorkKind
	NotAfter time.Time
	// Packet is the payload of exactly the packetCapture kind.
	Packet     *PacketCapture
	Source     *PacketSource
	StopSource *SourceBinding
}

// Packet capture bounds (ADR-248). The output cap is the interim 8 MiB per
// capture (one storage frame); the streaming lift is a named follow-up.
const (
	MaxPacketCaptureBytes    = 8 << 20
	MinPacketCaptureBytes    = 64 << 10
	MaxPacketCaptureDuration = 5 * time.Minute
	// PacketCaptureStartWithin bounds how long after queueing the node may
	// still start the capture.
	PacketCaptureStartWithin = 10 * time.Second
)

// PacketCapture is one manual networkHeaders recording of one Pod: the
// hub-compiled classic BPF program (empty: all traffic of the Pod) and its
// digest, how long to record and the output cap. The node never compiles.
type PacketCapture struct {
	CaptureID     string
	PodUID        string
	Program       []planning.BPFInstruction
	ProgramDigest [32]byte
	Duration      time.Duration
	MaxBytes      int64
	Observation   *ObservationPermit
}

// Valid checks the payload's own bounds; the node checks the digest against
// the program it received.
func (p PacketCapture) Valid() bool {
	if o := p.Observation; o != nil && (!o.ValidFinite(o.StartedAt) || o.Duration != p.Duration || o.Binding.CaptureID != p.CaptureID || o.Binding.PodUID != p.PodUID || o.Binding.ProgramDigest != p.ProgramDigest) {
		return false
	}
	return validUUID(p.CaptureID) && validUUID(p.PodUID) && len(p.Program) <= planning.MaxFilterInstructions && (len(p.Program) == 0) == (p.ProgramDigest == [32]byte{}) &&
		p.Duration >= time.Second && p.Duration <= MaxPacketCaptureDuration && p.Duration%time.Millisecond == 0 && p.MaxBytes >= MinPacketCaptureBytes && p.MaxBytes <= MaxPacketCaptureBytes
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// PacketResult is the node's account of one finished capture; the PCAPNG
// travels with it. Counters cover every frame the engine delivered.
type PacketResult struct {
	WorkID        string
	CaptureID     string
	StartedAt     time.Time
	EndedAt       time.Time
	Seen          uint64
	Retained      uint64
	Filtered      uint64
	Unsupported   uint64
	Fragment      uint64
	Extension     uint64
	Malformed     uint64
	OutputFull    uint64
	LostSamples   uint64
	WireBytes     uint64
	CapturedBytes int64
	Snaplen       int
	EngineVersion string
	ProgramDigest [32]byte
	// Failure is empty for a completed capture, otherwise why the engine
	// stopped (TargetNotFound, TargetHostNetwork or CaptureFailed); the
	// PCAPNG then holds what was retained before.
	Failure Reason
}

// Valid checks the result's internal consistency.
func (r PacketResult) Valid() bool {
	dropped := r.Filtered + r.Unsupported + r.Fragment + r.Extension + r.Malformed + r.OutputFull
	failure := r.Failure == "" || r.Failure == ReasonTargetNotFound || r.Failure == ReasonTargetHostNet || r.Failure == ReasonCaptureFailed
	return validUUID(r.WorkID) && validUUID(r.CaptureID) && !r.StartedAt.IsZero() && !r.EndedAt.Before(r.StartedAt) && r.Retained+dropped == r.Seen &&
		r.CapturedBytes > 0 && r.CapturedBytes <= MaxPacketCaptureBytes && r.Snaplen > 0 && r.Snaplen <= 1500 && len(r.EngineVersion) <= 64 && failure
}

// Outcome of one work item, reported in the next status.
type Outcome string

const (
	OutcomeAccepted Outcome = "accepted"
	OutcomeRefused  Outcome = "refused"
)

type Receipt struct {
	WorkID   string
	Sequence uint64
	Outcome  Outcome
	Reason   Reason
}

// Decide is the node's decision for one work item in this build: every kind
// needs a recorder, and none is implemented, so each item is refused with the
// recorder reason. Expired items are refused as well.
func Decide(w Work, now time.Time) Receipt {
	r := Receipt{WorkID: w.ID, Sequence: w.Sequence, Outcome: OutcomeRefused, Reason: ReasonRecorderNotImplemented}
	switch {
	case !w.Kind.Valid() || (w.Kind == WorkPacketCapture) != (w.Packet != nil) || w.Packet != nil && !w.Packet.Valid() ||
		(w.Kind == WorkPacketSource) != (w.Source != nil) || w.Source != nil && (!w.Source.Valid() || w.NotAfter.After(w.Source.Permit.DispatchUntil)) ||
		(w.Kind == WorkStopPacketSource) != (w.StopSource != nil) || w.StopSource != nil && !w.StopSource.Valid():
		r.Reason = ReasonWorkUnknown
	case !now.Before(w.NotAfter):
		r.Reason = ReasonWorkExpired
	}
	return r
}

// Identity is one attested node collector process. Node, Pod and boot values
// come from Kubernetes (TokenReview and live objects); Epoch is the process's
// random start identity, so a restart is a new collector generation.
type Identity struct {
	NodeName, NodeUID string
	PodName, PodUID   string
	BootID            string
	Epoch             string
	// Runtime is the kubelet-reported containerRuntimeVersion (for example
	// "containerd://2.1.3"), bounded text.
	Runtime string
}

// Report is one node status report.
type Report struct {
	Sequence   uint64
	ObservedAt time.Time
	Facts      Facts
	Mechanisms []Availability
	Budget     Usage
	Receipts   []Receipt
	Sources    []SourceStatus
}
