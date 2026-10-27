package collector

import "time"

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
)

func (k WorkKind) Valid() bool {
	return k == WorkArmSource || k == WorkStopSource || k == WorkSnapshot || k == WorkPeerGeneration
}

// Work is one item the connector queued for one node process. Sequence is
// assigned per node process and only grows; NotAfter bounds when the node may
// still act on it.
type Work struct {
	ID       string
	Sequence uint64
	Kind     WorkKind
	NotAfter time.Time
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
	case !w.Kind.Valid():
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
}
