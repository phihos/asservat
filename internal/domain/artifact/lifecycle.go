package artifact

import (
	"slices"
	"strconv"
	"time"
)

// OngoingLifecycle is the accepted actionLifecycle provenance of one save from
// an ongoing recording source (REQ-LIF-005/006, ADR-244). It is independently
// constructed from the source session and snapshot admission, never copied from
// a writer's manifest. TriggeredAt of the expectation is the window anchor t0.
// It confers no authority over the source, its ring or a later save.
type OngoingLifecycle struct {
	TriggerKind     string // policy, manual or recordingSave
	SourceSessionID string // one source epoch: a restarted source is a new session
	SourceStartedAt time.Time
	SnapshotID      string
	RequestedBefore time.Duration
	After           time.Duration
	HistoryCoverage string
	GapReasons      []string
	SourceStoppedAt time.Time `json:",omitzero"`
	WindowCoverage  string
	Origin          *RecordingSaveOrigin `json:",omitempty"`
}

// RecordingSaveOrigin binds a "Save existing recordings now" artifact to the
// unchanged policy executor whose source it saved.
type RecordingSaveOrigin struct {
	PolicyUID             string
	PolicyExecutionDigest Digest
}

// MaxLifecycleWindow bounds before/after; the ring age ceiling is one hour.
const MaxLifecycleWindow = time.Hour

var coverages = []string{"full", "partial", "none", "unknown"}
var gapReasons = []string{"notPreviouslyArmed", "warming", "capacityLimited", "sourceLost", "targetGone", "permitExpired", "retentionCutoff", "snapshotRefused", "clockUncertain", "unknownLoss", "historyEvicted"}

func lifecycleTime(t time.Time) bool { return !t.IsZero() && t.Nanosecond()%1000 == 0 }

// Validate enforces the coverage rules of action-lifecycle.md against the
// window anchor t0: full prehistory needs a source armed by t0-before; a known
// stop before t0+after prevents full window coverage; full window coverage
// needs full history and no gap. Every incomplete history names a reason.
func (l OngoingLifecycle) Validate(t0 time.Time) error {
	if !slices.Contains([]string{"policy", "manual", "recordingSave"}, l.TriggerKind) || !uuid(l.SourceSessionID) || !uuid(l.SnapshotID) || !lifecycleTime(l.SourceStartedAt) || !lifecycleTime(t0) {
		return ErrInvalid
	}
	for _, d := range []time.Duration{l.RequestedBefore, l.After} {
		if d < 0 || d > MaxLifecycleWindow || d%time.Millisecond != 0 {
			return ErrInvalid
		}
	}
	if l.RequestedBefore == 0 && l.After == 0 || !slices.Contains(coverages, l.HistoryCoverage) || !slices.Contains(coverages, l.WindowCoverage) || len(l.GapReasons) > len(gapReasons) {
		return ErrInvalid
	}
	for i, g := range l.GapReasons {
		if !slices.Contains(gapReasons, g) || slices.Contains(l.GapReasons[:i], g) {
			return ErrInvalid
		}
	}
	if !l.SourceStoppedAt.IsZero() && (!lifecycleTime(l.SourceStoppedAt) || l.SourceStoppedAt.Before(l.SourceStartedAt)) {
		return ErrInvalid
	}
	if l.HistoryCoverage == "full" && l.SourceStartedAt.After(t0.Add(-l.RequestedBefore)) || l.HistoryCoverage != "full" && len(l.GapReasons) == 0 {
		return ErrInvalid
	}
	windowEnd := t0.Add(l.After)
	if l.WindowCoverage == "full" && (l.HistoryCoverage != "full" || len(l.GapReasons) != 0 || !l.SourceStoppedAt.IsZero() && l.SourceStoppedAt.Before(windowEnd)) {
		return ErrInvalid
	}
	if l.TriggerKind == "recordingSave" {
		if l.After != 0 || l.Origin == nil || len(l.Origin.PolicyUID) < 1 || len(l.Origin.PolicyUID) > 64 || l.Origin.PolicyExecutionDigest == (Digest{}) {
			return ErrInvalid
		}
	} else if l.Origin != nil {
		return ErrInvalid
	}
	return nil
}

// Clone copies the slice and origin so a caller cannot alter accepted facts.
func (l *OngoingLifecycle) Clone() *OngoingLifecycle {
	if l == nil {
		return nil
	}
	c := *l
	c.GapReasons = slices.Clone(l.GapReasons)
	if l.Origin != nil {
		o := *l.Origin
		c.Origin = &o
	}
	return &c
}

// LifecycleDuration renders the action-lifecycle schema duration
// (^(0s|[1-9][0-9]*(ms|s|m|h|d))$) using the largest exact unit.
func LifecycleDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	for _, u := range []struct {
		unit   time.Duration
		suffix string
	}{{time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if d%u.unit == 0 {
			return strconv.FormatInt(int64(d/u.unit), 10) + u.suffix
		}
	}
	return strconv.FormatInt(int64(d/time.Millisecond), 10) + "ms"
}

// Coverage is the download coverage sentence: the type's fixed text plus the
// recorded history/window coverage of an ongoing save.
func (t NativeType) CoverageFor(l *OngoingLifecycle) string {
	if l == nil {
		return t.Coverage
	}
	return t.Coverage + " Recorded history: " + l.HistoryCoverage + "; requested window: " + l.WindowCoverage + "."
}
