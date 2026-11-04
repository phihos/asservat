package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Full existing HTTPS/frames path with synthetic authority, not installed
// availability: the failed native phase reports its actual original context,
// independently of the consumed three-second POST registration observation.
func TestDirectHolderOriginalCutoffFailureDiagnostic(t *testing.T) {
	c, f, inputs, native, registry := directHolderFixture(t, "owner-final")
	registry.until = time.Now().Add(3 * time.Second)
	_, err := c.ObserveCluster(f.base.root, f.base.request())
	var d interface {
		ObservationDeadlineDiagnostic() (string, time.Time, time.Duration)
	}
	if !errors.As(err, &d) {
		t.Fatal("missing original cutoff diagnostic", err)
	}
	label, until, left := d.ObservationDeadlineDiagnostic()
	if label != "caller" || !until.Equal(native.last.facts.FreshUntil) || left <= 0 || left > 5*time.Second {
		t.Fatal("lost original selected cutoff", label, until, left)
	}
	if !strings.Contains(regionalOutcome(err), "until-authority/caller=") {
		t.Fatal("cutoff absent from existing failure diagnostic", regionalOutcome(err))
	}
	if inputs.tokens.Load() != 1 || f.get.Load() != 1 || f.post.Load() != 1 || native.opens.Load() != 1 || registry.reads.Load() != 5 || len(c.sockets) != 0 {
		t.Fatal("changed acquisition/read/transport count")
	}
}

func TestDirectHolderDeadlineDiagnosticRetainsOriginalOnTie(t *testing.T) {
	c, f, _, _, _ := directHolderFixture(t, "owner-final")
	// The context and request tie. Every nested result is bounded by that
	// original end and must not rename it as a later source.
	r := f.base.request()
	ctx, cancel := context.WithDeadline(f.base.root, r.NotAfter)
	defer cancel()
	_, err := c.ObserveCluster(ctx, r)
	var d interface {
		ObservationDeadlineDiagnostic() (string, time.Time, time.Duration)
	}
	if !errors.As(err, &d) {
		t.Fatal("missing original cutoff diagnostic", err)
	}
	label, until, left := d.ObservationDeadlineDiagnostic()
	if label != "caller" || !until.Equal(r.NotAfter) || left <= 0 {
		t.Fatal("nested equal bound replaced original", label, until, left)
	}
}

// Untrusted method strings never enter the private log, and absent final
// attempts cannot be presented as having a measured zero remaining interval.
type arbitraryProbeDiagnostic struct{}

func (arbitraryProbeDiagnostic) Error() string { return "private-provider-text" }
func (arbitraryProbeDiagnostic) ProbeFailureDiagnostic() (string, time.Duration) {
	return "private-provider-token", time.Hour
}
func TestDirectHolderFailureDiagnosticClosedLabels(t *testing.T) {
	err := &observationCutoffFailure{err: arbitraryProbeDiagnostic{}, cutoff: observationCutoff{label: "private-provider-label", until: time.Now()}}
	if got := observationFailureDetail(err); got != "" {
		t.Fatal("private text rendered", got)
	}
	err.cutoff.label = "caller"
	got := observationFailureDetail(err)
	if !strings.Contains(got, "until-authority/caller=") || strings.Contains(got, "final_remaining") || strings.Contains(got, "private") {
		t.Fatal("incorrect cutoff-only diagnostic", got)
	}
}

// Exact timestamps improve each reported failure without changing the
// observation adapter's original per-category suppression of repeated logs.
func TestDirectHolderFailureDiagnosticKeepsStableCategory(t *testing.T) {
	first := &fixedStepError{"native-final", &observationCutoffFailure{err: errors.New("private"), cutoff: observationCutoff{label: "caller", until: time.Now()}}}
	second := &fixedStepError{"native-final", &observationCutoffFailure{err: errors.New("private"), cutoff: observationCutoff{label: "locator", until: time.Now().Add(time.Second)}}}
	if regionalOutcomeClass(first) != regionalOutcomeClass(second) || regionalOutcome(first) == regionalOutcome(second) {
		t.Fatal("dynamic deadline affected suppression key or disappeared")
	}
}
