package contextstart

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// Targets is the hub's investigation target port over idle regional standbys
// (ADR-179). The hub reads no workload cluster; each resolution is the
// region's delegated proof, capped at its checked receiver validity.
type Targets struct {
	Router *Router
	Now    func() time.Time
	// Report receives a fixed query step and remaining-time buckets on
	// failure only; it never sees targets, peers or error text.
	Report func(string)
}

func (t Targets) query(ctx context.Context, cluster, method string, in any) (targets.PodResolution, error) {
	var out targets.PodResolution
	if t.Router == nil || t.Now == nil || ctx == nil || ctx.Err() != nil {
		return out, targets.ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := fleetapp.RemainingBucket(call, time.Now())
	call, diagnostics := NewStreamDiagnosticContext(call)
	marks := &queryMarks{}
	call = context.WithValue(call, queryMarksKey{}, marks)
	until, err := t.Router.Query(call, cluster, method, in, &out)
	if err != nil {
		t.report(queryStep(err, diagnostics) + " start" + start + " end" + fleetapp.RemainingBucket(ctx, time.Now()) + " [" + marks.String() + "]")
		return targets.PodResolution{}, err
	}
	t.report("ok start" + start + " end" + fleetapp.RemainingBucket(ctx, time.Now()) + " [" + marks.String() + "]")
	out.FreshUntil = identity.Earlier(out.FreshUntil, until)
	if out.ExecutionClass != artifact.ContextAPIExecution || out.Request.ClusterID != cluster || !out.Valid(t.Now()) {
		return targets.PodResolution{}, targets.ErrUnavailable
	}
	return out, nil
}

// ResolveWorkload resolves a named workload to one current Pod. A Pod name is
// resolved under its actual owner, so only the Pod name is compared then.
func (t Targets) ResolveWorkload(ctx context.Context, r targets.WorkloadRequest) (targets.PodResolution, error) {
	if !r.Valid() {
		return targets.PodResolution{}, targets.ErrInvalid
	}
	out, err := t.query(ctx, r.ClusterID, queryResolveWorkload, r)
	if err != nil {
		return out, err
	}
	q := out.Request
	if q.Namespace.Name != r.Namespace || (r.Kind == "Pod" && q.PodName != r.Name) || (r.Kind != "Pod" && (q.Workload.Kind != r.Kind || q.Workload.Name != r.Name)) {
		return targets.PodResolution{}, targets.ErrUnavailable
	}
	return out, nil
}

// ResolvePod re-pins one exact Pod; the region never reselects another.
func (t Targets) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	if !r.Valid() {
		return targets.PodResolution{}, targets.ErrInvalid
	}
	out, err := t.query(ctx, r.ClusterID, queryResolvePod, r)
	if err != nil {
		return out, err
	}
	if out.Request != r {
		return targets.PodResolution{}, targets.ErrUnavailable
	}
	return out, nil
}

func (t Targets) report(step string) {
	if t.Report != nil {
		t.Report(step)
	}
}

// queryStep names where a failed query stopped: a closed regional answer, the
// stream's first interruption, or the router (no idle standby or its wait).
func queryStep(err error, d *StreamDiagnostics) string {
	var answer errQueryAnswer
	if errors.As(err, &answer) {
		return "answer/" + queryFailureLabel(err)
	}
	if v := d.Interruption(); v.Present() {
		return v.Stage() + "/" + v.Reason()
	}
	return "router"
}

// queryMarks collects fixed hub query stage durations for diagnostics only.
type queryMarks struct {
	mu    sync.Mutex
	marks []string
}
type queryMarksKey struct{}

func markQuery(ctx context.Context, stage string, start time.Time) {
	if m, ok := ctx.Value(queryMarksKey{}).(*queryMarks); ok && m != nil {
		m.mu.Lock()
		if len(m.marks) < 8 {
			m.marks = append(m.marks, stage+"="+time.Since(start).Round(10*time.Millisecond).String())
		}
		m.mu.Unlock()
	}
}
func (m *queryMarks) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.Join(m.marks, " ")
}
