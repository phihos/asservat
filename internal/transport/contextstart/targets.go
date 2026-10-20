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
	// Report receives fixed query outcome labels and timing buckets; it
	// never sees targets, peers or error text.
	Report func(string)
}

func (t Targets) query(ctx context.Context, cluster, method string, in any, matches func(targets.PodResolution) bool) (targets.PodResolution, error) {
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
	report := func(step string) {
		t.report(step + " start" + start + " end" + fleetapp.RemainingBucket(ctx, time.Now()) + " [" + marks.String() + "]")
	}
	until, err := t.Router.Query(call, cluster, method, in, &out)
	if err != nil {
		report(queryStep(err, diagnostics))
		return targets.PodResolution{}, err
	}
	regionalUntil := out.FreshUntil
	out.FreshUntil = identity.Earlier(out.FreshUntil, until)
	now := t.Now()
	switch {
	case out.ExecutionClass != artifact.ContextAPIExecution:
		report("result/class")
	case out.Request.ClusterID != cluster:
		report("result/cluster")
	case !out.Valid(now):
		report(queryResultStep(call, regionalUntil, until, now))
	case !matches(out):
		report("result/request")
	default:
		report("ok")
		return out, nil
	}
	return targets.PodResolution{}, targets.ErrUnavailable
}

// A decoded answer can be unusable even though its exchange succeeded. Keep
// the region's target cutoff distinct from the hub's original receiver cutoff.
// These labels are diagnostic only; no expiry is changed or retried here.
func queryResultStep(ctx context.Context, regionalUntil, receiverUntil, now time.Time) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "result/deadline"
	case ctx.Err() != nil:
		return "result/cancelled"
	case !now.Before(regionalUntil) && !now.Before(receiverUntil):
		return "result/both-expired"
	case !now.Before(regionalUntil):
		return "result/resolution-expired"
	case !now.Before(receiverUntil):
		return "result/receiver-expired"
	default:
		return "result/invalid"
	}
}

// ResolveWorkload resolves a named workload to one current Pod. A Pod name is
// resolved under its actual owner, so only the Pod name is compared then.
func (t Targets) ResolveWorkload(ctx context.Context, r targets.WorkloadRequest) (targets.PodResolution, error) {
	if !r.Valid() {
		return targets.PodResolution{}, targets.ErrInvalid
	}
	return t.query(ctx, r.ClusterID, queryResolveWorkload, r, func(out targets.PodResolution) bool {
		q := out.Request
		return q.Namespace.Name == r.Namespace && ((r.Kind == "Pod" && q.PodName == r.Name) || (r.Kind != "Pod" && q.Workload.Kind == r.Kind && q.Workload.Name == r.Name))
	})
}

// ResolvePod re-pins one exact Pod; the region never reselects another.
func (t Targets) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	if !r.Valid() {
		return targets.PodResolution{}, targets.ErrInvalid
	}
	return t.query(ctx, r.ClusterID, queryResolvePod, r, func(out targets.PodResolution) bool {
		return out.Request == r
	})
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
