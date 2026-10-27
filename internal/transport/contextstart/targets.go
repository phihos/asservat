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
// region's original API observation. Source/peer proofs bound delivery, while
// completed metadata retains its own first-read observation interval.
type Targets struct {
	Router *Router
	Now    func() time.Time
	// Report receives a fixed query outcome key separately from timing text.
	// Neither argument contains targets, peers or error text.
	Report func(event, timing string)
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
		t.report(step, "start"+start+" end"+fleetapp.RemainingBucket(ctx, time.Now())+" ["+marks.String()+"]")
	}
	until, err := t.Router.Query(call, cluster, method, in, &out)
	if err != nil {
		report(queryStep(err, diagnostics))
		return targets.PodResolution{}, err
	}
	regionalUntil := out.FreshUntil
	now := t.Now()
	switch {
	case out.ExecutionClass != artifact.ContextAPIExecution:
		report("result/class")
	case out.Request.ClusterID != cluster:
		report("result/cluster")
	case !out.Valid(now) || !now.Before(until) || call.Err() != nil:
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

// ObserveWorkloadRestarts asks the workload's region for one complete Pod
// restart observation (ADR-228). The answer is delegated proof, capped at the
// checked receiver validity; a truncated LIST arrives as a failure.
func (t Targets) ObserveWorkloadRestarts(ctx context.Context, r targets.RestartRequest) (targets.RestartObservation, error) {
	var out targets.RestartObservation
	if !r.Valid() || t.Router == nil || t.Now == nil || ctx == nil || ctx.Err() != nil {
		return out, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	call, diagnostics := NewStreamDiagnosticContext(call)
	until, err := t.Router.Query(call, r.ClusterID, queryObserveRestarts, r, &out)
	if err != nil {
		t.report("restarts/"+queryStep(err, diagnostics), "")
		return targets.RestartObservation{}, err
	}
	out.FreshUntil = identity.Earlier(out.FreshUntil, until)
	if out.ClusterID != r.ClusterID || out.Namespace.Name != r.Namespace || out.Workload.Kind != r.Kind || out.Workload.Name != r.Name || !out.Answers(r) || !out.Valid(t.Now()) {
		t.report("restarts/result", "")
		return targets.RestartObservation{}, targets.ErrUnavailable
	}
	return out, nil
}

// ReviewAccess asks the target Pod's region for one decision-time review
// (ADR-245). The answer is the region's closed outcome for exactly this
// request; a transport failure, an unsupported region or a mismatched answer
// is an error, which the caller records as a refusal.
func (t Targets) ReviewAccess(ctx context.Context, r targets.AccessReviewRequest) (targets.AccessReviewAnswer, error) {
	var out targets.AccessReviewAnswer
	if !r.Valid() || t.Router == nil || t.Now == nil || ctx == nil || ctx.Err() != nil {
		return out, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	call, diagnostics := NewStreamDiagnosticContext(call)
	if _, err := t.Router.Query(call, r.Target.ClusterID, queryReviewAccess, r, &out); err != nil {
		t.report("review/"+queryStep(err, diagnostics), "")
		return targets.AccessReviewAnswer{}, err
	}
	if !out.Valid(r) {
		t.report("review/result", "")
		return targets.AccessReviewAnswer{}, targets.ErrUnavailable
	}
	return out, nil
}

// PacketRecorder asks the target Pod's region whether its node collector
// offers the packet recorder now (ADR-248). Anything but an "available"
// answer, including an unsupported region, refuses.
func (t Targets) PacketRecorder(ctx context.Context, p targets.PodResolution) error {
	r := targets.RecorderRequest{Target: p.Request, Pin: p.Pin}
	if !r.Valid() || t.Router == nil || t.Now == nil || ctx == nil || ctx.Err() != nil {
		return targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	call, diagnostics := NewStreamDiagnosticContext(call)
	var out targets.RecorderAnswer
	if _, err := t.Router.Query(call, r.Target.ClusterID, queryPacketRecorder, r, &out); err != nil {
		t.report("recorder/"+queryStep(err, diagnostics), "")
		return err
	}
	if !out.Valid() {
		t.report("recorder/result", "")
		return targets.ErrUnavailable
	}
	if out.Outcome != targets.RecorderAvailable {
		return targets.ErrUnsupported
	}
	return nil
}

// ResolvePacketRecorder shares target and packet readiness under one original
// receiver check. No second query or refreshed deadline is introduced.
func (t Targets) ResolvePacketRecorder(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	if !r.Valid() || t.Router == nil || t.Now == nil || ctx == nil || ctx.Err() != nil {
		return targets.PodResolution{}, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	call, diagnostics := NewStreamDiagnosticContext(call)
	marks := &queryMarks{}
	call = context.WithValue(call, queryMarksKey{}, marks)
	start := fleetapp.RemainingBucket(call, time.Now())
	report := func(step string) {
		t.report("recorder-target/"+step, "start"+start+" end"+fleetapp.RemainingBucket(ctx, time.Now())+" ["+marks.String()+"]")
	}
	var out targets.RecorderResolution
	until, err := t.Router.Query(call, r.ClusterID, queryResolvePacketRecorder, r, &out)
	if err != nil {
		report(queryStep(err, diagnostics))
		return targets.PodResolution{}, err
	}
	now := t.Now()
	if !out.Valid(now) || !now.Before(until) || call.Err() != nil || out.Target.Request != r {
		report(queryResultStep(call, out.Target.FreshUntil, until, now))
		return targets.PodResolution{}, targets.ErrUnavailable
	}
	if out.Recorder.Outcome != targets.RecorderAvailable {
		return targets.PodResolution{}, targets.ErrUnsupported
	}
	report("ok")
	return out.Target, nil
}

func (t Targets) report(step, timing string) {
	if t.Report != nil {
		t.Report(step, timing)
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
