package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

const queryReadLiveRuntime = "read-live-runtime"

type LiveRuntimeTargetResolver interface {
	ResolveLiveRuntime(context.Context, collector.LiveRuntimeRequest) (collector.LiveRuntimeSnapshot, error)
}

// ReadLiveRuntime reuses one idle regional query for content-free current
// counters and report-to-report rates. The regional and receiver deadlines both
// remain binding; no answer refreshes the underlying node reports.
func (t Targets) ReadLiveRuntime(ctx context.Context, request collector.LiveRuntimeRequest) (collector.LiveRuntimeSnapshot, error) {
	var out collector.LiveRuntimeSnapshot
	if ctx == nil || ctx.Err() != nil || t.Router == nil || t.Now == nil || !request.Valid() {
		return out, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	call, diagnostics := NewStreamDiagnosticContext(call)
	until, err := t.Router.Query(call, request.ClusterID, queryReadLiveRuntime, request, &out)
	if err != nil {
		t.report("live-runtime/"+queryStep(err, diagnostics), "")
		return collector.LiveRuntimeSnapshot{}, err
	}
	out.FreshUntil = identity.Earlier(out.FreshUntil, until)
	if call.Err() != nil || out.ClusterID != request.ClusterID || !out.Valid(t.Now()) {
		t.report("live-runtime/result", "")
		return collector.LiveRuntimeSnapshot{}, targets.ErrUnavailable
	}
	return out, nil
}
