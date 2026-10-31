package bootstrap

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/contextstart"
	"context"
	"time"
)

// RegionalHistoryDispatch selects an existing outbound connector conversation.
// Only the SQL producer can supply the effect authority after this selection.
type RegionalHistoryDispatch struct {
	Router *contextstart.Router
	Signer fleetapp.HistoryWorkSigner
	Now    func() time.Time
	// Report receives only fixed stages and finite timing buckets.
	Report func(string, string)
}

var _ fleetapp.HistoryDispatcher = RegionalHistoryDispatch{}

type regionalHistorySession struct {
	attachment *contextstart.Attachment
	receiver   fleet.APIContextReceiver
	signer     fleetapp.HistoryWorkSigner
	now        func() time.Time
	until      time.Time
	cancel     context.CancelFunc
	report     func(string, string)
}

// historyRetryLeft is the least time a retried attach needs for its own
// wait and the history exchange that follows.
const historyRetryLeft = 4 * time.Second

// historyRetryPause spaces history attach retries.
const historyRetryPause = 250 * time.Millisecond

// attach takes one standby within at most five seconds of ctx.
func (d RegionalHistoryDispatch) attach(ctx context.Context, cluster, captureID string) (*contextstart.Attachment, context.Context, context.CancelFunc, time.Time, error) {
	until := d.Now().Add(5 * time.Second)
	if bound, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, bound)
	}
	call, cancel := context.WithDeadline(ctx, until)
	began := time.Now()
	a, e := d.Router.Attach(call, cluster, captureID)
	reportHistoryDispatch(d.Report, call, "attach", began, until, e)
	if e != nil {
		cancel()
		return nil, nil, nil, time.Time{}, e
	}
	return a, call, cancel, until, nil
}

func (d RegionalHistoryDispatch) PrepareHistory(ctx context.Context, cluster, captureID string) (fleetapp.HistorySession, error) {
	if ctx == nil || ctx.Err() != nil || d.Router == nil || d.Signer == nil || d.Now == nil {
		return nil, fleet.ErrUnavailable
	}
	// Retry while history's own budget (ADR-272) still leaves time for the
	// exchange: right after a start a standby may be reopening, and the
	// recording collect holds this capture's route and the cluster's capture
	// slot for its short exchange (native run 41211070820), refused at once.
	a, call, cancel, until, e := d.attach(ctx, cluster, captureID)
	for e != nil {
		bound, ok := ctx.Deadline()
		if !ok || bound.Sub(d.Now()) < historyRetryLeft {
			return nil, e
		}
		pause := time.NewTimer(historyRetryPause)
		select {
		case <-ctx.Done():
			pause.Stop()
			return nil, e
		case <-pause.C:
		}
		a, call, cancel, until, e = d.attach(ctx, cluster, captureID)
	}
	began := time.Now()
	r, e := a.Receiver(call)
	reportHistoryDispatch(d.Report, call, "receiver", began, until, e)
	if e != nil {
		a.Close()
		cancel()
		return nil, e
	}
	until = identity.Earlier(until, r.ValidUntil)
	// The attachment retains call's cancellation. Its joined Close is the owner;
	// do not cancel it at this preparation boundary.
	return &regionalHistorySession{attachment: a, receiver: r, signer: d.Signer, now: d.Now, until: until, cancel: cancel, report: d.Report}, nil
}
func (s *regionalHistorySession) ExecutorEpoch() string {
	return s.receiver.Channel.Executor.ProcessEpoch
}
func (s *regionalHistorySession) NotAfter() time.Time { return s.until }
func (s *regionalHistorySession) Close() {
	if s != nil && s.attachment != nil {
		s.cancel()
		s.attachment.Close()
	}
}
func (s *regionalHistorySession) ExecuteHistory(ctx context.Context, a capture.HistoryOperationAuthority, b capture.HistoryCiphertexts, c artifact.Copies) (fleetapp.HistoryReply, error) {
	var out fleetapp.HistoryReply
	if s == nil || ctx == nil || ctx.Err() != nil || !a.Valid(s.now()) || a.ExecutorEpoch != s.ExecutorEpoch() || a.NotAfter.After(s.until) {
		return out, fleet.ErrDenied
	}
	// Prepare's checked receiver belongs to this exact retained attachment.
	// Consume that original proof only within its original validity; RunHistory
	// still checks live ownership, and the first work frame pulls and validates
	// the region's current source/peer before any effect. Re-reading here repeats
	// that regional source round trip without providing another authority bound.
	if !s.receiver.Valid(s.now()) {
		return out, fleet.ErrUnavailable
	}
	w := fleetapp.HistoryWork{Channel: s.receiver.Channel, Authority: a}
	effectUntil := identity.Earlier(s.until, a.NotAfter)
	began := time.Now()
	signed, e := s.signer.SignHistoryWork(ctx, w)
	reportHistoryDispatch(s.report, ctx, "sign", began, effectUntil, e)
	if e != nil {
		return out, e
	}
	defer clear(signed)
	if !a.Valid(s.now()) || ctx.Err() != nil {
		return out, fleet.ErrUnavailable
	}
	began = time.Now()
	observed, diagnostics := contextstart.NewStreamDiagnosticContext(ctx)
	out, e = s.attachment.RunHistory(observed, w, signed, b, c)
	reportHistoryDispatch(s.report, ctx, "exchange", began, effectUntil, e)
	if e != nil && s.report != nil {
		if peerUntil, ok := diagnostics.WorkPeerDeadline(); ok {
			reportHistoryDispatch(s.report, ctx, "exchange-peer", began, peerUntil, e)
		}
		if first := diagnostics.Interruption(); first.Present() {
			s.report("exchange-stream/"+first.Stage()+"/"+first.Reason(), "")
		}
	}
	return out, e
}

func reportHistoryDispatch(report func(string, string), ctx context.Context, stage string, began, until time.Time, err error) {
	auditapp.MarkStep(ctx, "h-"+stage, began)
	if report == nil {
		return
	}
	state := "ok"
	if err != nil {
		state = "failed"
	}
	if bound, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, bound)
	}
	remaining := time.Until(until)
	expired := ""
	if remaining <= 0 {
		expired = " expired"
	}
	report(stage+"/"+state, "elapsed"+auditapp.DurationBucket(time.Since(began))+" remaining"+auditapp.DurationBucket(remaining)+expired)
}
