package contextstart

import (
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"context"
	"time"
)

// RunHistory never constructs an APIContextWork or APIExecution. It consumes
// this attachment's same finite slot and joins cancellation before returning.
func (a *Attachment) RunHistory(ctx context.Context, w fleetapp.HistoryWork, signed []byte, b capture.HistoryCiphertexts, c artifact.Copies) (fleetapp.HistoryReply, error) {
	var out fleetapp.HistoryReply
	if a == nil || ctx == nil || ctx.Err() != nil || !w.Valid(time.Now()) || w.Channel != a.standby.channel || w.Authority.Expectation.CaptureID != a.capture || len(signed) == 0 {
		return out, fleet.ErrInvalid
	}
	a.mu.Lock()
	if a.closed || a.dispatched || a.ctx.Err() != nil || a.standby.ctx.Err() != nil {
		a.mu.Unlock()
		return out, fleet.ErrUnavailable
	}
	a.router.mu.Lock()
	if a.router.standby[a.standby.channel.ExchangeID] != a.standby || !a.standby.liveLocked() {
		a.router.mu.Unlock()
		a.mu.Unlock()
		return out, fleet.ErrUnavailable
	}
	a.dispatched = true
	a.work.Add(1)
	defer a.work.Done()
	call, cancel := context.WithDeadline(ctx, w.Authority.NotAfter)
	ended := make(chan struct{})
	stop := context.AfterFunc(a.ctx, func() { cancel(); close(ended) })
	defer func() {
		if !stop() {
			<-ended
		}
		cancel()
	}()
	job := &captureJob{ctx: call, signed: append([]byte(nil), signed...), result: make(chan jobResult, 1)}
	job.historyRun = func(run context.Context, s Stream) (string, error) {
		var e error
		out, e = serveHubHistory(run, s, w, job.signed, b, c, time.Now)
		recordStreamDiagnostic(run, s, e, streamHubOperations)
		return "", e
	}
	a.standby.job <- job
	a.router.mu.Unlock()
	a.mu.Unlock()
	// A handed-off effect retains its reservation until the actual operation
	// returns, including cancellation; no uncertain operation is replayed.
	result := <-job.result
	if result.err != nil {
		out.Bundle.Clear()
		return fleetapp.HistoryReply{}, result.err
	}
	return out, nil
}
