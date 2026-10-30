package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type SourceQueue interface {
	EnqueueSourceExpected(context.Context, targets.PacketSourceObservation, collector.PacketSource) (collector.Work, error)
	EnqueueSourceStop(context.Context, collector.SourceBinding, time.Time) (collector.Work, error)
}
type SourceLocal struct {
	Snapshots evidence.SourceSnapshotCanceller
	Verifier  app.SourceWorkVerifier
	Queue     SourceQueue
}

func sourceReply(w app.SourceWork, state string) contracts.SourceReply {
	reply := contracts.SourceReply{Format: contracts.SourceWorkFormat, SourceID: w.Binding().SourceID, Fence: w.Binding().Fence, State: state}
	if w.StopSnapshot != nil {
		reply.CaptureID = w.StopSnapshot.CaptureID
		reply.SnapshotID = w.StopSnapshot.Request.SnapshotID
	}
	return reply
}
func matchingSourceReply(w app.SourceWork, r contracts.SourceReply) bool {
	return r.SourceID == w.Binding().SourceID && r.Fence == w.Binding().Fence && (w.StopSnapshot == nil && r.CaptureID == "" && r.SnapshotID == "" || w.StopSnapshot != nil && r.CaptureID == w.StopSnapshot.CaptureID && r.SnapshotID == w.StopSnapshot.Request.SnapshotID)
}

func serveRegionalSource(ctx context.Context, s Stream, r fleet.APIContextReceiver, signed []byte, local *SourceLocal, now func() time.Time) error {
	if local == nil || local.Verifier == nil || local.Queue == nil {
		return fleet.ErrUnavailable
	}
	auth, err := local.Verifier.VerifySourceWork(ctx, signed, r)
	if err != nil || !auth.Valid(now()) {
		return fleet.ErrDenied
	}
	w := auth.Work
	call, cancel := context.WithDeadline(ctx, auth.ValidUntil)
	defer cancel()
	ended := make(chan struct{})
	stop := context.AfterFunc(s.Context(), func() { cancel(); close(ended) })
	defer func() {
		if !stop() {
			<-ended
		}
	}()
	if call.Err() != nil || !w.Valid(now()) {
		return fleet.ErrUnavailable
	}
	var effectErr error
	if w.StopSnapshot != nil {
		if local.Snapshots == nil {
			effectErr = fleet.ErrUnavailable
		} else {
			effectErr = local.Snapshots.CancelSourceSnapshot(call, *w.StopSnapshot)
		}
	} else if w.Stop {
		_, effectErr = local.Queue.EnqueueSourceStop(call, w.Source.Permit.Binding, w.NotAfter)
	} else {
		_, effectErr = local.Queue.EnqueueSourceExpected(call, w.Node, w.Source)
	}
	state := "queued"
	if effectErr != nil {
		state = "unavailable"
	}
	if call.Err() != nil || !auth.Valid(now()) {
		return fleet.ErrUnavailable
	}
	body, err := contracts.EncodeSourceReply(sourceReply(w, state))
	if err != nil {
		return err
	}
	defer clear(body)
	if err = s.Send(call, contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: body}); err != nil {
		return err
	}
	f, err := s.Receive(call)
	defer clear(f.Payload)
	if err != nil || f.Kind != contracts.APIContextReceiptFrame {
		return contracts.ErrAPIContextProtocol
	}
	reply, err := contracts.DecodeSourceReply(f.Payload)
	if err != nil || !matchingSourceReply(w, reply) || reply.State != "received" {
		return contracts.ErrAPIContextProtocol
	}
	return nil
}

func serveHubSource(ctx context.Context, s Stream, w app.SourceWork, signed []byte, now func() time.Time) error {
	if ctx == nil || s == nil || now == nil || ctx.Err() != nil || !w.Valid(now()) {
		return fleet.ErrInvalid
	}
	call, cancel := context.WithDeadline(ctx, w.NotAfter)
	defer cancel()
	if err := s.Send(call, contracts.APIContextFrame{Kind: contracts.SourceWorkFrame, Payload: signed}); err != nil {
		return err
	}
	f, err := s.Receive(call)
	defer clear(f.Payload)
	if err != nil || f.Kind != contracts.APIContextResultFrame {
		return contracts.ErrAPIContextProtocol
	}
	r, err := contracts.DecodeSourceReply(f.Payload)
	if err != nil || !matchingSourceReply(w, r) || (r.State != "queued" && r.State != "unavailable") {
		return contracts.ErrAPIContextProtocol
	}
	if call.Err() != nil || !w.Valid(now()) {
		return fleet.ErrUnavailable
	}
	body, err := contracts.EncodeSourceReply(sourceReply(w, "received"))
	if err != nil {
		return err
	}
	defer clear(body)
	if err = s.Send(call, contracts.APIContextFrame{Kind: contracts.APIContextReceiptFrame, Payload: body}); err != nil {
		return err
	}
	if r.State != "queued" {
		return fleet.ErrUnavailable
	}
	return nil
}

// RunSource uses the existing owned finite attachment slot and joined cleanup;
// it creates no capture/attempt or per-source encrypted intent/outcome objects.
func (a *Attachment) RunSource(ctx context.Context, w app.SourceWork, signed []byte) error {
	if a == nil || ctx == nil || ctx.Err() != nil || !w.Valid(time.Now()) || w.Channel != a.standby.channel || w.RouteID() != a.capture || len(signed) == 0 {
		return fleet.ErrInvalid
	}
	a.mu.Lock()
	if a.closed || a.dispatched || a.ctx.Err() != nil || a.standby.ctx.Err() != nil {
		a.mu.Unlock()
		return fleet.ErrUnavailable
	}
	a.router.mu.Lock()
	if a.router.standby[a.standby.channel.ExchangeID] != a.standby || !a.standby.liveLocked() {
		a.router.mu.Unlock()
		a.mu.Unlock()
		return fleet.ErrUnavailable
	}
	a.dispatched = true
	a.work.Add(1)
	defer a.work.Done()
	call, cancel := context.WithDeadline(ctx, w.NotAfter)
	defer cancel()
	ended := make(chan struct{})
	stop := context.AfterFunc(a.ctx, func() { cancel(); close(ended) })
	defer func() {
		if !stop() {
			<-ended
		}
	}()
	job := &captureJob{ctx: call, signed: append([]byte(nil), signed...), result: make(chan jobResult, 1)}
	job.historyRun = func(run context.Context, s Stream) (string, error) {
		err := serveHubSource(run, s, w, job.signed, time.Now)
		recordStreamDiagnostic(run, s, err, streamHubOperations)
		return "", err
	}
	a.standby.job <- job
	a.router.mu.Unlock()
	a.mu.Unlock()
	result := <-job.result
	return result.err
}

// SourceWorkEnd retains all original precommit/target/receiver bounds, while
// the separate active leaf remains within its committed thirty-second limit.
func SourceWorkEnd(w app.SourceWork, r fleet.APIContextReceiver) time.Time {
	return identity.Earlier(w.Source.Permit.DispatchUntil, identity.Earlier(w.Target.FreshUntil, identity.Earlier(w.Node.FreshUntil, r.ValidUntil)))
}
