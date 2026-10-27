package bootstrap

import (
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
}

var _ fleetapp.HistoryDispatcher = RegionalHistoryDispatch{}

type regionalHistorySession struct {
	attachment *contextstart.Attachment
	receiver   fleet.APIContextReceiver
	signer     fleetapp.HistoryWorkSigner
	now        func() time.Time
	until      time.Time
	cancel     context.CancelFunc
}

func (d RegionalHistoryDispatch) PrepareHistory(ctx context.Context, cluster, captureID string) (fleetapp.HistorySession, error) {
	if ctx == nil || ctx.Err() != nil || d.Router == nil || d.Signer == nil || d.Now == nil {
		return nil, fleet.ErrUnavailable
	}
	until := d.Now().Add(5 * time.Second)
	if bound, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, bound)
	}
	call, cancel := context.WithDeadline(ctx, until)
	a, e := d.Router.Attach(call, cluster, captureID)
	if e != nil {
		cancel()
		return nil, e
	}
	r, e := a.Receiver(call)
	if e != nil {
		a.Close()
		cancel()
		return nil, e
	}
	until = identity.Earlier(until, r.ValidUntil)
	// The attachment retains call's cancellation. Its joined Close is the owner;
	// do not cancel it at this preparation boundary.
	return &regionalHistorySession{attachment: a, receiver: r, signer: d.Signer, now: d.Now, until: until, cancel: cancel}, nil
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
	current, e := s.attachment.Receiver(ctx)
	if e != nil || current.Channel != s.receiver.Channel || !current.Valid(s.now()) {
		return out, fleet.ErrUnavailable
	}
	w := fleetapp.HistoryWork{Channel: current.Channel, Authority: a}
	signed, e := s.signer.SignHistoryWork(ctx, w)
	if e != nil {
		return out, e
	}
	defer clear(signed)
	if !a.Valid(s.now()) || ctx.Err() != nil {
		return out, fleet.ErrUnavailable
	}
	return s.attachment.RunHistory(ctx, w, signed, b, c)
}
