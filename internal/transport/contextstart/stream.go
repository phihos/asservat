package contextstart

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// frameStream is deliberately internal to the single API context protocol. The
// server/client constructors supply actual HTTP/2 stream/socket deadline hooks.
type frameStream struct {
	ctx                          context.Context
	cancel                       context.CancelFunc
	channel                      fleet.APIContextChannel
	check                        ReceiverCheck
	read                         io.Reader
	write                        io.Writer
	readDeadline, writeDeadline  func(time.Time) error
	flush                        func() error
	interruptIO                  func()
	mu                           sync.Mutex
	reads, writes, frames, bytes int
	closed                       bool
	first                        atomic.Pointer[StreamInterruption]
	work                         sync.WaitGroup
	once                         sync.Once
	joined                       sync.Once
	joinedDone                   chan struct{}
	interrupted                  chan struct{}
	incoming                     chan contracts.APIContextFrame
	pumpDone                     chan struct{}
	awaited                      bool
	leaseStarted                 bool
	historyWork                  bool
	lease                        *framePeerLease
	leaseBounds                  []framePeerBound
	stopOwner                    func() bool
	ownerDone                    chan struct{}
	// ADR-178: sources is the hub's per-exchange feed; local is the region's
	// own source reader. sourceSeq is the last used source sequence.
	sources   *SourceFeed
	local     app.ConnectorIdentitySourceReader
	sourceSeq int
	// ADR-179: targets answers the hub's pre-work queries on the region;
	// querySeq is the last used query sequence on either side.
	targets  QueryTargets
	querySeq int
}

func newFrameStream(ctx context.Context, channel fleet.APIContextChannel, check ReceiverCheck, read io.Reader, write io.Writer, rd, wd func(time.Time) error, flush func() error, interrupt func()) (*frameStream, error) {
	if ctx == nil || ctx.Err() != nil || !channel.Valid() || check == nil || read == nil || write == nil || rd == nil || wd == nil || flush == nil || interrupt == nil {
		return nil, fleet.ErrInvalid
	}
	owner, cancel := context.WithCancel(ctx)
	s := &frameStream{ctx: owner, cancel: cancel, channel: channel, check: check, read: read, write: write, readDeadline: rd, writeDeadline: wd, flush: flush, interruptIO: interrupt, interrupted: make(chan struct{}), joinedDone: make(chan struct{})}
	s.ownerDone = make(chan struct{})
	s.stopOwner = context.AfterFunc(owner, func() { s.interruptAt(streamOwner, streamErrorReason(owner.Err())); close(s.ownerDone) })
	return s, nil
}
func (s *frameStream) interrupt() { s.interruptAt(streamClose, streamClosed) }
func (s *frameStream) interruptAt(stage streamStage, reason streamReason) {
	s.record(stage, reason)
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.lease = nil
		s.cancel()
		s.mu.Unlock()
		s.interruptIO()
		close(s.interrupted)
	})
}
func (s *frameStream) Context() context.Context { return s.ctx }
func (s *frameStream) Close() error {
	if s == nil {
		return nil
	}
	s.interrupt()
	<-s.interrupted
	s.joined.Do(func() {
		defer close(s.joinedDone)
		if !s.stopOwner() {
			<-s.ownerDone
		}
		s.work.Wait()
		s.mu.Lock()
		pump := s.pumpDone
		bounds := append([]framePeerBound(nil), s.leaseBounds...)
		s.mu.Unlock()
		for _, bound := range bounds {
			if !bound.stop() {
				<-bound.done
			}
			bound.cancel()
		}
		if pump != nil {
			<-pump
			for f := range s.incoming {
				clear(f.Payload)
			}
		}
	})
	<-s.joinedDone
	return nil
}
func (s *frameStream) begin(ctx context.Context, read bool) (context.Context, time.Time, func(), error) {
	return s.beginFrame(ctx, read, peerFrame)
}
func (s *frameStream) beginFrame(ctx context.Context, read bool, mode framePeerMode) (context.Context, time.Time, func(), error) {
	admissionStage, callStage, peerStage, boundStage, deadlineStage := streamSendAdmission, streamSendCall, streamSendPeer, streamSendBound, streamSendDeadline
	if read {
		admissionStage, callStage, peerStage, boundStage, deadlineStage = streamReceiveAdmission, streamReceiveCall, streamReceivePeer, streamReceiveBound, streamReceiveDeadline
	}
	if s == nil || ctx == nil {
		s.record(admissionStage, streamInvalid)
		return nil, time.Time{}, nil, fleet.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		s.mu.Lock()
		leased := s.leaseStarted
		s.mu.Unlock()
		if leased {
			s.interruptAt(admissionStage, streamErrorReason(err))
		} else {
			s.record(admissionStage, streamErrorReason(err))
		}
		return nil, time.Time{}, nil, fleet.ErrUnavailable
	}
	s.mu.Lock()
	reason := streamNoReason
	if s.closed {
		reason = streamClosed
	} else if err := s.ctx.Err(); err != nil {
		reason = streamErrorReason(err)
	} else if !read && s.frames >= contracts.APIContextMaximumFrames {
		reason = streamBudget
	} else if read && s.reads != 0 || !read && s.writes != 0 {
		reason = streamBusy
	}
	if reason != streamNoReason {
		s.record(admissionStage, reason)
		s.mu.Unlock()
		return nil, time.Time{}, nil, fleet.ErrUnavailable
	}
	if read {
		s.reads++
	} else {
		s.writes++
	}
	s.work.Add(1)
	s.mu.Unlock()
	until := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	stopOwner := context.AfterFunc(s.ctx, cancel)
	// After any timeout, this stream is terminal. An uncertain I/O never gets a
	// longer next deadline or a replacement connection carrying the same work.
	interruptDone := make(chan struct{})
	stopCall := context.AfterFunc(call, func() { s.interruptAt(callStage, streamErrorReason(call.Err())); close(interruptDone) })
	finish := func() {
		if !stopCall() {
			<-interruptDone
		}
		stopOwner()
		cancel()
		s.mu.Lock()
		if read {
			s.reads--
		} else {
			s.writes--
		}
		s.mu.Unlock()
		s.work.Done()
	}
	observed, observedMode, e := s.observePeer(call, mode)
	reason = streamNoReason
	if e != nil {
		reason = streamErrorReason(e)
	} else if !observed.Valid(time.Now()) {
		reason = streamPeerInvalid
	} else if observed.Channel != s.channel {
		reason = streamPeerChanged
	} else if err := call.Err(); err != nil {
		reason = streamErrorReason(err)
	}
	if reason != streamNoReason {
		s.interruptAt(peerStage, reason)
		finish()
		return nil, time.Time{}, nil, fleet.ErrUnavailable
	}
	observed, e = s.acceptPeer(call, observed, observedMode)
	if e != nil {
		s.interruptAt(peerStage, streamErrorReason(e))
		finish()
		return nil, time.Time{}, nil, fleet.ErrUnavailable
	}
	until = identity.Earlier(until, observed.ValidUntil)
	bounded, narrow := context.WithDeadline(call, until)
	// A socket write deadline does not necessarily interrupt a blocked HTTP/2
	// request-body pipe. Join an explicit callback at the shorter original peer
	// deadline before returning or reusing any stream resources.
	boundedDone := make(chan struct{})
	stopBounded := context.AfterFunc(bounded, func() { s.interruptAt(boundStage, streamErrorReason(bounded.Err())); close(boundedDone) })
	end := func() {
		if !stopBounded() {
			<-boundedDone
		}
		finish()
		narrow()
	}
	deadline := s.writeDeadline
	if read {
		deadline = s.readDeadline
	}
	reason = streamNoReason
	if e = deadline(until); e != nil {
		reason = streamErrorReason(e)
	} else if !time.Now().Before(until) {
		reason = streamExpired
	} else if err := bounded.Err(); err != nil {
		reason = streamErrorReason(err)
	}
	if reason != streamNoReason {
		s.interruptAt(deadlineStage, reason)
		end()
		return nil, time.Time{}, nil, fleet.ErrUnavailable
	}
	return bounded, until, end, nil
}
func (s *frameStream) count(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || n < 0 || s.frames >= contracts.APIContextMaximumFrames || s.bytes > contracts.APIContextMaximumExchangeBytes-n {
		return false
	}
	s.frames++
	s.bytes += n
	return true
}
func (s *frameStream) Send(ctx context.Context, f contracts.APIContextFrame) error {
	_, e := s.send(ctx, f)
	return e
}

// send retains the actual original frame bound for the hub's acknowledged
// pre-work query transition. Generic Send never changes completed deadlines.
func (s *frameStream) send(ctx context.Context, f contracts.APIContextFrame) (time.Time, error) {
	// ADR-178: the work check needs the region's fresh source first.
	if s != nil && (f.Kind == contracts.APIContextWorkFrame || f.Kind == contracts.HistoryWorkFrame || f.Kind == contracts.SourceWorkFrame) {
		if e := s.pullSource(ctx); e != nil {
			return time.Time{}, fleet.ErrUnavailable
		}
	}
	if s != nil {
		if e := s.admitLeaseFrame(f.Kind, false); e != nil {
			s.interruptAt(streamSendAdmission, streamErrorReason(e))
			return time.Time{}, fleet.ErrUnavailable
		}
	}
	mode := peerFrame
	if f.Kind == contracts.APIContextWorkFrame || f.Kind == contracts.HistoryWorkFrame || f.Kind == contracts.SourceWorkFrame {
		s.mu.Lock()
		s.historyWork = f.Kind == contracts.HistoryWorkFrame
		s.mu.Unlock()
		mode = peerWork
	}
	if f.Kind == contracts.APIContextResultFrame || f.Kind == contracts.HistoryResponseFrame {
		mode = peerFinal
	}
	call, until, end, e := s.beginFrame(ctx, false, mode)
	if e != nil {
		return time.Time{}, e
	}
	defer end()
	if !s.count(len(f.Payload) + 5) {
		s.interruptAt(streamSendAdmission, streamBudget)
		return time.Time{}, contracts.ErrAPIContextProtocol
	}
	writer := &streamWriteDiagnostic{writer: s.write}
	e = contracts.WriteAPIContextFrame(writer, f)
	stage, reason := streamWrite, writer.reason
	if e == nil {
		stage = streamFlush
		e = s.flush()
		reason = streamErrorReason(e)
	}
	if e != nil {
		if reason == streamNoReason {
			reason = streamErrorReason(e)
		}
	} else if err := call.Err(); err != nil {
		stage, reason = streamSendResult, streamErrorReason(err)
	} else if !time.Now().Before(until) {
		stage, reason = streamSendResult, streamExpired
	}
	if reason != streamNoReason {
		s.interruptAt(stage, reason)
		return time.Time{}, fleet.ErrUnavailable
	}
	return until, nil
}

// The sole reader remains active between identity calls so an actual EOF
// cancels a blocked regional runner. Only one frame can wait for its consumer;
// one additional frame may be in the bounded decoder. Reading ahead supplies
// no authority: Receive still checks the exact retained work peer and caller
// bound; a final result additionally requires a new full current observation.
func (s *frameStream) startReader() (<-chan contracts.APIContextFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return nil, fleet.ErrUnavailable
	}
	if s.pumpDone != nil {
		return s.incoming, nil
	}
	s.incoming = make(chan contracts.APIContextFrame, 1)
	s.pumpDone = make(chan struct{})
	go func() {
		defer close(s.pumpDone)
		defer close(s.incoming)
		for {
			reader := &streamReadDiagnostic{reader: s.read}
			f, e := contracts.ReadAPIContextFrame(reader)
			reason := streamNoReason
			if e != nil {
				reason = reader.reason
				if reason == streamNoReason {
					reason = streamErrorReason(e)
				}
			} else if !s.count(len(f.Payload) + 5) {
				reason = streamBudget
			}
			if reason != streamNoReason {
				clear(f.Payload)
				s.interruptAt(streamRead, reason)
				return
			}
			select {
			case s.incoming <- f:
			case <-s.ctx.Done():
				clear(f.Payload)
				return
			}
			// Receipt is the protocol's terminal frame. No later body value is accepted
			// or used. Let its exact semantic check finish before joined Close, avoiding
			// an EOF race against an already received terminal acknowledgement.
			if f.Kind == contracts.APIContextReceiptFrame || f.Kind == contracts.HistoryReceiptFrame {
				return
			}
		}
	}()
	return s.incoming, nil
}
func (s *frameStream) Receive(ctx context.Context) (contracts.APIContextFrame, error) {
	f, _, e := s.receive(ctx)
	return f, e
}

// receive returns only after its finite I/O cancellation callbacks have joined.
func (s *frameStream) receive(ctx context.Context) (contracts.APIContextFrame, time.Time, error) {
	call, until, end, e := s.begin(ctx, true)
	if e != nil {
		return contracts.APIContextFrame{}, time.Time{}, e
	}
	defer end()
	incoming, e := s.startReader()
	if e != nil {
		return contracts.APIContextFrame{}, time.Time{}, e
	}
	var f contracts.APIContextFrame
	for {
		select {
		case received, ok := <-incoming:
			if !ok {
				return contracts.APIContextFrame{}, time.Time{}, fleet.ErrUnavailable
			}
			f = received
		case <-call.Done():
			s.interruptAt(streamReceiveCall, streamErrorReason(call.Err()))
			return contracts.APIContextFrame{}, time.Time{}, fleet.ErrUnavailable
		case <-s.ctx.Done():
			return contracts.APIContextFrame{}, time.Time{}, fleet.ErrUnavailable
		}
		if f.Kind != contracts.APIContextSourceFrame {
			break
		}
		// ADR-178: the region's pre-result source never reaches the caller.
		e = s.absorbSource(f)
		clear(f.Payload)
		if e != nil {
			s.interruptAt(streamReceiveResult, streamErrorReason(e))
			return contracts.APIContextFrame{}, time.Time{}, fleet.ErrUnavailable
		}
	}
	reason := streamNoReason
	if err := call.Err(); err != nil {
		reason = streamErrorReason(err)
	} else if err := s.ctx.Err(); err != nil {
		reason = streamErrorReason(err)
	} else if !time.Now().Before(until) {
		reason = streamExpired
	}
	if reason != streamNoReason {
		clear(f.Payload)
		s.interruptAt(streamReceiveResult, reason)
		return contracts.APIContextFrame{}, time.Time{}, fleet.ErrUnavailable
	}
	if e := s.admitLeaseFrame(f.Kind, true); e != nil {
		clear(f.Payload)
		s.interruptAt(streamReceiveResult, streamErrorReason(e))
		return contracts.APIContextFrame{}, time.Time{}, fleet.ErrUnavailable
	}
	if f.Kind == contracts.APIContextResultFrame || f.Kind == contracts.HistoryResponseFrame {
		if e := s.confirmResultPeer(call); e != nil {
			clear(f.Payload)
			return contracts.APIContextFrame{}, time.Time{}, e
		}
	}
	return f, until, nil
}

// AwaitWork is a once-only passive read before any signed capture exists. Its
// residency bound is not an effect/peer grant. Only after the bounded work frame
// arrives is the exact connection checked under a fresh original <=5s interval.
// No later identity/result read can select this passive path.
func (s *frameStream) AwaitWork(ctx context.Context) (contracts.APIContextFrame, fleet.APIContextReceiver, error) {
	var empty contracts.APIContextFrame
	var zero fleet.APIContextReceiver
	if s == nil || ctx == nil || ctx.Err() != nil {
		return empty, zero, fleet.ErrInvalid
	}
	until, ok := ctx.Deadline()
	if !ok || !time.Now().Before(until) || until.After(time.Now().Add(30*time.Second)) {
		return empty, zero, fleet.ErrInvalid
	}
	if d, ok := s.ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	s.mu.Lock()
	if s.closed || s.awaited || s.pumpDone != nil || s.reads != 0 || s.writes != 0 || s.frames > 2 {
		s.mu.Unlock()
		return empty, zero, fleet.ErrDenied
	}
	s.awaited = true
	s.reads++
	s.work.Add(1)
	s.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, until)
	done := make(chan struct{})
	stop := context.AfterFunc(call, func() { s.interruptAt(streamPassiveCall, streamErrorReason(call.Err())); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		cancel()
		s.mu.Lock()
		s.reads--
		s.mu.Unlock()
		s.work.Done()
	}()
	if err := s.readDeadline(until); err != nil {
		s.interruptAt(streamPassiveDeadline, streamErrorReason(err))
		return empty, zero, fleet.ErrUnavailable
	}
	incoming, e := s.startReader()
	if e != nil {
		return empty, zero, e
	}
	var f contracts.APIContextFrame
	for {
		select {
		case v, ok := <-incoming:
			if !ok {
				return empty, zero, fleet.ErrUnavailable
			}
			f = v
		case <-call.Done():
			return empty, zero, fleet.ErrUnavailable
		case <-s.ctx.Done():
			return empty, zero, fleet.ErrUnavailable
		}
		// ADR-178/179: answer the hub's source requests and target queries
		// while still waiting for work.
		if f.Kind == contracts.APIContextSourceRequestFrame {
			e = s.answerSource(call, f)
		} else if f.Kind == contracts.APIContextQueryFrame {
			e = s.answerQuery(call, f)
		} else {
			break
		}
		clear(f.Payload)
		if e != nil {
			s.interruptAt(streamPassiveFrame, streamErrorReason(e))
			return empty, zero, fleet.ErrDenied
		}
	}
	reason := streamNoReason
	if f.Kind != contracts.APIContextWorkFrame && f.Kind != contracts.HistoryWorkFrame && f.Kind != contracts.SourceWorkFrame {
		reason = streamProtocol
	} else if err := call.Err(); err != nil {
		reason = streamErrorReason(err)
	} else if err := s.ctx.Err(); err != nil {
		reason = streamErrorReason(err)
	}
	if reason != streamNoReason {
		clear(f.Payload)
		s.interruptAt(streamPassiveFrame, reason)
		return empty, zero, fleet.ErrDenied
	}
	s.mu.Lock()
	s.historyWork = f.Kind == contracts.HistoryWorkFrame
	s.mu.Unlock()
	checkCtx, end := context.WithTimeout(call, 5*time.Second)
	defer end()
	receiver, mode, e := s.observePeer(checkCtx, peerWork)
	reason = streamNoReason
	if e != nil {
		reason = streamErrorReason(e)
	} else if err := checkCtx.Err(); err != nil {
		reason = streamErrorReason(err)
	} else if receiver.Channel != s.channel {
		reason = streamPeerChanged
	} else if !receiver.Valid(time.Now()) {
		reason = streamPeerInvalid
	}
	if reason != streamNoReason {
		clear(f.Payload)
		s.interruptAt(streamPassivePeer, reason)
		return empty, zero, fleet.ErrDenied
	}
	receiver, e = s.acceptPeer(checkCtx, receiver, mode)
	if e != nil {
		clear(f.Payload)
		s.interruptAt(streamPassivePeer, streamErrorReason(e))
		return empty, zero, fleet.ErrDenied
	}
	return f, receiver, nil
}
