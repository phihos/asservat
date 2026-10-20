package contextstart

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type queryDecodeHook func()

func (f queryDecodeHook) UnmarshalJSON([]byte) error { f(); return nil }

type queryLifecycleFixture struct {
	stream        *frameStream
	peer          net.Conn
	receiver      fleet.APIContextReceiver
	passiveUntil  time.Time
	readRestores  atomic.Int32
	writeRestores atomic.Int32
}

// The peer performs the real bounded source/query frame exchange. It remains
// connected after answering, so a completed answer is distinct from EOF.
func newQueryLifecycleFixture(t *testing.T, parent context.Context, check ReceiverCheck, answer func(contracts.APIContextOperationReply) contracts.APIContextFrame) *queryLifecycleFixture {
	t.Helper()
	w := workFixture()
	now := time.Now()
	f := &queryLifecycleFixture{receiver: fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: now, ValidUntil: now.Add(time.Second)}}
	f.passiveUntil, _ = parent.Deadline()
	if check == nil {
		check = func(context.Context) (fleet.APIContextReceiver, error) { return f.receiver, nil }
	}
	socket, peer := net.Pipe()
	f.peer = peer
	var err error
	f.stream, err = newFrameStream(parent, w.Work.Channel, check, socket, socket,
		func(d time.Time) error {
			if d.Equal(f.passiveUntil) {
				f.readRestores.Add(1)
			}
			return socket.SetReadDeadline(d)
		}, func(d time.Time) error {
			if d.Equal(f.passiveUntil) {
				f.writeRestores.Add(1)
			}
			return socket.SetWriteDeadline(d)
		}, func() error { return nil }, func() { _ = socket.Close() })
	if err != nil {
		t.Fatal(err)
	}
	f.stream.sources = NewSourceFeed(w.Work.Channel.ExchangeID, time.Now)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for {
			frame, e := contracts.ReadAPIContextFrame(peer)
			if e != nil {
				return
			}
			switch frame.Kind {
			case contracts.APIContextSourceRequestFrame:
				request, e := contracts.DecodeAPIContextSourceRequest(frame.Payload)
				if e != nil {
					t.Error(e)
					return
				}
				frame = contracts.APIContextFrame{Kind: contracts.APIContextSourceFrame, Payload: sourcePayload(t, request.ExchangeID, request.Sequence, time.Now())}
			case contracts.APIContextQueryFrame:
				request, e := contracts.DecodeAPIContextOperation(frame.Payload)
				if e != nil {
					t.Error(e)
					return
				}
				reply := contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: request.Sequence, Method: request.Method, Body: json.RawMessage(`{}`)}
				if answer != nil {
					frame = answer(reply)
				} else {
					frame = queryAnswerFrame(t, reply)
				}
				if frame.Kind == 0 {
					_ = peer.Close()
					return
				}
			default:
				t.Error("unexpected hub frame", frame.Kind)
				return
			}
			if e := contracts.WriteAPIContextFrame(peer, frame); e != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = f.stream.Close()
		_ = peer.Close()
		<-joined
	})
	return f
}

func queryAnswerFrame(t *testing.T, reply contracts.APIContextOperationReply) contracts.APIContextFrame {
	t.Helper()
	payload, err := contracts.EncodeAPIContextOperationReply(reply)
	if err != nil {
		t.Error(err)
	}
	return contracts.APIContextFrame{Kind: contracts.APIContextAnswerFrame, Payload: payload}
}

func TestContextQueryCompletedAnswerRetainsProofAndFiniteCounts(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "closed-denial"}[denied], func(t *testing.T) {
			parent, end := context.WithTimeout(context.Background(), 2*time.Second)
			defer end()
			f := newQueryLifecycleFixture(t, parent, nil, func(reply contracts.APIContextOperationReply) contracts.APIContextFrame {
				if denied {
					reply.Body, reply.Failure = nil, "denied"
				}
				return queryAnswerFrame(t, reply)
			})
			for i := 0; i < contracts.APIContextMaximumQueries; i++ {
				ctx, cancel := context.WithTimeout(parent, time.Second)
				until, err := f.stream.query(ctx, queryResolvePod, struct{}{}, &struct{}{})
				cancel()
				if denied {
					var closed errQueryAnswer
					if !errors.As(err, &closed) || !errors.Is(err, targets.ErrDenied) {
						t.Fatal("closed denial lost", err)
					}
				} else if err != nil || !until.Equal(f.receiver.ValidUntil) {
					t.Fatal("successful proof changed", until, err)
				}
				if f.stream.Context().Err() != nil {
					t.Fatal("completed caller cancellation closed standby")
				}
			}
			if f.readRestores.Load() != 4 || f.writeRestores.Load() != 4 {
				t.Fatal("both original passive deadlines were not restored", f.readRestores.Load(), f.writeRestores.Load())
			}
			if f.stream.querySeq != 4 || f.stream.sourceSeq != 4 || f.stream.frames != 16 {
				t.Fatal("finite sequence/frame accounting changed", f.stream.querySeq, f.stream.sourceSeq, f.stream.frames)
			}
			if _, err := f.stream.query(parent, queryResolvePod, struct{}{}, &struct{}{}); err == nil {
				t.Fatal("fifth query accepted")
			}
		})
	}
}

func TestContextQueryIncompleteAnswerNeverRestores(t *testing.T) {
	for _, scenario := range []string{"unknown-failure", "wrong-sequence", "wrong-method", "wrong-kind", "malformed-answer", "invalid-body", "eof", "cancelled", "late-answer"} {
		t.Run(scenario, func(t *testing.T) {
			parent, end := context.WithTimeout(context.Background(), 2*time.Second)
			defer end()
			ctx, cancel := context.WithTimeout(parent, 100*time.Millisecond)
			defer cancel()
			f := newQueryLifecycleFixture(t, parent, nil, func(reply contracts.APIContextOperationReply) contracts.APIContextFrame {
				switch scenario {
				case "unknown-failure":
					reply.Body, reply.Failure = nil, "foreign"
				case "wrong-sequence":
					reply.Sequence++
				case "wrong-method":
					reply.Method = queryResolveWorkload
				case "wrong-kind":
					return contracts.APIContextFrame{Kind: contracts.APIContextWorkFrame, Payload: []byte("invalid")}
				case "malformed-answer":
					return contracts.APIContextFrame{Kind: contracts.APIContextAnswerFrame, Payload: []byte("{")}
				case "invalid-body":
					reply.Body = json.RawMessage(`{"unknown":true}`)
				case "eof":
					return contracts.APIContextFrame{}
				case "cancelled":
					cancel()
				case "late-answer":
					<-ctx.Done()
				}
				return queryAnswerFrame(t, reply)
			})
			if _, err := f.stream.query(ctx, queryResolvePod, struct{}{}, &struct{}{}); err == nil {
				t.Fatal("incomplete query accepted")
			}
			if f.readRestores.Load() != 0 || f.writeRestores.Load() != 0 {
				t.Fatal("incomplete query restored a deadline")
			}
			if f.stream.Context().Err() == nil {
				t.Fatal("failed query left stream usable")
			}
		})
	}
}

func TestContextQueryCompletionKeepsEveryOriginalBound(t *testing.T) {
	for _, earlierCheck := range []int{1, 2, 3} {
		t.Run(map[int]string{1: "explicit-query-peer", 2: "send-peer", 3: "receive-peer"}[earlierCheck], func(t *testing.T) {
			parent, end := context.WithTimeout(context.Background(), 2*time.Second)
			defer end()
			early := time.Now().Add(80 * time.Millisecond)
			var calls atomic.Int32
			check := func(context.Context) (fleet.APIContextReceiver, error) {
				now := time.Now()
				r := fleet.APIContextReceiver{Channel: workFixture().Work.Channel, ObservedAt: now, ValidUntil: now.Add(time.Second)}
				if int(calls.Add(1)) == earlierCheck {
					r.ValidUntil = early
				}
				return r, nil
			}
			f := newQueryLifecycleFixture(t, parent, check, nil)
			ctx, cancel := context.WithTimeout(parent, time.Second)
			defer cancel()
			// Decode occurs after Receive joined its finite callbacks. Cross
			// the earlier proof cutoff even if no socket timer has fired yet.
			out := queryDecodeHook(func() { time.Sleep(time.Until(early) + time.Millisecond) })
			if _, err := f.stream.query(ctx, queryResolvePod, struct{}{}, &out); err == nil {
				t.Fatal("expired original peer bound was restored")
			}
			if f.readRestores.Load() != 0 || f.writeRestores.Load() != 0 || f.stream.Context().Err() == nil {
				t.Fatal("expired query was not terminal before restoration", f.readRestores.Load(), f.writeRestores.Load(), f.stream.Context().Err())
			}
		})
	}
}

func TestContextQueryAnswerCutoffIncludesEarlierFrameProofs(t *testing.T) {
	for _, earlierCheck := range []int{2, 3} {
		t.Run(map[int]string{2: "send", 3: "receive"}[earlierCheck], func(t *testing.T) {
			parent, end := context.WithTimeout(context.Background(), 2*time.Second)
			defer end()
			ctx, cancel := context.WithTimeout(parent, time.Second)
			defer cancel()
			early := time.Now().Add(400 * time.Millisecond)
			var checks atomic.Int32
			check := func(context.Context) (fleet.APIContextReceiver, error) {
				now := time.Now()
				r := fleet.APIContextReceiver{Channel: workFixture().Work.Channel, ObservedAt: now, ValidUntil: now.Add(time.Second)}
				if int(checks.Add(1)) == earlierCheck {
					r.ValidUntil = early
				}
				return r, nil
			}
			f := newQueryLifecycleFixture(t, parent, check, nil)
			until, err := f.stream.query(ctx, queryResolvePod, struct{}{}, &struct{}{})
			if err != nil || !until.Equal(early) {
				t.Fatal("answer outlived a contributing original frame proof", until, early, err)
			}
		})
	}
}

func TestContextQueryReuseChecksNewSourceAndRejectsRevokedPeer(t *testing.T) {
	parent, end := context.WithTimeout(context.Background(), 2*time.Second)
	defer end()
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	var checks atomic.Int32
	check := func(context.Context) (fleet.APIContextReceiver, error) {
		if checks.Add(1) > 3 {
			return fleet.APIContextReceiver{}, fleet.ErrDenied
		}
		now := time.Now()
		return fleet.APIContextReceiver{Channel: workFixture().Work.Channel, ObservedAt: now, ValidUntil: now.Add(time.Second)}, nil
	}
	f := newQueryLifecycleFixture(t, parent, check, nil)
	if _, err := f.stream.query(ctx, queryResolvePod, struct{}{}, &struct{}{}); err != nil {
		t.Fatal("initial query", err)
	}
	if _, err := f.stream.query(ctx, queryResolvePod, struct{}{}, &struct{}{}); err == nil {
		t.Fatal("revoked peer reused completed query proof")
	}
	if f.stream.sourceSeq != 2 || checks.Load() != 4 || f.readRestores.Load() != 1 || f.writeRestores.Load() != 1 || f.stream.Context().Err() == nil {
		t.Fatal("reuse did not pull a new source before its rejecting current check")
	}
}

func TestContextQueryCompletionFailureIsTerminal(t *testing.T) {
	for _, scenario := range []string{"read-hook", "write-hook", "cancel-during-read-hook", "eof-during-read-hook", "attempted-work", "busy-read", "busy-write", "cancel-after-answer"} {
		t.Run(scenario, func(t *testing.T) {
			parent, end := context.WithTimeout(context.Background(), 2*time.Second)
			defer end()
			ctx, cancel := context.WithTimeout(parent, time.Second)
			defer cancel()
			f := newQueryLifecycleFixture(t, parent, nil, nil)
			readDeadline, writeDeadline := f.stream.readDeadline, f.stream.writeDeadline
			f.stream.readDeadline = func(d time.Time) error {
				if d.Equal(f.passiveUntil) {
					switch scenario {
					case "read-hook":
						return errors.New("deadline hook")
					case "cancel-during-read-hook":
						cancel()
					case "eof-during-read-hook":
						_ = f.peer.Close()
						// The reader records interruption before acquiring mu.
						for f.stream.first.Load() == nil {
							time.Sleep(time.Millisecond)
						}
					}
				}
				return readDeadline(d)
			}
			f.stream.writeDeadline = func(d time.Time) error {
				if d.Equal(f.passiveUntil) && scenario == "write-hook" {
					return errors.New("deadline hook")
				}
				return writeDeadline(d)
			}
			out := queryDecodeHook(func() {
				f.stream.mu.Lock()
				defer f.stream.mu.Unlock()
				switch scenario {
				case "attempted-work":
					f.stream.leaseStarted = true // failed first proof, no lease
				case "busy-read":
					f.stream.reads++
				case "busy-write":
					f.stream.writes++
				case "cancel-after-answer":
					cancel()
				}
			})
			if _, err := f.stream.query(ctx, queryResolvePod, struct{}{}, &out); err == nil || f.stream.Context().Err() == nil {
				t.Fatal("failed transition remained usable", err)
			}
			if scenario != "write-hook" && f.writeRestores.Load() != 0 {
				t.Fatal("transition continued after failure")
			}
			if _, err := f.stream.query(parent, queryResolvePod, struct{}{}, &struct{}{}); err == nil {
				t.Fatal("failed transition resurrected")
			}
		})
	}
}

func TestContextQueryCompletedStandbyExpiresAtOriginalParent(t *testing.T) {
	parent, end := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer end()
	f := newQueryLifecycleFixture(t, parent, nil, nil)
	if _, err := f.stream.query(parent, queryResolvePod, struct{}{}, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.stream.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("original standby parent was extended")
	}
	if time.Now().Before(f.passiveUntil) {
		t.Fatal("standby did not retain original parent")
	}
	if _, err := f.stream.query(context.Background(), queryResolvePod, struct{}{}, &struct{}{}); err == nil {
		t.Fatal("expired standby reused")
	}
}
