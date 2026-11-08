package contextstart

import (
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

func TestContextStreamShortPeerDeadlineInterruptsBlockedRequestPipe(t *testing.T) {
	w := workFixture()
	start := time.Now()
	until := start.Add(40 * time.Millisecond)
	read, write := io.Pipe()
	defer read.Close()
	defer write.Close()
	check := func(context.Context) (fleet.APIContextReceiver, error) {
		return fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(start, identity.Recheck).Narrow(until)}, nil
	}
	// A request-body pipe has no socket deadline of its own. Merely setting the
	// underlying HTTP/2 connection deadline cannot be its cancellation owner.
	s, e := newFrameStream(context.Background(), w.Work.Channel, check, bytes.NewReader(nil), write, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() { _ = write.CloseWithError(context.DeadlineExceeded) })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	done := make(chan error, 1)
	go func() {
		done <- s.Send(context.Background(), contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("{}")})
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("blocked expired send succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("short original peer deadline did not interrupt pipe")
	}
	if e = s.Send(context.Background(), contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("{}")}); e == nil {
		t.Fatal("expired exchange resumed")
	}
}

func TestContextStreamSpendsFiniteFrameBudgetAcrossDirections(t *testing.T) {
	w := workFixture()
	read, write := io.Pipe()
	defer write.Close()
	check := func(context.Context) (fleet.APIContextReceiver, error) {
		return fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(w.VerifiedAt, identity.Recheck).Narrow(w.ValidUntil)}, nil
	}
	s, e := newFrameStream(context.Background(), w.Work.Channel, check, read, io.Discard, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() { read.Close() })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for n := 0; n < contracts.APIContextMaximumFrames; n++ {
		if n%2 == 0 {
			written := make(chan error, 1)
			go func() {
				written <- contracts.WriteAPIContextFrame(write, contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("{}")})
			}()
			_, e = s.Receive(context.Background())
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		} else {
			e = s.Send(context.Background(), contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("{}")})
		}
		if e != nil {
			t.Fatal(n, e)
		}
	}
	if e = s.Send(context.Background(), contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("{}")}); e == nil {
		t.Fatal("frame budget replenished")
	}

}

func TestContextStreamPassiveFirstWaitDoesNotConsumePeerLease(t *testing.T) {
	w := workFixture()
	read, write := io.Pipe()
	defer write.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	expected, _ := ctx.Deadline()
	deadline := make(chan time.Time, 1)
	var checks atomic.Int32
	check := func(context.Context) (fleet.APIContextReceiver, error) {
		checks.Add(1)
		n := time.Now()
		return fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(n, identity.Recheck).Narrow(n.Add(40 * time.Millisecond))}, nil
	}
	s, e := newFrameStream(ctx, w.Work.Channel, check, read, io.Discard, func(d time.Time) error { deadline <- d; return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() { read.Close() })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	done := make(chan error, 1)
	go func() { _, _, e := s.AwaitWork(ctx); done <- e }()
	if got := <-deadline; !got.Equal(expected) {
		t.Fatal("passive read acquired a five-second effect deadline")
	}
	time.Sleep(80 * time.Millisecond)
	if checks.Load() != 0 {
		t.Fatal("idle waiting spent or refreshed a peer observation")
	}
	if e = contracts.WriteAPIContextFrame(write, contracts.APIContextFrame{Kind: contracts.APIContextWorkFrame, Payload: []byte("signed")}); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil || checks.Load() != 1 {
		t.Fatalf("fresh exact peer check after passive wait: %v", e)
	}
	if _, _, e = s.AwaitWork(ctx); e == nil {
		t.Fatal("passive first-read path was reused")
	}
}
func TestContextStreamEOFJoinsBlockedHubOperation(t *testing.T) {
	w := workFixture()
	read, write := io.Pipe()
	defer write.Close()
	check := func(context.Context) (fleet.APIContextReceiver, error) {
		return fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(w.VerifiedAt, identity.Recheck).Narrow(w.ValidUntil)}, nil
	}
	s, e := newFrameStream(context.Background(), w.Work.Channel, check, read, io.Discard, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() { read.Close() })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	entered, joined := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := ServeHubOperations(context.Background(), s, w.Work, []byte("signed"), func(ctx context.Context, ops *HubOperations) (string, error) {
			close(entered)
			_, err := ops.ReadAPIProcess(ctx) // blocks on the regional reply
			close(joined)
			return "Unavailable", err
		}, time.Now)
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("hub run not entered")
	}
	write.Close()
	select {
	case <-joined:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stream EOF did not end the blocked hub operation")
	}
	if e = <-done; e == nil {
		t.Fatal("EOF conversation succeeded")
	}
}

func terminalReceiptTestStream(t *testing.T, flush func() error) (*frameStream, *io.PipeWriter) {
	t.Helper()
	w := workFixture()
	ctx, cancel := context.WithDeadline(context.Background(), w.ValidUntil)
	t.Cleanup(cancel)
	read, write := io.Pipe()
	check := func(context.Context) (fleet.APIContextReceiver, error) {
		return fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(w.VerifiedAt, identity.Recheck).Narrow(w.ValidUntil)}, nil
	}
	s, e := newFrameStream(ctx, w.Work.Channel, check, read, io.Discard, func(time.Time) error { return nil }, func(time.Time) error { return nil }, flush, func() { _ = read.Close() })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close(); _ = read.Close(); _ = write.Close() })
	if e = s.Send(ctx, contracts.APIContextFrame{Kind: contracts.APIContextWorkFrame, Payload: []byte("signed")}); e != nil {
		t.Fatal(e)
	}
	written := make(chan error, 1)
	go func() {
		written <- contracts.WriteAPIContextFrame(write, contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("result")})
	}()
	result, e := s.Receive(ctx)
	clear(result.Payload)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-written; e != nil {
		t.Fatal(e)
	}
	return s, write
}

func TestContextStreamTerminalReceiptRequiresSuccessfulFlush(t *testing.T) {
	var flushes atomic.Int32
	s, _ := terminalReceiptTestStream(t, func() error {
		if flushes.Add(1) == 2 {
			return fleet.ErrDenied
		}
		return nil
	})
	e := s.Send(context.Background(), contracts.APIContextFrame{Kind: contracts.APIContextReceiptFrame, Payload: []byte("receipt")})
	if e == nil {
		t.Fatal("failed receipt flush succeeded")
	}
	if s.sentTerminalReceipt() {
		t.Fatal("failed receipt flush was reported as delivered")
	}
	if got := s.interruption().Stage(); got != "flush" {
		t.Fatal("failed receipt flush was not retained", got)
	}
}

func TestContextStreamReadFailureDuringReceiptFlushIsTerminal(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var flushes atomic.Int32
	s, write := terminalReceiptTestStream(t, func() error {
		if flushes.Add(1) == 2 {
			close(entered)
			<-release
		}
		return nil
	})
	done := make(chan error, 1)
	go func() {
		done <- s.Send(context.Background(), contracts.APIContextFrame{Kind: contracts.APIContextReceiptFrame, Payload: []byte("receipt")})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("receipt flush not entered")
	}
	if s.sentTerminalReceipt() {
		t.Error("in-flight receipt flush was reported as delivered")
	}
	if e := write.Close(); e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	pump := s.pumpDone
	s.mu.Unlock()
	select {
	case <-pump:
	case <-time.After(time.Second):
		t.Fatal("reader did not observe EOF")
	}
	if got := s.interruption().Stage(); got != "read" {
		t.Error("read failure during receipt flush was dropped", got)
	}
	close(release)
	<-done
}

func TestContextStreamPeerCloseWaitHasFixedGrace(t *testing.T) {
	w := workFixture()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	read, write := io.Pipe()
	defer write.Close()
	check := func(context.Context) (fleet.APIContextReceiver, error) {
		return fleet.APIContextReceiver{Channel: w.Work.Channel, Window: identity.Check(w.VerifiedAt, identity.Recheck).Narrow(w.ValidUntil)}, nil
	}
	s, e := newFrameStream(ctx, w.Work.Channel, check, read, io.Discard, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() { _ = read.Close() })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.startReader(); e != nil {
		t.Fatal(e)
	}
	started := time.Now()
	s.awaitPeerClose(ctx)
	if elapsed := time.Since(started); elapsed < 1500*time.Millisecond || elapsed >= 4*time.Second {
		t.Fatal("peer-close wait did not use the fixed two-second grace", elapsed)
	}
	if ctx.Err() != nil {
		t.Fatal("peer-close grace waited for the original standby deadline")
	}
	closed := make(chan struct{})
	go func() { _ = s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("stream cleanup remained blocked after peer-close grace")
	}
}
