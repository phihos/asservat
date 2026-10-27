package contextstart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

type streamPrivateError struct{}

func (*streamPrivateError) Error() string { panic("private error rendered") }
func (*streamPrivateError) Unwrap() error { panic("private error unwrapped") }
func (*streamPrivateError) Is(error) bool { panic("private error compared") }

type streamReaderFunc func([]byte) (int, error)

func (f streamReaderFunc) Read(p []byte) (int, error) { return f(p) }

type streamWriterFunc func([]byte) (int, error)

func (f streamWriterFunc) Write(p []byte) (int, error) { return f(p) }

func diagnosticStream(t *testing.T, ctx context.Context, check ReceiverCheck, reader io.Reader, writer io.Writer, rd, wd func(time.Time) error, flush func() error, interrupt func()) *frameStream {
	t.Helper()
	w := workFixture()
	if ctx == nil {
		ctx = context.Background()
	}
	if check == nil {
		check = func(context.Context) (fleet.APIContextReceiver, error) {
			return fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: w.VerifiedAt, ValidUntil: w.ValidUntil}, nil
		}
	}
	if reader == nil {
		reader = bytes.NewReader(nil)
	}
	if writer == nil {
		writer = io.Discard
	}
	if rd == nil {
		rd = func(time.Time) error { return nil }
	}
	if wd == nil {
		wd = func(time.Time) error { return nil }
	}
	if flush == nil {
		flush = func() error { return nil }
	}
	if interrupt == nil {
		interrupt = func() {}
	}
	s, e := newFrameStream(ctx, w.Work.Channel, check, reader, writer, rd, wd, flush, interrupt)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func requireStreamReason(t *testing.T, s *frameStream, stage streamStage, reason streamReason) {
	t.Helper()
	got := s.interruption()
	if got.stage != stage || got.reason != reason {
		t.Fatalf("closed diagnostic %s/%s, want %s/%s", got.Stage(), got.Reason(), (StreamInterruption{stage: stage}).Stage(), (StreamInterruption{reason: reason}).Reason())
	}
	s.Close()
	if s.interruption() != got {
		t.Fatal("joined close overwrote original deciding failure")
	}
}

func TestContextStreamDiagnosticPeerAndDeadlineBranches(t *testing.T) {
	for _, read := range []bool{false, true} {
		for _, name := range []string{"private-error", "unavailable", "denied", "invalid-peer", "changed-peer", "deadline-hook"} {
			t.Run(map[bool]string{false: "send", true: "receive"}[read]+"/"+name, func(t *testing.T) {
				w := workFixture()
				checks, deadlines := 0, 0
				check := func(context.Context) (fleet.APIContextReceiver, error) {
					checks++
					r := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: w.VerifiedAt, ValidUntil: w.ValidUntil}
					switch name {
					case "private-error":
						return r, &streamPrivateError{}
					case "unavailable":
						return r, fleet.ErrUnavailable
					case "denied":
						return r, fleet.ErrDenied
					case "invalid-peer":
						r.ValidUntil = r.ObservedAt
					case "changed-peer":
						r.Channel.ExchangeID = "00000000-0000-4000-8000-000000000099"
					}
					return r, nil
				}
				d := func(time.Time) error { deadlines++; return &streamPrivateError{} }
				s := diagnosticStream(t, nil, check, nil, nil, d, d, nil, nil)
				_, _, end, e := s.begin(context.Background(), read)
				if end != nil {
					end()
				}
				if !errors.Is(e, fleet.ErrUnavailable) {
					t.Fatal("original normalization changed")
				}
				stage := streamSendPeer
				if read {
					stage = streamReceivePeer
				}
				reason := streamOther
				switch name {
				case "unavailable":
					reason = streamUnavailable
				case "denied":
					reason = streamDenied
				case "invalid-peer":
					reason = streamPeerInvalid
				case "changed-peer":
					reason = streamPeerChanged
				case "deadline-hook":
					stage = streamSendDeadline
					if read {
						stage = streamReceiveDeadline
					}
				}
				requireStreamReason(t, s, stage, reason)
				wantDeadline := 0
				if name == "deadline-hook" {
					wantDeadline = 1
				}
				if checks != 1 || deadlines != wantDeadline {
					t.Fatal("original peer/deadline call ordering changed", checks, deadlines)
				}
			})
		}
	}
}

func TestContextStreamDiagnosticReadAndWriteFailures(t *testing.T) {
	for _, name := range []string{"read-eof", "read-private", "read-malformed", "read-byte-budget", "write-private", "write-invalid-frame", "write-byte-budget", "flush-private"} {
		t.Run(name, func(t *testing.T) {
			reads, writes, flushes := 0, 0, 0
			r := streamReaderFunc(func(p []byte) (int, error) {
				reads++
				if name == "read-private" {
					return 0, &streamPrivateError{}
				}
				return 0, io.EOF
			})
			var reader io.Reader = r
			if name == "read-malformed" {
				reader = bytes.NewReader([]byte{0, 0, 0, 0, 1})
			}
			if name == "read-byte-budget" {
				var b bytes.Buffer
				_ = contracts.WriteAPIContextFrame(&b, contracts.APIContextFrame{Kind: contracts.APIContextReceiptFrame, Payload: []byte("{}")})
				reader = &b
			}
			writer := streamWriterFunc(func(p []byte) (int, error) {
				writes++
				if name == "write-private" {
					return 0, &streamPrivateError{}
				}
				return len(p), nil
			})
			flush := func() error {
				flushes++
				if name == "flush-private" {
					return &streamPrivateError{}
				}
				return nil
			}
			s := diagnosticStream(t, nil, nil, reader, writer, nil, nil, flush, nil)
			frame := contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("{}")}
			stage, reason := streamRead, streamEOF
			var e error
			switch name {
			case "read-eof", "read-private", "read-malformed", "read-byte-budget":
				if name == "read-private" {
					reason = streamOther
				}
				if name == "read-malformed" {
					reason = streamProtocol
				}
				if name == "read-byte-budget" {
					reason = streamBudget
					s.bytes = contracts.APIContextMaximumExchangeBytes
				}
				_, e = s.Receive(context.Background())
			default:
				stage, reason = streamWrite, streamOther
				if name == "write-invalid-frame" {
					frame.Kind = 0
					reason = streamProtocol
				}
				if name == "write-byte-budget" {
					s.bytes = contracts.APIContextMaximumExchangeBytes
					stage, reason = streamSendAdmission, streamBudget
				}
				if name == "flush-private" {
					stage = streamFlush
				}
				e = s.Send(context.Background(), frame)
			}
			want := fleet.ErrUnavailable
			if name == "write-byte-budget" {
				want = contracts.ErrAPIContextProtocol
			}
			if !errors.Is(e, want) {
				t.Fatal("original result changed")
			}
			requireStreamReason(t, s, stage, reason)
			if name == "read-eof" || name == "read-private" {
				if reads != 1 || writes != 0 || flushes != 0 {
					t.Fatal("read error repeated or crossed effects")
				}
			}
			if name == "write-private" && (writes != 1 || flushes != 0) {
				t.Fatal("write error repeated or flushed")
			}
			if name == "write-invalid-frame" || name == "write-byte-budget" {
				if writes != 0 || flushes != 0 {
					t.Fatal("invalid write reached I/O")
				}
			}
			if name == "flush-private" && (writes != 2 || flushes != 1) {
				t.Fatal("flush error changed original frame writes")
			}
		})
	}
}

func TestContextStreamDiagnosticRetainedReadDeadline(t *testing.T) {
	// A real net.Conn deadline remains installed after Receive has completed.
	// The background EOF reader then encounters that exact bound while there is
	// no Receive call/timer running. This reproduces the suspected mechanism,
	// without asserting it caused the separate native failure or relaxing it.
	local, remote := net.Pipe()
	defer remote.Close()
	w := workFixture()
	start := time.Now()
	until := start.Add(120 * time.Millisecond)
	var checks, interrupts atomic.Int32
	check := func(context.Context) (fleet.APIContextReceiver, error) {
		checks.Add(1)
		return fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: start, ValidUntil: until}, nil
	}
	s := diagnosticStream(t, nil, check, local, io.Discard, local.SetReadDeadline, local.SetWriteDeadline, nil, func() { interrupts.Add(1); _ = local.Close() })
	written := make(chan error, 1)
	go func() {
		written <- contracts.WriteAPIContextFrame(remote, contracts.APIContextFrame{Kind: contracts.APIContextOperationResponseFrame, Payload: []byte("{}")})
	}()
	f, e := s.Receive(context.Background())
	if e != nil || f.Kind != contracts.APIContextOperationResponseFrame {
		t.Fatal("first finite frame failed")
	}
	clear(f.Payload)
	if e = <-written; e != nil {
		t.Fatal(e)
	}
	select {
	case <-s.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("retained original socket deadline did not interrupt pump")
	}
	s.Close()
	requireStreamReason(t, s, streamRead, streamTimeout)
	if checks.Load() != 1 || interrupts.Load() != 1 {
		t.Fatal("background read refreshed authority or repeated close")
	}
	if _, e = s.Receive(context.Background()); !errors.Is(e, fleet.ErrUnavailable) || checks.Load() != 1 {
		t.Fatal("expired original stream resumed")
	}
}

func TestContextStreamDiagnosticOriginalOwnerAndCallCancellation(t *testing.T) {
	t.Run("owner", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		s := diagnosticStream(t, ctx, nil, nil, nil, nil, nil, nil, nil)
		cancel()
		<-s.interrupted
		requireStreamReason(t, s, streamOwner, streamCanceled)
	})
	t.Run("blocked-peer-call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		entered := make(chan struct{})
		s := diagnosticStream(t, nil, func(c context.Context) (fleet.APIContextReceiver, error) {
			close(entered)
			<-c.Done()
			return fleet.APIContextReceiver{}, c.Err()
		}, nil, nil, nil, nil, nil, nil)
		done := make(chan error, 1)
		go func() {
			done <- s.Send(ctx, contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("{}")})
		}()
		<-entered
		cancel()
		if e := <-done; !errors.Is(e, fleet.ErrUnavailable) {
			t.Fatal("caller cancellation normalized differently")
		}
		s.Close()
		v := s.interruption()
		if v.reason != streamCanceled || (v.stage != streamSendCall && v.stage != streamSendPeer) {
			t.Fatal("original canceled caller not retained", v.Stage(), v.Reason())
		}
	})
	t.Run("short-peer-bound", func(t *testing.T) {
		w := workFixture()
		n := time.Now()
		until := n.Add(80 * time.Millisecond)
		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		s := diagnosticStream(t, nil, func(context.Context) (fleet.APIContextReceiver, error) {
			return fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: n, ValidUntil: until}, nil
		}, nil, writer, nil, nil, nil, func() { _ = writer.CloseWithError(context.DeadlineExceeded) })
		if e := s.Send(context.Background(), contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: []byte("{}")}); !errors.Is(e, fleet.ErrUnavailable) {
			t.Fatal("short bound allowed write")
		}
		requireStreamReason(t, s, streamSendBound, streamExpired)
	})
}

func TestContextStreamDiagnosticPrivateErrorAndDecoderSemantics(t *testing.T) {
	err := &streamPrivateError{}
	if streamErrorReason(err) != streamOther {
		t.Fatal("unknown private error classified")
	}
	for _, cause := range []error{fleet.ErrUnavailable, fleet.ErrDenied, contracts.ErrAPIContextProtocol, context.Canceled} {
		ctx, record := NewStreamDiagnosticContext(context.Background())
		s := diagnosticStream(t, nil, nil, nil, nil, nil, nil, nil, nil)
		s.record(streamReceivePeer, streamOther)
		recordStreamDiagnostic(ctx, s, cause, streamHubReceive)
		got := record.Interruption()
		if got.Stage() != "receive-peer" || got.Reason() != "other" {
			t.Fatal("closed recording changed")
		}
		s.Close()
		recordStreamDiagnostic(ctx, s, fleet.ErrDenied, streamRegionalReceipt)
		if record.Interruption() != got {
			t.Fatal("later close replaced first cause")
		}
	}
	// ReadFull accepts n==len(p),EOF. Do not promote a discarded Reader error
	// into a stream failure when the original complete frame is valid.
	wire := []byte{byte(contracts.APIContextReceiptFrame), 0, 0, 0, 2, '{', '}'}
	reads := 0
	r := &streamReadDiagnostic{reader: streamReaderFunc(func(p []byte) (int, error) {
		reads++
		n := copy(p, wire)
		wire = wire[n:]
		if len(wire) == 0 {
			return n, io.EOF
		}
		return n, nil
	})}
	f, e := contracts.ReadAPIContextFrame(r)
	if e != nil || string(f.Payload) != "{}" || reads != 2 {
		t.Fatal("diagnostic delegate changed ReadFull semantics")
	}
}

func TestContextStreamDiagnosticOriginalHubRunErrorAndJoinedAttachment(t *testing.T) {
	w := workFixture()
	router, e := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{ClusterID: w.Work.Target.ClusterID, Standby: 1, Captures: 1}}})
	if e != nil {
		t.Fatal(e)
	}
	// The standby keeps its own residency beyond the attachment's deadline.
	resident, cancel := context.WithCancel(context.Background())
	defer cancel()
	resident, record := NewStreamDiagnosticContext(resident)
	ctx, end := context.WithDeadline(resident, w.ValidUntil)
	defer end()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: w.VerifiedAt, ValidUntil: w.ValidUntil}
	check := func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil }
	standby, e := router.RegisterStandby(resident, receiver, check)
	if e != nil {
		t.Fatal(e)
	}
	attachment, e := router.Attach(ctx, w.Work.Target.ClusterID, w.Work.CaptureID)
	if e != nil {
		t.Fatal(e)
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	s := diagnosticStream(t, standby.Context(), check, reader, io.Discard, nil, nil, nil, func() { _ = reader.Close() })
	served := make(chan error, 1)
	finish := make(chan struct{})
	go func() { err := standby.Serve(s, time.Now); served <- err; <-finish; s.Close(); standby.Finish() }()
	// The region acknowledges the hub's finish and echoes its final state.
	ack, e := contracts.EncodeAPIContextOperationReply(contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: opFinish})
	if e != nil {
		t.Fatal(e)
	}
	result, e := contracts.EncodeAPIContextResult(contracts.APIContextResult{Format: contracts.APIContextExchangeFormat, ExchangeID: w.Work.Channel.ExchangeID, CaptureID: w.Work.CaptureID, State: "Unavailable"})
	if e != nil {
		t.Fatal(e)
	}
	written := make(chan error, 1)
	go func() {
		if err := contracts.WriteAPIContextFrame(writer, contracts.APIContextFrame{Kind: contracts.APIContextOperationResponseFrame, Payload: ack}); err != nil {
			written <- err
			return
		}
		written <- contracts.WriteAPIContextFrame(writer, contracts.APIContextFrame{Kind: contracts.APIContextResultFrame, Payload: result})
	}()
	calls := 0
	private := &streamPrivateError{}
	state, e := attachment.Run(w.Work, []byte("signed"), func(context.Context, *HubOperations) (string, error) {
		calls++
		return "Unavailable", private
	})
	close(finish)
	attachment.Close()
	router.Close()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != private {
		t.Fatal("original hub run error was replaced", err)
	}
	if e != private || state != "Unavailable" || calls != 1 {
		t.Fatal("original run error/state normalization or call count changed", state, e)
	}
	got := record.Interruption()
	if got.stage != streamHubOperations || got.reason != streamOther {
		t.Fatal("joined hub run failure lost", got.Stage(), got.Reason())
	}
}

type streamDiagnosticVerifier func(context.Context, []byte, fleet.APIContextReceiver) (fleet.AuthenticatedAPIContextWork, error)

func (f streamDiagnosticVerifier) VerifyAPIContextWork(c context.Context, b []byte, r fleet.APIContextReceiver) (fleet.AuthenticatedAPIContextWork, error) {
	return f(c, b, r)
}

func TestContextStreamDiagnosticRegionalVerificationAndIsolation(t *testing.T) {
	w := workFixture()
	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx, regional := NewStreamDiagnosticContext(parent)
	_, hub := NewStreamDiagnosticContext(parent)
	if d, _ := ctx.Deadline(); d != func() time.Time { d, _ := parent.Deadline(); return d }() {
		t.Fatal("recorder changed original deadline")
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: w.VerifiedAt, ValidUntil: w.ValidUntil}
	checks := 0
	check := func(context.Context) (fleet.APIContextReceiver, error) { checks++; return receiver, nil }
	s := diagnosticStream(t, ctx, check, reader, io.Discard, nil, nil, nil, func() { _ = reader.Close() })
	written := make(chan error, 1)
	go func() {
		written <- contracts.WriteAPIContextFrame(writer, contracts.APIContextFrame{Kind: contracts.APIContextWorkFrame, Payload: []byte("signed")})
	}()
	verifications := 0
	local := &countingLocal{}
	e := ServeRegionalOperations(ctx, s, receiver, streamDiagnosticVerifier(func(c context.Context, b []byte, r fleet.APIContextReceiver) (fleet.AuthenticatedAPIContextWork, error) {
		verifications++
		expected := receiver
		expected.ValidUntil, _ = ctx.Deadline() // The work lease retains the shorter original caller.
		if c != ctx || r != expected || string(b) != "signed" {
			t.Fatal("original verifier input changed")
		}
		return fleet.AuthenticatedAPIContextWork{}, &streamPrivateError{}
	}), local.local(), time.Now)
	if e != fleet.ErrDenied || verifications != 1 || checks != 1 || local.calls != 0 {
		t.Fatal("original verification normalization or call count changed")
	}
	if e = <-written; e != nil {
		t.Fatal(e)
	}
	s.Close()
	v := regional.Interruption()
	if v.stage != streamRegionalVerify || v.reason != streamDenied || hub.Interruption().Present() {
		t.Fatal("independent endpoint recorder lost cause or cross-populated")
	}
	if parent.Err() != nil {
		t.Fatal("diagnostic canceled original parent")
	}
}

func TestContextStreamDiagnosticAdmissionAndPassiveBranches(t *testing.T) {
	for _, name := range []string{"nil-caller", "canceled-caller", "closed", "frame-limit", "busy-read", "busy-write"} {
		t.Run(name, func(t *testing.T) {
			checks := 0
			s := diagnosticStream(t, nil, func(context.Context) (fleet.APIContextReceiver, error) {
				checks++
				return fleet.APIContextReceiver{}, nil
			}, nil, nil, nil, nil, nil, nil)
			ctx := context.Background()
			read := false
			want := streamInvalid
			switch name {
			case "nil-caller":
				ctx = nil
			case "canceled-caller":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
				want = streamCanceled
			case "closed":
				s.closed = true
				want = streamClosed
			case "frame-limit":
				s.frames = contracts.APIContextMaximumFrames
				want = streamBudget
			case "busy-read":
				read = true
				s.reads = 1
				want = streamBusy
			case "busy-write":
				s.writes = 1
				want = streamBusy
			}
			_, _, end, e := s.begin(ctx, read)
			if end != nil {
				end()
			}
			if e != fleet.ErrUnavailable || checks != 0 {
				t.Fatal("refused admission reached peer or changed category")
			}
			stage := streamSendAdmission
			if read {
				stage = streamReceiveAdmission
			}
			requireStreamReason(t, s, stage, want)
		})
	}
	for _, name := range []string{"deadline-hook", "wrong-kind", "peer-private", "peer-changed", "peer-invalid"} {
		t.Run("passive/"+name, func(t *testing.T) {
			w := workFixture()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			defer writer.Close()
			checks := 0
			check := func(context.Context) (fleet.APIContextReceiver, error) {
				checks++
				r := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: w.VerifiedAt, ValidUntil: w.ValidUntil}
				switch name {
				case "peer-private":
					return r, &streamPrivateError{}
				case "peer-changed":
					r.Channel.ExchangeID = "00000000-0000-4000-8000-000000000099"
				case "peer-invalid":
					r.ValidUntil = r.ObservedAt
				}
				return r, nil
			}
			rd := func(time.Time) error {
				if name == "deadline-hook" {
					return &streamPrivateError{}
				}
				return nil
			}
			s := diagnosticStream(t, nil, check, reader, io.Discard, rd, nil, nil, func() { _ = reader.Close() })
			written := make(chan error, 1)
			if name != "deadline-hook" {
				go func() {
					kind := contracts.APIContextWorkFrame
					if name == "wrong-kind" {
						kind = contracts.APIContextReceiptFrame
					}
					written <- contracts.WriteAPIContextFrame(writer, contracts.APIContextFrame{Kind: kind, Payload: []byte("{}")})
				}()
			}
			_, _, e := s.AwaitWork(ctx)
			wantError := fleet.ErrDenied
			stage, reason := streamPassivePeer, streamOther
			switch name {
			case "deadline-hook":
				wantError = fleet.ErrUnavailable
				stage = streamPassiveDeadline
			case "wrong-kind":
				stage, reason = streamPassiveFrame, streamProtocol
			case "peer-changed":
				reason = streamPeerChanged
			case "peer-invalid":
				reason = streamPeerInvalid
			}
			if e != wantError {
				t.Fatal("original passive branch normalization changed")
			}
			if name != "deadline-hook" {
				if e = <-written; e != nil {
					t.Fatal(e)
				}
			}
			requireStreamReason(t, s, stage, reason)
			wantChecks := 1
			if name == "deadline-hook" || name == "wrong-kind" {
				wantChecks = 0
			}
			if checks != wantChecks {
				t.Fatal("passive refusal changed peer call count")
			}
		})
	}
}
