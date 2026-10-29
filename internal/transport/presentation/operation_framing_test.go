package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/audit"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
)

// Keep the actual C18 coordinator, audit acknowledgement, typed adapter and
// ownership. Only its independently owned reader/ledger/authority are synthetic.
type framingReader struct {
	*bridgeFixture
	entered chan struct{}
	release chan struct{}
}

func TestTypedWriterPreservesMain64KiBLimit(t *testing.T) {
	for _, owned := range []bool{false, true} {
		for _, size := range []int{64 << 10, 64<<10 + 1} {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			until := time.Now().Add(500 * time.Millisecond)
			reply := OperationReply{Body: []byte(`{"status":"ok"}`), ValidUntil: until}
			if owned {
				var err error
				reply, err = ownOperationReply(ctx, reply, &replyGuardFixture{}, time.Now().Add(time.Second), func(context.Context, audit.OperationOutcome) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				if err = reply.acknowledge(ctx, audit.OperationOutcome{OutputBytes: int64(len(reply.Body)), MetadataUntil: until}); err != nil {
					t.Fatal(err)
				}
			}
			w := &operationWriter{ResponseRecorder: httptest.NewRecorder()}
			sent, err := WriteOperationReplyResponse(ctx, w, 200, bytes.Repeat([]byte("x"), size), reply, until, reply.CheckDisclosure)
			if size == 64<<10 {
				if err != nil || !sent || w.Body.Len() != size {
					t.Fatal("original64KiB refused", owned, err)
				}
			} else if err == nil || sent || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "" {
				t.Fatal("over64KiB escaped or polluted fallback", owned, err)
			}
			_ = reply.Close(ctx)
			cancel()
		}
	}
}

func TestOwnedResponseRejectsAdditionalApplicationPayload(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			result := make(chan error, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeout(r.Context(), time.Second)
				defer cancel()
				until := time.Now().Add(100 * time.Millisecond)
				body := []byte(`{"status":"ok"}`)
				reply, err := ownOperationReply(ctx, OperationReply{Body: body, ValidUntil: until}, &replyGuardFixture{}, time.Now().Add(time.Second), func(context.Context, audit.OperationOutcome) error { return nil })
				if err == nil {
					err = reply.acknowledge(ctx, audit.OperationOutcome{OutputBytes: int64(len(body)), MetadataUntil: until})
				}
				defer reply.Close(ctx)
				if err == nil {
					_, err = WriteOperationReplyResponse(ctx, w, 200, reply.Body, reply, until, reply.CheckDisclosure)
				}
				if err == nil {
					n, lateErr := w.Write([]byte("unexpected"))
					if n != 0 || lateErr == nil || (!h2 && !errors.Is(lateErr, http.ErrContentLength)) {
						err = errors.New("additional application payload accepted")
					}
				}
				result <- err
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			response, err := server.Client().Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(data) != `{"status":"ok"}` || response.ProtoMajor != map[bool]int{false: 1, true: 2}[h2] {
				t.Fatal("payload/framing changed", err)
			}
			if err = <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOwnedResponseHTTP2FramingRetainsOriginalFiniteEnd(t *testing.T) {
	release := make(chan struct{})
	closed := make(chan error, 1)
	written := make(chan error, 1)
	var payloadEnd, originalEnd time.Time
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payloadEnd, originalEnd = time.Now().Add(100*time.Millisecond), time.Now().Add(350*time.Millisecond)
		ctx, cancel := context.WithDeadline(r.Context(), originalEnd)
		defer cancel()
		guard := &replyGuardFixture{close: func(ctx context.Context) error {
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		body := []byte(`{"status":"ok"}`)
		reply, err := ownOperationReply(ctx, OperationReply{Body: body, ValidUntil: payloadEnd}, guard, time.Now().Add(time.Second), func(context.Context, audit.OperationOutcome) error { return nil })
		if err == nil {
			err = reply.acknowledge(ctx, audit.OperationOutcome{OutputBytes: int64(len(body)), MetadataUntil: payloadEnd})
		}
		defer func() { closed <- reply.Close(ctx) }()
		if err == nil {
			_, err = WriteOperationReplyResponse(ctx, w, 200, reply.Body, reply, payloadEnd, reply.CheckDisclosure)
		}
		written <- err
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	client := server.Client()
	client.Timeout = 2 * time.Second
	r, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len(`{"status":"ok"}`))
	if _, err = io.ReadFull(r.Body, body); err != nil || !time.Now().Before(payloadEnd) {
		t.Fatal("payload missed original deadline", err)
	}
	tail, err := io.ReadAll(r.Body)
	if err == nil || len(tail) != 0 || time.Now().Before(originalEnd) || time.Now().After(originalEnd.Add(300*time.Millisecond)) {
		t.Fatal("finite original framing bound not retained", err)
	}
	select {
	case <-closed:
		t.Fatal("cleanup was not held")
	default:
	}
	close(release)
	if err = <-closed; err != nil {
		t.Fatal("independent joined cleanup failed", err)
	}
}

func TestOwnedResponseNoRoomKeepsSuccessfulWriteAndOriginalFence(t *testing.T) {
	for _, held := range []bool{false, true} {
		t.Run(map[bool]string{false: "immediate-close", true: "held-close"}[held], func(t *testing.T) {
			written := make(chan error, 1)
			closed := make(chan error, 1)
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var until time.Time
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeout(r.Context(), time.Second)
				defer cancel()
				until = time.Now().Add(100 * time.Millisecond)
				guard := &replyGuardFixture{}
				if held {
					guard.close = func(c context.Context) error { <-release; <-c.Done(); return c.Err() }
				}
				body := []byte(`{"status":"ok"}`)
				reply, err := ownOperationReply(ctx, OperationReply{Body: body, ValidUntil: until}, guard, until, func(context.Context, audit.OperationOutcome) error { return nil })
				if err == nil {
					err = reply.acknowledge(ctx, audit.OperationOutcome{OutputBytes: int64(len(body)), MetadataUntil: until})
				}
				defer func() { closed <- reply.Close(ctx) }()
				if err == nil {
					_, err = WriteOperationReplyResponse(ctx, w, 200, reply.Body, reply, until, reply.CheckDisclosure)
				}
				written <- err
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			client.Timeout = time.Second
			r, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Body.Close()
			if err = <-written; err != nil {
				t.Fatal("no-room invented writer failure", err)
			}
			body, err := io.ReadAll(r.Body)
			if string(body) != `{"status":"ok"}` {
				t.Fatal("payload changed")
			}
			if held {
				if err == nil || time.Now().Before(until) {
					t.Fatal("held cleanup escaped unchanged original fence", err)
				}
				close(release)
				if err = <-closed; err == nil {
					t.Fatal("expired cleanup fabricated success")
				}
			} else if err != nil {
				t.Fatal("immediate cleanup lost normal EOF", err)
			} else if err = <-closed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type framingWriter struct {
	*operationWriter
	mu        sync.Mutex
	deadlines []time.Time
	onFlush   func()
}

func (w *framingWriter) FlushError() error {
	if w.onFlush != nil {
		w.onFlush()
	}
	w.ResponseRecorder.Flush()
	return nil
}

func (w *framingWriter) SetWriteDeadline(at time.Time) error {
	w.mu.Lock()
	w.deadlines = append(w.deadlines, at)
	w.mu.Unlock()
	return w.operationWriter.SetWriteDeadline(at)
}

func TestOwnedResponseUnsentFailurePreservesHTTPFallback(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeout(r.Context(), time.Second)
				defer cancel()
				until := time.Now().Add(300 * time.Millisecond)
				reply, err := ownOperationReply(ctx, OperationReply{Body: []byte(`{"status":"ok","data":"sensitive"}`), ValidUntil: until}, &replyGuardFixture{}, time.Now().Add(time.Second), func(context.Context, audit.OperationOutcome) error { return nil })
				if err != nil {
					t.Error(err)
					return
				}
				defer reply.Close(ctx)
				// Missing audit acknowledgement is an actual pre-output refusal.
				if sent, err := WriteOperationReplyResponse(ctx, w, 200, reply.Body, reply, until, reply.CheckDisclosure); err == nil || sent {
					t.Error("unaudited output accepted")
					return
				}
				// The existing browser/MCP problem writers use WriteHeader and
				// json.Encoder; they do not clear a success Content-Length.
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"title": "Service Unavailable", "status": 503})
			}))
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			r, err := server.Client().Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || r.StatusCode != 503 || !json.Valid(body) || !bytes.Contains(body, []byte(`"status":503`)) {
				t.Fatal("fallback corrupted by success Content-Length", err, len(body))
			}
		})
	}
}

func TestOwnedResponseHandoffCannotReviveElapsedOrCanceledFence(t *testing.T) {
	for _, mode := range []string{"expired", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			writeCtx, cancelWrite := context.WithCancel(ctx)
			defer cancelWrite()
			until := time.Now().Add(100 * time.Millisecond)
			body := []byte(`{"status":"ok"}`)
			reply, err := ownOperationReply(ctx, OperationReply{Body: body, ValidUntil: until}, &replyGuardFixture{}, time.Now().Add(time.Second), func(context.Context, audit.OperationOutcome) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer reply.Close(context.Background())
			if err = reply.acknowledge(ctx, audit.OperationOutcome{OutputBytes: int64(len(body)), MetadataUntil: until}); err != nil {
				t.Fatal(err)
			}
			w := &framingWriter{operationWriter: &operationWriter{ResponseRecorder: httptest.NewRecorder()}}
			released := make(chan struct{})
			w.onFlush = func() {
				reply.owner.mu.Lock()
				go func() {
					defer close(released)
					defer reply.owner.mu.Unlock()
					if mode == "expired" {
						<-time.After(time.Until(until) + 10*time.Millisecond)
					} else {
						<-time.After(10 * time.Millisecond)
						cancelWrite()
					}
				}()
			}
			if sent, err := WriteOperationReplyResponse(writeCtx, w, 200, reply.Body, reply, until, reply.CheckDisclosure); err == nil || !sent {
				t.Fatal("fence revived after payload write", err)
			}
			<-released
			w.mu.Lock()
			defer w.mu.Unlock()
			if len(w.deadlines) != 1 || !w.deadlines[0].Equal(until) {
				t.Fatal("expired/canceled handoff reset socket deadline")
			}
		})
	}
}

func TestOwnedResponseFramingCannotRelaxFailedPayload(t *testing.T) {
	for _, mode := range []string{"success", "success-cleanup", "partial", "blocked", "cancelled", "unaudited", "no-room", "trailer", "trailer-prefix", "metadata"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			until := time.Now().Add(50 * time.Millisecond)
			body := []byte(`{"status":"ok"}`)
			cleanup := time.Now().Add(2 * time.Second)
			if mode == "success-cleanup" {
				cleanup = time.Now().Add(500 * time.Millisecond)
			}
			if mode == "no-room" {
				cleanup = until
			}
			reply, err := ownOperationReply(ctx, OperationReply{Body: body, ValidUntil: until}, &replyGuardFixture{}, cleanup, func(context.Context, audit.OperationOutcome) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer reply.Close(ctx)
			if mode != "unaudited" {
				if err = reply.acknowledge(ctx, audit.OperationOutcome{OutputBytes: int64(len(body)), MetadataUntil: until}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "metadata" {
				reply = OperationReply{Body: bytes.Clone(body), ValidUntil: until}
			}
			w := &framingWriter{operationWriter: &operationWriter{ResponseRecorder: httptest.NewRecorder(), short: mode == "partial"}}
			if mode == "blocked" {
				w.writeEntered, w.writeStop = make(chan struct{}), make(chan struct{})
			}
			if mode == "cancelled" {
				cancel()
			}
			if mode == "trailer" {
				w.Header().Set("Trailer", "Example")
			}
			if mode == "trailer-prefix" {
				w.Header()[http.TrailerPrefix+"Example"] = []string{"value"}
			}
			_, err = WriteOperationReplyResponse(ctx, w, 200, reply.Body, reply, until, reply.CheckDisclosure)
			success := mode == "success" || mode == "success-cleanup"
			if (success || mode == "metadata" || mode == "no-room") != (err == nil) {
				t.Fatal("wrong disposition", err)
			}
			w.mu.Lock()
			defer w.mu.Unlock()
			for _, at := range w.deadlines {
				// Existing cancellation deliberately sets an immediate deadline
				// using now, which may be just after the elapsed original cutoff.
				if at.After(until) && !success && !(mode == "blocked" && !at.After(time.Now())) {
					t.Fatal("failed/unowned payload relaxed deadline")
				}
				if success && at.After(until) {
					original, _ := ctx.Deadline()
					if mode == "success-cleanup" {
						original = cleanup
					}
					if !at.Equal(original) {
						t.Fatal("framing extended original request bound")
					}
				}
			}
			if success && len(w.deadlines) != 2 {
				t.Fatal("missing finite handoff")
			}
		})
	}
}

func (r *framingReader) ReadProjection(ctx context.Context, start value.ContextReadStart, owner analysisapp.ContextProjectionRequestOwner) (analysisapp.ContextProjectionRead, error) {
	read, err := r.bridgeFixture.ReadProjection(ctx, start, owner)
	return &framingRead{ContextProjectionRead: read, reader: r}, err
}

type framingRead struct {
	analysisapp.ContextProjectionRead
	reader *framingReader
}

func (r *framingRead) Close(ctx context.Context) error {
	close(r.reader.entered)
	select {
	case <-r.reader.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return r.ContextProjectionRead.Close(ctx)
}

func TestTypedQueryHTTP2FramingSurvivesJoinedCleanup(t *testing.T) {
	for _, mode := range []string{"browser", "mcp-envelope"} {
		t.Run(mode, func(t *testing.T) { typedQueryFraming(t, mode) })
	}
}
func typedQueryFraming(t *testing.T, mode string) {
	written := make(chan error, 1)
	closed := make(chan error, 1)
	reader := &framingReader{entered: make(chan struct{}), release: make(chan struct{})}
	var expected []byte
	var until time.Time
	var fixture *bridgeFixture
	var audited *AuditedOperations
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, f, _, p := bridgeAuditFixture(t)
		fixture, audited = f, s
		reader.bridgeFixture = f
		f.s.Results.Reader = reader
		p.adapter, _ = NewContextProjectionOperations(f.s, f.s.Results)
		f.a.ValidUntil = time.Now().Add(300 * time.Millisecond)
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		reply, err := s.Call(ctx, f, "get_file_excerpt", bridgeInput())
		if err != nil {
			written <- err
			return
		}
		expected, until = bytes.Clone(reply.Body), reply.ValidUntil
		defer func() { closed <- reply.Close(ctx) }()
		writeCtx, finish := reply.ResponseContext(ctx)
		defer finish()
		if mode == "browser" {
			_, err = WriteOperationReplyResponse(writeCtx, w, http.StatusOK, reply.Body, reply, until, reply.CheckDisclosure)
		} else {
			expected, err = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{map[string]string{"type": "text", "text": string(reply.Body)}}}})
			if err == nil {
				_, err = WriteOperationReplyResponse(writeCtx, w, http.StatusOK, expected, reply, until, reply.CheckDisclosure)
			}
		}
		written <- err
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer func() {
		select {
		case <-reader.release:
		default:
			close(reader.release)
		}
	}()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if err = <-written; err != nil {
		t.Fatal("payload write failed", err)
	}
	select {
	case <-reader.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actual read cleanup did not begin")
	}
	data := make([]byte, len(expected))
	if _, err = io.ReadFull(response.Body, data); err != nil || !bytes.Equal(data, expected) || !time.Now().Before(until) {
		t.Fatal("whole original payload not received before disclosure cutoff", err)
	}
	// The original byte deadline expires while cleanup is positively still held.
	<-time.After(time.Until(until) + 30*time.Millisecond)
	if fixture.completions != 0 || len(audited.lanes["normal"]) != 1 {
		t.Fatal("cleanup/slot released before actual join")
	}
	close(reader.release)
	tail, err := io.ReadAll(response.Body)
	if err != nil || len(tail) != 0 {
		t.Fatal("successful typed reply lost zero-payload EOF during joined cleanup", err)
	}
	if err = <-closed; err != nil || fixture.completions != 1 || len(audited.lanes["normal"]) != 0 {
		t.Fatal("actual C18 cleanup did not complete once", err)
	}
}
