package browser

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/presentation"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// The fault is explicit: only the first half of a real, audited metadata reply
// is flushed, then its ORIGINAL effective write deadline is allowed to expire.
// This is a transport possibility witness, not the installed failure's cause.
type metadataDeadlineWriter struct {
	http.ResponseWriter
	mu            sync.Mutex
	until         time.Time
	expected      chan []byte
	deadlineFault bool
	writeFault    bool
	afterFlush    func()
}

func (w *metadataDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *metadataDeadlineWriter) SetWriteDeadline(until time.Time) error {
	w.mu.Lock()
	w.until = until
	w.mu.Unlock()
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(until)
}
func (w *metadataDeadlineWriter) FlushError() error {
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err == nil && w.afterFlush != nil {
		w.afterFlush()
	}
	return err
}
func (w *metadataDeadlineWriter) Write(p []byte) (int, error) {
	w.expected <- bytes.Clone(p)
	if w.writeFault {
		n, _ := w.ResponseWriter.Write(p[:len(p)/2])
		return n, errors.New("private-provider-sentinel")
	}
	if !w.deadlineFault {
		return w.ResponseWriter.Write(p)
	}
	w.mu.Lock()
	until := w.until
	w.mu.Unlock()
	cut := len(p) / 2
	n, err := w.ResponseWriter.Write(p[:cut])
	if err != nil {
		return n, err
	}
	if err = http.NewResponseController(w.ResponseWriter).Flush(); err != nil {
		return n, err
	}
	ctx, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	<-ctx.Done()
	more, err := w.ResponseWriter.Write(p[cut:])
	return n + more, err
}

func TestAuditedBrowserHTTP2MetadataBodyLifetime(t *testing.T) {
	for _, deadlineFault := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "original-deadline-after-prefix"}[deadlineFault], func(t *testing.T) {
			expected := make(chan []byte, 1)
			reports := make(chan string, 4)
			var protocol int
			done := make(chan struct{})
			h, server, _, normal, _, _ := auditedBrowserTransportFixture(t, true, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(done)
					protocol = r.ProtoMajor
					next.ServeHTTP(&metadataDeadlineWriter{ResponseWriter: w, expected: expected, deadlineFault: deadlineFault}, r)
				})
			})
			h.Report = func(v string) { reports <- v }
			response, err := server.Client().Do(auditedBrowserRequest(t, server, "get_capture", `{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
			if err != nil {
				t.Fatal("headers unavailable", err)
			}
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			<-done
			original := <-expected
			begin, finish := normal.count()
			if protocol != 2 || response.StatusCode != 200 || begin != 1 || finish != 1 || !json.Valid(original) {
				t.Fatal("not actual audited HTTP2 metadata", protocol, response.StatusCode, begin, finish)
			}
			if !deadlineFault {
				if readErr != nil || !bytes.Equal(body, original) || !json.Valid(body) {
					t.Fatal("completed reply cleared before transport copied bytes", readErr)
				}
				select {
				case stage := <-reports:
					t.Fatal("successful reply reported failure", stage)
				default:
				}
			} else {
				if readErr == nil || len(body) == 0 || len(body) > len(original) || !bytes.Equal(body, original[:len(body)]) {
					t.Fatal("deadline did not reproduce unreadable200", readErr, len(body), len(original))
				}
				t.Logf("HTTP200 body bytes=%d/%d JSON-valid=%t; transport failed", len(body), len(original), json.Valid(body))
				// Diagnostic expectation intentionally exposes the current silent sent=true
				// branch; neither public body nor operation authority should be changed.
				select {
				case stage := <-reports:
					if stage != "response-write-started" {
						t.Fatal("unexpected stage", stage)
					}
				default:
					t.Fatal("started metadata failure has no closed diagnostic")
				}
			}
		})
	}
}

// Synthetic application replies isolate the actual HTTP handler/writer and
// cleanup ordering. They do not qualify C09 history or reproduce a Native cause.
type metadataReturnOperations struct {
	presentation.Operations
	reply func(context.Context) presentation.OperationReply
}

func (o metadataReturnOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if name == "list_capture_history" || name == "get_capture_settings" {
		return contracts.InvestigationTool{}, true
	}
	return o.Operations.Tool(name)
}
func (o metadataReturnOperations) Call(ctx context.Context, _ identities.CurrentIdentity, _ string, _ json.RawMessage) (presentation.OperationReply, error) {
	return o.reply(ctx), nil
}

func TestBrowserHTTP2MetadataFailureOnlyReturnEvidence(t *testing.T) {
	for _, name := range []string{"list_diagnostics", "list_capture_history", "get_capture_settings", "get_capture"} {
		modes := []string{"complete", "write-error", "metadata-expired", "deadline", "canceled"}
		if name == "get_capture" {
			modes = []string{"metadata-expired"}
		}
		for _, mode := range modes {
			t.Run(name+"/"+mode, func(t *testing.T) {
				reports := make(chan string, 4)
				done, released := make(chan struct{}), make(chan struct{})
				expected := make(chan []byte, 1)
				var h *InvestigationHandler
				var protocol int
				var replyBody []byte
				var cancelParent context.CancelFunc
				hold := mode == "metadata-expired" || mode == "deadline" || mode == "canceled"
				handler, server, _, _, _, _ := auditedBrowserTransportFixture(t, true, func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						defer close(done)
						protocol = r.ProtoMajor
						parent, cancel := context.WithCancel(r.Context())
						cancelParent = cancel
						defer cancel()
						if mode == "deadline" {
							var stop context.CancelFunc
							parent, stop = context.WithTimeout(parent, 500*time.Millisecond)
							defer stop()
						}
						writer := &metadataDeadlineWriter{ResponseWriter: w, expected: expected, writeFault: mode == "write-error"}
						if hold {
							writer.afterFlush = func() {
								// Controlled cleanup fault only: after a successful flush, hold the
								// EXISTING active-accounting mutex until the chosen original boundary.
								// This is not evidence of normal contention or the installed cause.
								h.mu.Lock()
								writer.mu.Lock()
								until := writer.until
								writer.mu.Unlock()
								if mode == "canceled" {
									until = time.Now().Add(500 * time.Millisecond)
								}
								go func() {
									timer := time.NewTimer(time.Until(until))
									defer timer.Stop()
									<-timer.C
									if mode == "canceled" {
										cancelParent()
									}
									h.mu.Unlock()
									close(released)
								}()
							}
						}
						next.ServeHTTP(writer, r.WithContext(parent))
						if hold {
							<-released
						}
					})
				})
				h = handler
				h.operations = metadataReturnOperations{Operations: h.operations, reply: func(ctx context.Context) presentation.OperationReply {
					replyBody = []byte(`{"status":"ok","result":{}}`)
					until := time.Now().Add(2 * time.Second)
					if mode == "metadata-expired" {
						until = time.Now().Add(500 * time.Millisecond)
					}
					if end, _ := ctx.Deadline(); end.Before(until) {
						until = end
					}
					return presentation.OperationReply{Body: replyBody, ValidUntil: until}
				}}
				h.Report = func(stage string) {
					if strings.HasPrefix(stage, "response-return/") {
						h.mu.Lock()
						active := len(h.active)
						h.mu.Unlock()
						if active != 0 || len(h.slots) != 0 || !bytes.Equal(replyBody, make([]byte, len(replyBody))) {
							t.Error("return diagnostic preceded normal cleanup")
						}
					}
					reports <- stage
				}
				response, err := server.Client().Do(auditedBrowserRequest(t, server, name, `{}`))
				if err != nil {
					t.Fatal("actual H2 headers", err)
				}
				body, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				<-done
				if protocol != 2 || response.StatusCode != 200 {
					t.Fatal("not an actual H2 operation reply", protocol, response.StatusCode)
				}
				var original []byte
				select {
				case original = <-expected:
				default:
					t.Fatal("writer did not receive body")
				}
				if mode == "complete" && (readErr != nil || !bytes.Equal(body, original)) {
					t.Fatal("successful metadata body changed", readErr)
				}
				if !bytes.HasPrefix(original, body) {
					t.Fatal("changed response or synthetic transport", protocol, response.StatusCode)
				}
				want := ""
				if name != "get_capture" {
					if mode == "write-error" {
						want = "response-write-started/" + name
					} else if mode != "complete" {
						want = "response-return/canceled/metadata-live/" + name
					}
				}
				select {
				case got := <-reports:
					// H2 stream timeout can cancel its request, and the context timer
					// can publish after its wall deadline. These are distinct observed
					// states, not proof of which boundary caused the installed failure.
					if name != "get_capture" && (mode == "metadata-expired" || mode == "deadline") {
						allowed := got == "response-return/live/metadata-expired/"+name || got == "response-return/canceled/metadata-expired/"+name || got == "response-return/deadline/metadata-expired/"+name
						if !allowed {
							t.Fatal("nonclosed expiry evidence", got)
						}
					} else if want == "" || got != want || strings.Contains(got, "private-provider") {
						t.Fatal("wrong closed failure evidence", got, want)
					}
				default:
					if want != "" {
						t.Fatal("missing closed failure evidence", want)
					}
				}
				select {
				case extra := <-reports:
					t.Fatal("duplicate failure evidence", extra)
				default:
				}
			})
		}
	}
}

func TestBrowserMetadataReturnReasonRetainsBothBoundaryFacts(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	<-expired.Done()
	for _, test := range []struct {
		ctx   context.Context
		until time.Time
		want  string
	}{
		{canceled, time.Now().Add(time.Minute), "canceled/metadata-live"},
		{canceled, time.Now().Add(-time.Second), "canceled/metadata-expired"},
		{expired, time.Now().Add(time.Minute), "deadline/metadata-live"},
		{expired, time.Now().Add(-time.Second), "deadline/metadata-expired"},
		{context.Background(), time.Now().Add(-time.Second), "live/metadata-expired"},
		{context.Background(), time.Now().Add(time.Minute), ""},
	} {
		if got := metadataReturnReason(test.ctx, test.until); got != test.want {
			t.Fatal("wrong closed original boundary", got, test.want)
		}
	}
}
