package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
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
}

func (w *metadataDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *metadataDeadlineWriter) SetWriteDeadline(until time.Time) error {
	w.mu.Lock()
	w.until = until
	w.mu.Unlock()
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(until)
}
func (w *metadataDeadlineWriter) Write(p []byte) (int, error) {
	w.expected <- bytes.Clone(p)
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
