package browser

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// Actual TLS/HTTP2 transport and product factory/sink; the manually supplied
// metadata/response/leases are synthetic authority, not native worker proof.
// The structural assertion intentionally compiles before the new phase method
// exists, reproducing the original socket timeout rather than a compile error.
func TestNativeContentHTTP2BodySetupSurvivesOriginalPreflightDeadline(t *testing.T) {
	done := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		run := func() error {
			if req.ProtoMajor != 2 {
				return errors.New("HTTP2 was not negotiated")
			}
			preflightUntil := time.Now().Add(150 * time.Millisecond)
			if e := http.NewResponseController(w).SetWriteDeadline(preflightUntil); e != nil {
				return e
			}
			owner, cancel := context.WithTimeout(req.Context(), 3*time.Second)
			defer cancel()
			f := &contentResponseFactory{writer: w, request: req.WithContext(owner)}
			f.DownloadContentPreflightComplete(preflightUntil)
			originalEnd, _ := owner.Deadline()
			if receiver, ok := any(f).(interface {
				BeginDownloadContentBody(context.Context, time.Time) error
			}); ok {
				if e := receiver.BeginDownloadContentBody(owner, originalEnd); e != nil {
					return e
				}
			}
			// Fresh authority setup has no output. It completes after the old metadata
			// deadline, while the original whole response and new byte lease remain live.
			wait := time.NewTimer(time.Until(preflightUntil.Add(100 * time.Millisecond)))
			defer wait.Stop()
			select {
			case <-wait.C:
			case <-owner.Done():
				return owner.Err()
			}
			response, lease := responseDeliveryFixture(3, artifact.DownloadSelection{Length: 3})
			response.Until = originalEnd
			metadata := artifact.NativeDownloadMetadata{Filename: "context.json", ETag: `"original"`, Size: 3}
			sink, e := f.OpenDownloadResponse(owner, metadata, response)
			if e != nil {
				return e
			}
			defer sink.Close()
			piece, stop := context.WithDeadline(owner, lease.Until)
			defer stop()
			n, e := sink.WriteChunk(piece, lease, 0, []byte("abc"))
			if e != nil {
				return e
			}
			if n != 3 {
				return errors.New("incomplete native bytes")
			}
			return sink.Finish(owner)
		}
		done <- run()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	response, e := server.Client().Get(server.URL)
	if e != nil {
		<-done
		t.Fatalf("valid fresh content phase failed after old preflight deadline: %v", e)
	}
	defer response.Body.Close()
	body, e := io.ReadAll(response.Body)
	if e != nil || response.ProtoMajor != 2 || response.StatusCode != 200 || string(body) != "abc" {
		t.Fatalf("content: status=%d h2=%d bytes=%q error=%v", response.StatusCode, response.ProtoMajor, body, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestNativeHTTP2ResponseIdleBetweenFreshByteLeases(t *testing.T) {
	done := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		run := func() error {
			if req.ProtoMajor != 2 {
				return errors.New("HTTP2 was not negotiated")
			}
			response, first := responseDeliveryFixture(6, artifact.DownloadSelection{Length: 6})
			response.Until = time.Now().Add(3 * time.Second)
			first.Until = time.Now().Add(150 * time.Millisecond)
			first.Authority.ValidUntil = first.Until
			sink, e := NewHTTPDownloadResponse(w, req, artifact.NativeDownloadMetadata{Filename: "context.json", ETag: `"original"`, Size: 6}, response)
			if e != nil {
				return e
			}
			defer sink.Close()
			piece, stop := context.WithDeadline(req.Context(), first.Until)
			_, e = sink.WriteChunk(piece, first, 0, []byte("abc"))
			stop()
			if e != nil {
				return e
			}
			wait := time.NewTimer(time.Until(first.Until.Add(100 * time.Millisecond)))
			defer wait.Stop()
			select {
			case <-wait.C:
			case <-req.Context().Done():
				return req.Context().Err()
			}
			// A new current lease, rather than an extension of the old handle.
			_, next := responseDeliveryFixture(6, artifact.DownloadSelection{Length: 6})
			next.Sequence = 2
			next.Until = response.Until
			next.Authority.ValidUntil = next.Until
			piece, stop = context.WithDeadline(req.Context(), next.Until)
			defer stop()
			_, e = sink.WriteChunk(piece, next, 3, []byte("def"))
			if e != nil {
				return e
			}
			return sink.Finish(req.Context())
		}
		done <- run()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	response, e := server.Client().Get(server.URL)
	if e != nil {
		<-done
		t.Fatal(e)
	}
	defer response.Body.Close()
	body, e := io.ReadAll(response.Body)
	if e != nil || string(body) != "abcdef" || response.ProtoMajor != 2 {
		t.Fatalf("idle renewal: %q %v", body, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

type contentBodyDeadlineWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
	during    func()
}

func (w *contentBodyDeadlineWriter) SetWriteDeadline(d time.Time) error {
	w.deadlines = append(w.deadlines, d)
	if w.during != nil {
		w.during()
	}
	return nil
}

func TestNativeContentBodyPhaseKeepsOriginalBoundsAndRejectsRenewal(t *testing.T) {
	for _, mode := range []string{"bounded", "missing-ack", "expired-ack", "cancelled", "cancel-during-set", "repeat", "conditional"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			owner, cancel := context.WithDeadline(t.Context(), now.Add(2*time.Second))
			defer cancel()
			caller, end := context.WithDeadline(t.Context(), now.Add(time.Second))
			defer end()
			request := httptest.NewRequest("GET", "https://console.invalid/content", nil).WithContext(owner)
			w := &contentBodyDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
			f := &contentResponseFactory{writer: w, request: request}
			switch mode {
			case "missing-ack":
			case "expired-ack":
				f.DownloadContentPreflightComplete(now.Add(-time.Second))
			default:
				f.DownloadContentPreflightComplete(now.Add(500 * time.Millisecond))
			}
			if mode == "cancelled" {
				cancel()
			}
			if mode == "cancel-during-set" {
				w.during = cancel
			}
			if mode == "conditional" {
				if e := f.conditional(owner, 412, time.Now); e != nil {
					t.Fatal(e)
				}
				if len(w.deadlines) != 1 || !w.deadlines[0].Equal(f.until) || !f.bodyUntil.IsZero() {
					t.Fatal("conditional renewed the socket")
				}
				return
			}
			e := f.BeginDownloadContentBody(caller, now.Add(time.Hour))
			if mode == "bounded" || mode == "repeat" {
				if e != nil {
					t.Fatal(e)
				}
				want, _ := caller.Deadline()
				if !f.bodyUntil.Equal(want) || len(w.deadlines) != 1 || !w.deadlines[0].Equal(want) {
					t.Fatal("lost original caller bound")
				}
				if mode == "repeat" && f.BeginDownloadContentBody(caller, now.Add(2*time.Hour)) == nil {
					t.Fatal("body phase renewed")
				}
			} else if e == nil || !f.bodyUntil.IsZero() {
				t.Fatal("unacknowledged/expired/cancelled phase accepted")
			}
		})
	}
}
