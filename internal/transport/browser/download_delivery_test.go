package browser

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeHTTPDeliveryAndRanges(t *testing.T) {
	native := []byte("synthetic native evidence\n")
	m := artifact.NativeDownloadMetadata{Filename: "artifact-1.json", ETag: `"v1"`, Size: int64(len(native)), SHA256: sha256.Sum256(native)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selection, err := selectNativeRange(m.Size, m.ETag, r.Header.Get("Range"), r.Header.Get("If-Match"), r.Header.Get("If-Range"))
		if err != nil {
			status := http.StatusRequestedRangeNotSatisfiable
			if err == errPrecondition {
				status = http.StatusPreconditionFailed
			}
			w.WriteHeader(status)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		sink := &HTTPDownloadDestination{Writer: w, Request: r}
		n, err := sink.Send(ctx, m, artifact.DownloadSelection{Offset: selection.Offset, Length: selection.Length, Partial: selection.Partial}, native[selection.Offset:selection.Offset+selection.Length])
		if err != nil || n != selection.Length {
			t.Errorf("send %d %v", n, err)
		}
	}))
	defer server.Close()
	for _, tc := range []struct {
		name, rng, match, ifRange string
		status                    int
		body, contentRange        string
	}{
		{"full", "", "", "", 200, string(native), ""},
		{"resume", "bytes=10-", `"v1"`, "", 206, string(native[10:]), "bytes 10-25/26"},
		{"checked mismatch", "bytes=10-", `"v2"`, "", 412, "", ""},
		{"standard fallback", "bytes=10-", "", `"v2"`, 200, string(native), ""},
		{"unsatisfiable", "bytes=99-", "", "", 416, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
			request.Header.Set("Range", tc.rng)
			if tc.match != "" {
				request.Header.Set("If-Match", tc.match)
			}
			request.Header.Set("If-Range", tc.ifRange)
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != tc.status || string(body) != tc.body {
				t.Fatalf("status %d length %d err %v", response.StatusCode, len(body), err)
			}
			if tc.status == 200 || tc.status == 206 {
				for key, want := range map[string]string{"ETag": `"v1"`, "Content-Type": "application/octet-stream", "Content-Range": tc.contentRange, "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff", "Content-Disposition": "attachment; filename=artifact-1.json", "Accept-Ranges": "bytes"} {
					if response.Header.Get(key) != want {
						t.Fatalf("%s: %q", key, response.Header.Get(key))
					}
				}
				if response.ContentLength != int64(len(body)) || response.Uncompressed {
					t.Fatal("native representation transformed")
				}
			}
		})
	}
}
func TestNativeHTTPSinkRejectsBeforeHeaders(t *testing.T) {
	for _, tc := range []string{"no TLS", "no deadline", "expired", "long lease", "bad filename", "bad range", "compressed", "no deadline support"} {
		t.Run(tc, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://app.invalid/download", nil)
			w := httptest.NewRecorder()
			ctx, cancel := context.WithTimeout(r.Context(), time.Second)
			defer cancel()
			m := artifact.NativeDownloadMetadata{Filename: "file.bin", ETag: `"v1"`, Size: 3}
			selection := artifact.DownloadSelection{Length: 3}
			switch tc {
			case "no TLS":
				r.TLS = nil
			case "no deadline":
				ctx = context.Background()
			case "expired":
				cancel()
			case "long lease":
				var c context.CancelFunc
				ctx, c = context.WithTimeout(r.Context(), time.Minute)
				defer c()
			case "bad filename":
				m.Filename = "../core\r\nsecret"
			case "bad range":
				selection.Length = 4
			case "compressed":
				w.Header().Set("Content-Encoding", "gzip")
			}
			s := &HTTPDownloadDestination{Writer: w, Request: r}
			if n, err := s.Send(ctx, m, selection, []byte("abc")); err == nil || n != 0 || s.HeadersSent() || w.Body.Len() != 0 {
				t.Fatal("failed request disclosed bytes", n, err)
			}
		})
	}
}

// The cancellation callback can already be running when Send returns from a
// blocked writer. Its deadline mutation must finish before the response and
// underlying connection can be reused by the caller.
func TestNativeHTTPSinkJoinsRunningDeadlineCallback(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://app.invalid/download", nil)
	ctx, cancel := context.WithTimeout(request.Context(), 4*time.Second)
	defer cancel()
	writer := &blockedDownloadDeadlineWriter{
		ResponseRecorder: httptest.NewRecorder(), cancel: cancel,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	returned := make(chan error, 1)
	go func() {
		sink := &HTTPDownloadDestination{Writer: writer, Request: request}
		_, err := sink.Send(ctx, artifact.NativeDownloadMetadata{Filename: "file.bin", ETag: `"v1"`, Size: 3}, artifact.DownloadSelection{Length: 3}, []byte("abc"))
		returned <- err
	}()
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		close(writer.release)
		t.Fatal("cancellation callback did not enter the deadline writer")
	}
	early := false
	select {
	case <-returned:
		early = true
	case <-time.After(25 * time.Millisecond):
	}
	close(writer.release)
	if early {
		t.Fatal("Send returned while its cancellation callback could still mutate the connection deadline")
	}
	select {
	case err := <-returned:
		if err != context.Canceled {
			t.Fatalf("expected cancelled writer result, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Send did not finish after its cancellation callback completed")
	}
}

type blockedDownloadDeadlineWriter struct {
	*httptest.ResponseRecorder
	cancel           context.CancelFunc
	entered, release chan struct{}
	deadlines        atomic.Int32
}

func (w *blockedDownloadDeadlineWriter) SetWriteDeadline(time.Time) error {
	if w.deadlines.Add(1) > 1 {
		close(w.entered)
		<-w.release
	}
	return nil
}
func (w *blockedDownloadDeadlineWriter) Write([]byte) (int, error) {
	w.cancel()
	<-w.entered
	return 0, context.Canceled
}
