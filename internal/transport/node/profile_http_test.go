package node

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

type gatedProfileBody struct{ entered, release, joined chan struct{} }

func (r gatedProfileBody) Read([]byte) (int, error) {
	close(r.entered)
	<-r.release
	close(r.joined)
	return 0, io.ErrUnexpectedEOF
}

func TestProfileUploadCancellationJoinsTransportReaderBeforeReturning(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := &Client{base: base, http: server.Client()}
	const id = "11111111-1111-4111-8111-111111111111"
	now := time.Now().UTC()
	r := collector.ProfileResult{CaptureID: id, WorkID: id, ExpectationDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true, ResponseComplete: true, NativeBytes: 1}}
	body := gatedProfileBody{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.UploadProfileStream(ctx, id, r, body) }()
	select {
	case <-body.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("native body reader not reached")
	}
	cancel()
	var early bool
	select {
	case <-done:
		early = true
	case <-time.After(100 * time.Millisecond):
	}
	close(body.release)
	select {
	case <-body.joined:
	case <-time.After(time.Second):
		t.Fatal("native body reader did not join")
	}
	if early {
		t.Fatal("upload returned ownership while transport still read the native buffer")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled upload claimed success")
		}
	case <-time.After(time.Second):
		t.Fatal("joined upload did not return")
	}
}
