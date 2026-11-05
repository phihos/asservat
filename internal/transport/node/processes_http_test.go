package node

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestProcessUploadCancellationRetainsNativeUntilHTTPReaderJoins(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := &Client{base: base, http: server.Client()}
	const id = "11111111-1111-4111-8111-111111111111"
	now := time.Now().UTC()
	result := collector.ProcessResult{CaptureID: id, WorkID: id, PodUID: id, NodeUID: id, NodeBootID: id, ExpectationDigest: artifact.Digest{1}, StartedAt: now, CompletedAt: now, NativeBytes: 1}
	body := gatedProfileBody{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.UploadProcessesStream(ctx, id, result, body) }()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		t.Fatal("body not reached")
	}
	cancel()
	early := false
	select {
	case <-done:
		early = true
	case <-time.After(100 * time.Millisecond):
	}
	close(body.release)
	select {
	case <-body.joined:
	case <-time.After(time.Second):
		t.Fatal("transport reader not joined")
	}
	if early {
		t.Fatal("native ownership released before body reader joined")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled upload claimed success")
		}
	case <-time.After(time.Second):
		t.Fatal("joined upload not returned")
	}
}
