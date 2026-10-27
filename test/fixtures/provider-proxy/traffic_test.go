//go:build ignore

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrafficExactWritesAndFiniteInputs(t *testing.T) {
	server := httptest.NewServer(trafficHandler())
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/traffic?records=17")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	n, err := io.Copy(io.Discard, response.Body)
	if err != nil || response.StatusCode != 200 || n != 17*trafficRecordBytes || response.Trailer.Get("X-Fixture-Traffic-Writes") != "17" || response.Trailer.Get("X-Fixture-Traffic-Bytes") != "1088" || response.Trailer.Get("X-Fixture-Traffic-Complete") != "true" {
		t.Fatal("finite synthetic stream did not match measured completion", n, err, response.Trailer)
	}
	for _, query := range []string{"records=0", "records=-1", "records=65537", "records=1&records=2", "other=1", "records=bad"} {
		response, err := server.Client().Get(server.URL + "/traffic?" + query)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatal("unbounded/unknown input accepted", query, response.StatusCode)
		}
	}
}

type deadlineWriter struct {
	*httptest.ResponseRecorder
	until  time.Time
	writes int
}

func (w *deadlineWriter) SetWriteDeadline(until time.Time) error { w.until = until; return nil }
func (w *deadlineWriter) Write(b []byte) (int, error) {
	w.writes++
	return w.ResponseRecorder.Write(b)
}

func TestTrafficPreservesOriginalDeadlineAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	request := httptest.NewRequest(http.MethodGet, "/traffic?records=1", nil).WithContext(ctx)
	trafficHandler().ServeHTTP(w, request)
	if !w.until.Equal(until) || w.writes != 1 {
		t.Fatal("traffic extended original deadline", w.until, until, w.writes)
	}
	cancel()
	w = &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	trafficHandler().ServeHTTP(w, request)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Fixture-Traffic-Max-Bytes") != "" {
		t.Fatal("canceled traffic request continued")
	}
}

func TestTrafficFullApplicationBudget(t *testing.T) {
	server := httptest.NewServer(trafficHandler())
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/traffic?records=65536")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	n, err := io.Copy(io.Discard, response.Body)
	if err != nil || n != trafficMaxPayload || response.Trailer.Get("X-Fixture-Traffic-Writes") != "65536" || response.Trailer.Get("X-Fixture-Traffic-Complete") != "true" {
		t.Fatal("actual traffic handler did not complete finite maximum", n, err, response.Trailer)
	}
	t.Logf("actual fixture handler: %d application bytes, 65536 completed flushed writes; packet count unmeasured", n)
}

// Model only the serialized route's observed per-batch delay. This is not a
// measurement of Kubernetes proxy internals or the installed capture path.
func TestTrafficClientDirectAvoidsSerializedProxyDelay(t *testing.T) {
	target := httptest.NewServer(trafficHandler())
	defer target.Close()
	parsed, _ := url.Parse(target.URL)
	proxy := httputil.NewSingleHostReverseProxy(parsed)
	delayed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(1100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		proxy.ServeHTTP(w, r)
	}))
	defer delayed.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 8500*time.Millisecond)
	indirect := runTrafficClient(ctx, delayed.URL)
	cancel()
	// The bounded delayed proxy must remain a failed measurement.
	if indirect.Failure == "" || indirect.Batches == 16 {
		t.Fatal("serialized proxy route unexpectedly completed the fixed traffic budget", indirect)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 8500*time.Millisecond)
	defer cancel()
	direct := runTrafficClient(ctx, target.URL)
	if direct.Failure != "" || direct.Batches != 16 || direct.Records != 65536 || direct.Bytes != 4194304 {
		t.Fatal("direct traffic incomplete", direct)
	}
	t.Logf("synthetic proxy: batches=%d bytes=%d elapsed=%s failure=%s; direct: batches=%d bytes=%d elapsed=%s", indirect.Batches, indirect.Bytes, indirect.Elapsed, indirect.Failure, direct.Batches, direct.Bytes, direct.Elapsed)
}

func TestTrafficClientNeverRetriesUnknownBatch(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result := runTrafficClient(ctx, server.URL)
	if result.Failure != "acknowledgement" || result.Batches != 0 || calls.Load() != 1 {
		t.Fatal("unknown batch retried", result, calls.Load())
	}
}
