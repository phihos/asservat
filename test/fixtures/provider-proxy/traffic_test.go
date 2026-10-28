//go:build ignore

package main

import (
	"context"
	"encoding/json"
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
	started := time.Now()
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
	t.Logf("actual fixture handler: %d application bytes, 65536 completed flushed writes; wall=%s, CPU/packet count unmeasured", n, time.Since(started))
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

// The final batch needs 1.2s of modeled work at the actual Write/Flush boundary.
// This exposes the fixed schedule's available tail; it is not a reconstruction
// of installed CPU, network, collector timing or packet counts.
type variableTrafficWriter struct {
	http.ResponseWriter
	ctx    context.Context
	writes int
	slow   bool
}

func (w *variableTrafficWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *variableTrafficWriter) Write(b []byte) (int, error) {
	if w.slow && w.writes%1024 == 0 {
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-w.ctx.Done():
			return 0, w.ctx.Err()
		case <-timer.C:
		}
	}
	w.writes++
	return w.ResponseWriter.Write(b)
}
func TestTrafficClientVariableBatchWorkFitsOriginalPhase(t *testing.T) {
	var calls atomic.Int64
	handler := trafficHandler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		batch := int(calls.Add(1)) - 1
		if batch < 0 || batch >= 16 {
			t.Error("traffic batch was replayed")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		delay := time.Duration(batch%5) * 20 * time.Millisecond
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		handler.ServeHTTP(&variableTrafficWriter{ResponseWriter: w, ctx: r.Context(), slow: batch == 15}, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 8500*time.Millisecond)
	defer cancel()
	result := runTrafficClient(ctx, server.URL)
	if result.Failure != "" || result.Batches != 16 || result.Records != 65536 || result.Bytes != 4194304 || !result.LastAcknowledged || calls.Load() != 16 {
		t.Fatal("unchanged phase did not leave tail for representative variable HTTP work", result, calls.Load())
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > 2048 || result.WaitElapsed <= 0 || result.WorkElapsed <= 0 || result.WaitElapsed > result.Elapsed || result.WorkElapsed > result.Elapsed-result.WaitElapsed {
		t.Fatal("unbounded or unavailable wall timing", result, len(raw), err)
	}
	t.Logf("actual helper+handler with synthetic variable batch work: batches=%d records=%d bytes=%d wall=%s wait=%s HTTPwork=%s receipt=%dB (notCPU)", result.Batches, result.Records, result.Bytes, result.Elapsed, result.WaitElapsed, result.WorkElapsed, len(raw))
}
