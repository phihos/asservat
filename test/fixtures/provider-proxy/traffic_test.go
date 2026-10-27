//go:build ignore

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
