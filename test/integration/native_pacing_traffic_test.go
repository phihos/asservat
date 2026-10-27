package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

const nativeTrafficRecords = 65536
const nativeTrafficRecordBytes = 64
const nativeTrafficPayload = nativeTrafficRecords * nativeTrafficRecordBytes
const nativeTrafficBatches = 16
const nativeTrafficRecordsPerBatch = nativeTrafficRecords / nativeTrafficBatches
const nativeTrafficInterval = 500 * time.Millisecond
const nativeTrafficPhase = 8500 * time.Millisecond

type nativeTrafficResult struct {
	Batches, Records, Bytes int64
	Elapsed                 time.Duration
}

// The installed caller supplies a stream to the exact selected Pod's existing
// /traffic endpoint, after the exact accepted source reports Running. Capture/traffic timestamp overlap
// must be measured by the installed caller. No retry/target choice
// occurs here. Sixteen batches spread finite traffic over a ten-second capture.
func nativePacingTraffic(ctx context.Context, open func(context.Context, int) (*http.Response, error)) (out nativeTrafficResult, err error) {
	started := time.Now()
	defer func() { out.Elapsed = time.Since(started) }()
	if ctx == nil || open == nil || ctx.Err() != nil {
		return out, errors.New("traffic caller unavailable")
	}
	phase, cancel := context.WithTimeout(ctx, nativeTrafficPhase)
	defer cancel()
	for i := range nativeTrafficBatches {
		wait := time.NewTimer(max(0, time.Until(started.Add(time.Duration(i)*nativeTrafficInterval))))
		select {
		case <-phase.Done():
			wait.Stop()
			return out, phase.Err()
		case <-wait.C:
		}
		response, err := open(phase, nativeTrafficRecordsPerBatch)
		if err != nil {
			return out, err
		}
		if response == nil || response.Body == nil {
			return out, errors.New("traffic stream missing")
		}
		expected := int64(nativeTrafficRecordsPerBatch * nativeTrafficRecordBytes)
		read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, expected+1))
		response.Body.Close()
		out.Bytes += read
		if readErr != nil || response.StatusCode != http.StatusOK || read != expected || response.Header.Get("X-Fixture-Traffic-Max-Bytes") != strconv.FormatInt(expected, 10) || response.Trailer.Get("X-Fixture-Traffic-Writes") != strconv.Itoa(nativeTrafficRecordsPerBatch) || response.Trailer.Get("X-Fixture-Traffic-Bytes") != strconv.FormatInt(expected, 10) || response.Trailer.Get("X-Fixture-Traffic-Complete") != "true" {
			return out, errors.New("traffic did not acknowledge exact bounded batch")
		}
		out.Batches++
		out.Records += nativeTrafficRecordsPerBatch
	}
	return out, phase.Err()
}

// A measured small artifact never qualifies the near-full-window experiment.
// The 64 KiB tolerance covers final format blocks without increasing the cap.
func nativePacingRequireNearFullRecording(size int64) error {
	if size < artifact.RecordingNativeLimit-nativePacingWindow || size > artifact.RecordingNativeLimit {
		return fmt.Errorf("near-full qualification requires %d..%d measured native bytes; got %d", artifact.RecordingNativeLimit-nativePacingWindow, artifact.RecordingNativeLimit, size)
	}
	return nil
}

func TestNativePacingTrafficBoundedBatches(t *testing.T) {
	// The runner consumes the same bounded receipt protocol. The actual
	// ignored provider handler has separate explicit-file HTTP unit tests.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		records, err := strconv.Atoi(r.URL.Query().Get("records"))
		if err != nil || records != nativeTrafficRecordsPerBatch {
			t.Error("unexpected batch request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Fixture-Traffic-Max-Bytes", strconv.Itoa(records*nativeTrafficRecordBytes))
		w.Header().Set("Trailer", "X-Fixture-Traffic-Writes, X-Fixture-Traffic-Bytes, X-Fixture-Traffic-Complete")
		var record [nativeTrafficRecordBytes]byte
		for range records {
			if _, err := w.Write(record[:]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		w.Header().Set("X-Fixture-Traffic-Writes", strconv.Itoa(records))
		w.Header().Set("X-Fixture-Traffic-Bytes", strconv.Itoa(records*nativeTrafficRecordBytes))
		w.Header().Set("X-Fixture-Traffic-Complete", "true")
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var calls int
	result, err := nativePacingTraffic(ctx, func(ctx context.Context, records int) (*http.Response, error) {
		calls++
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/traffic?records="+strconv.Itoa(records), nil)
		return server.Client().Do(request)
	})
	if err != nil || calls != nativeTrafficBatches || result.Records != nativeTrafficRecords || result.Bytes != nativeTrafficPayload || result.Elapsed > nativeTrafficPhase {
		t.Fatal("traffic exceeded finite application budget or missed completion", err, calls, result)
	}
	t.Logf("loopback traffic: %d batches/%d writes/%d application bytes in %.3fs; packet/native size remains unmeasured", result.Batches, result.Records, result.Bytes, result.Elapsed.Seconds())
}

func TestNativePacingTrafficNoRetryAndMeasuredSizeGate(t *testing.T) {
	var calls int
	if _, err := nativePacingTraffic(t.Context(), func(context.Context, int) (*http.Response, error) {
		calls++
		return nil, errors.New("synthetic unknown batch outcome")
	}); err == nil || calls != 1 {
		t.Fatal("unknown traffic batch retried", calls, err)
	}
	for _, size := range []int64{4096, artifact.RecordingNativeLimit - nativePacingWindow - 1, artifact.RecordingNativeLimit + 1} {
		if nativePacingRequireNearFullRecording(size) == nil {
			t.Fatal("tiny or oversized artifact relabeled as near-full", size)
		}
	}
	if err := nativePacingRequireNearFullRecording(artifact.RecordingNativeLimit - nativePacingWindow); err != nil {
		t.Fatal(err)
	}
}
