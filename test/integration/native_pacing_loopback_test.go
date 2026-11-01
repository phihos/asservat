package integration

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic bytes only. No packet parser, capture, collector or provider facts.
type nativePacingPattern struct{ size, offset int64 }

func (p *nativePacingPattern) Read(b []byte) (int, error) {
	if p.offset == p.size {
		return 0, io.EOF
	}
	n := min(int64(len(b)), p.size-p.offset)
	for i := range int(n) {
		b[i] = byte((p.offset+int64(i))*31 + 7)
	}
	p.offset += n
	return int(n), nil
}
func (p *nativePacingPattern) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekCurrent:
		offset += p.offset
	case io.SeekEnd:
		offset += p.size
	case io.SeekStart:
	default:
		return 0, fmt.Errorf("seek mode")
	}
	if offset < 0 || offset > p.size {
		return 0, fmt.Errorf("seek range")
	}
	p.offset = offset
	return offset, nil
}
func nativePatternDigest(size, offset, length int64) [32]byte {
	digest := sha256.New()
	_, _ = io.CopyN(digest, &nativePacingPattern{size: size, offset: offset}, length)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

type nativePacingWriter struct {
	http.ResponseWriter
	bytes *atomic.Int64
	first chan struct{}
}

func (w nativePacingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 && w.bytes.Add(int64(n)) == int64(n) {
		close(w.first)
	}
	return n, err
}

func TestNativePacingHTTP2BackpressureAndStreamingResume(t *testing.T) {
	const size = (8 << 20) - (64 << 10)
	const etag = `"synthetic-native-version"`
	var written, writerNanos atomic.Int64
	first, completed := make(chan struct{}), make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		if r.URL.Path == "/whole" {
			started := time.Now()
			defer func() { writerNanos.Store(int64(time.Since(started))); close(completed) }()
			w = nativePacingWriter{w, &written, first}
		}
		http.ServeContent(w, r, "synthetic.bin", time.Unix(1, 0), &nativePacingPattern{size: size})
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client, closeClient := nativePacingClient(server.Client().Transport.(*http.Transport))
	defer closeClient()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/whole", nil)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	select {
	case <-first:
	case <-ctx.Done():
		t.Fatal("writer never started", ctx.Err())
	}
	// Wait after a real write, not merely before the handler gets scheduled.
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-completed:
		t.Fatal("whole body escaped final-client flow control before consumption")
	case <-timer.C:
	}
	buffered := written.Load()
	if buffered < 1 || buffered > 4*nativePacingWindow {
		t.Fatal("small receive windows did not bound server write-ahead", buffered)
	}
	selection := nativePacingSelection{Length: size, Total: size, ETag: etag, SHA256: nativePatternDigest(size, 0, size)}
	whole, err := nativePacingConsume(ctx, response, selection, io.Discard, nativePacingInterval)
	if err != nil || whole.Elapsed <= 5*time.Second || whole.Bytes != size {
		t.Fatal("paced whole streaming transfer", err, whole)
	}
	select {
	case <-completed:
	case <-ctx.Done():
		t.Fatal("writer did not join", ctx.Err())
	}
	if time.Duration(writerNanos.Load()) <= 5*time.Second {
		t.Fatal("reader was slow but server escaped backpressure", time.Duration(writerNanos.Load()))
	}
	// Two independently requested exact ranges reconstruct the same artifact.
	// Only the streaming hash is retained; no near-8 MiB client buffer exists.
	joined := sha256.New()
	for _, span := range [][2]int64{{0, size / 2}, {size / 2, size - size/2}} {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/range", nil)
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", span[0], span[0]+span[1]-1))
		request.Header.Set("If-Range", etag)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		selection := nativePacingSelection{Offset: span[0], Length: span[1], Total: size, ETag: etag, Partial: true, SHA256: nativePatternDigest(size, span[0], span[1])}
		if _, err := nativePacingConsume(ctx, response, selection, joined, nativePacingInterval); err != nil {
			t.Fatal("streaming range/resume", err)
		}
	}
	var joinedDigest [32]byte
	copy(joinedDigest[:], joined.Sum(nil))
	if joinedDigest != selection.SHA256 {
		t.Fatal("resumed ranges changed exact native hash")
	}
	t.Logf("real loopback HTTP/2 TLS: %d synthetic bytes, before-read server write-ahead %d bytes, whole %.3fs, blocked writer %.3fs, exact streaming whole/range/resume SHA-256", size, buffered, whole.Elapsed.Seconds(), time.Duration(writerNanos.Load()).Seconds())
}
