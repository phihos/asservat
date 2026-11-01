package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const nativePacingWindow = 64 << 10
const nativePacingChunk = 32 << 10
const nativePacingInterval = 25 * time.Millisecond

// Qualification client only: keep the installed TLS/route configuration while
// making final-client reads exert backpressure on the real HTTP/2 writer.
func nativePacingClient(base *http.Transport) (*http.Client, func()) {
	t := base.Clone()
	t.ForceAttemptHTTP2 = true
	t.HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerConnection: nativePacingWindow, MaxReceiveBufferPerStream: nativePacingWindow}
	return &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, t.CloseIdleConnections
}

type nativePacingSelection struct {
	Offset, Length, Total int64
	ETag                  string
	SHA256                [32]byte
	Partial               bool
}

type nativePacingResult struct {
	Bytes   int64
	SHA256  [32]byte
	Elapsed time.Duration
}

// Consume uses one fixed buffer and never retries. A caller can pass a shared
// hash/file writer for successive ranges. Selection facts come from verified
// download metadata; this helper creates no authority or deadline.
func nativePacingConsume(ctx context.Context, response *http.Response, selection nativePacingSelection, destination io.Writer, interval time.Duration) (out nativePacingResult, err error) {
	started := time.Now()
	defer func() { out.Elapsed = time.Since(started) }()
	if response == nil || response.Body == nil {
		return out, errors.New("missing native response")
	}
	defer response.Body.Close()
	if ctx == nil || ctx.Err() != nil || destination == nil || selection.Offset < 0 || selection.Length < 1 || selection.Total < selection.Length || selection.Offset > selection.Total-selection.Length || !selection.Partial && (selection.Offset != 0 || selection.Length != selection.Total) || interval < 0 || interval > time.Second {
		return out, errors.New("invalid paced selection")
	}
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = response.Body.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	if _, bounded := ctx.Deadline(); !bounded {
		return out, errors.New("paced transfer requires original deadline")
	}
	status, contentRange := http.StatusOK, ""
	if selection.Partial {
		status = http.StatusPartialContent
		contentRange = fmt.Sprintf("bytes %d-%d/%d", selection.Offset, selection.Offset+selection.Length-1, selection.Total)
	}
	if response.ProtoMajor != 2 || response.StatusCode != status || response.Header.Get("Content-Range") != contentRange || response.ContentLength != selection.Length || response.Header.Get("ETag") != selection.ETag {
		return out, errors.New("native HTTP/2 selection metadata mismatch")
	}
	digest := sha256.New()
	sink := io.MultiWriter(destination, digest)
	buffer := make([]byte, nativePacingChunk)
	defer clear(buffer)
	for {
		if interval > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return out, ctx.Err()
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		n, readErr := io.ReadFull(response.Body, buffer)
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if int64(n) > selection.Length-out.Bytes {
			return out, errors.New("native response exceeded selected range")
		}
		if n > 0 {
			if _, err := sink.Write(buffer[:n]); err != nil {
				return out, err
			}
			out.Bytes += int64(n)
		}
		if readErr != nil {
			if readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
				return out, readErr
			}
			break
		}
	}
	copy(out.SHA256[:], digest.Sum(nil))
	if out.Bytes != selection.Length || out.SHA256 != selection.SHA256 || ctx.Err() != nil {
		return out, errors.New("native streaming bytes/hash mismatch or original deadline ended")
	}
	return out, nil
}
