package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNativePacingRejectsFalseQualification(t *testing.T) {
	for _, mode := range []string{"http1", "wrong-range", "wrong-size", "wrong-hash", "truncated", "overlong", "wrong-etag", "unbounded"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			selection := nativePacingSelection{Length: 1, Total: 1, ETag: `"version"`, SHA256: sha256.Sum256([]byte("x"))}
			response := &http.Response{ProtoMajor: 2, StatusCode: 200, ContentLength: 1, Header: http.Header{"Etag": []string{selection.ETag}}, Body: io.NopCloser(strings.NewReader("x"))}
			switch mode {
			case "http1":
				response.ProtoMajor = 1
			case "wrong-range":
				selection.Partial = true
			case "wrong-size":
				response.ContentLength = 2
			case "wrong-hash":
				selection.SHA256[0]++
			case "truncated":
				response.Body = io.NopCloser(strings.NewReader(""))
			case "overlong":
				response.Body = io.NopCloser(strings.NewReader("xx"))
			case "wrong-etag":
				response.Header.Set("ETag", `"other"`)
			case "unbounded":
				ctx = context.Background()
			}
			if _, err := nativePacingConsume(ctx, response, selection, io.Discard, 0); err == nil {
				t.Fatal("invalid response accepted as paced native qualification", mode)
			}
		})
	}
}

func TestNativePacingOriginalDeadlineClosesBlockedRead(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	selection := nativePacingSelection{Length: 1, Total: 1, ETag: `"version"`, SHA256: sha256.Sum256([]byte("x"))}
	response := &http.Response{ProtoMajor: 2, StatusCode: 200, ContentLength: 1, Header: http.Header{"Etag": []string{selection.ETag}}, Body: reader}
	var destination bytes.Buffer
	if _, err := nativePacingConsume(ctx, response, selection, &destination, 0); err == nil || destination.Len() != 0 || ctx.Err() == nil {
		t.Fatal("blocked read escaped original caller deadline", err, destination.Len())
	}
}

func TestNativePacingWriteHookRunsOnce(t *testing.T) {
	calls := 0
	var out bytes.Buffer
	hook := &nativePacingWriteHook{writer: &out, hook: func() error { calls++; return nil }}
	for range 2 {
		if n, err := hook.Write([]byte("x")); err != nil || n != 1 {
			t.Fatal("paced write hook", n, err)
		}
	}
	if calls != 1 || out.String() != "xx" {
		t.Fatal("write hook did not preserve delivery", calls, out.String())
	}
	failure := &nativePacingWriteHook{writer: &out, hook: func() error { calls++; return context.Canceled }}
	for range 2 {
		if n, err := failure.Write([]byte("x")); n != 0 || err != context.Canceled {
			t.Fatal("write hook failure was not retained", n, err)
		}
	}
	if calls != 2 {
		t.Fatal("failed hook was retried", calls)
	}
}
