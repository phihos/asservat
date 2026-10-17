package mtls

import (
	"asservat.local/asservat/internal/contracts"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

// A generic HTTP failure cannot become an instruction to repeat an uncertain
// native POST. Only the authenticated exact positive no-command response can.
func TestNativeNoCommandExactH2Response(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(http.Header)
		status int
		idle   bool
	}{
		{name: "exact", status: 204, idle: true},
		{name: "generic404", status: 404},
		{name: "nonce", status: 204, change: func(h http.Header) { h.Set("Asservat-Native-Nonce", "wrong") }},
		{name: "expired", status: 204, change: func(h http.Header) {
			h.Set("Asservat-Native-Until", time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
		}},
		{name: "duplicate", status: 204, change: func(h http.Header) { h.Add("Asservat-Native-Disposition", "no-command") }},
		{name: "wrong-worker", status: 204, change: func(h http.Header) { h.Set("Asservat-Native-Worker", "22222222-2222-4222-8222-222222222222") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hello := nativeHello()
			hello.Reference.OperationID = ""
			hello.Reference.Fence = 0
			_, client := nativeStreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				frame, err := contracts.ReadNativeFrame(r.Body)
				defer clear(frame.Payload)
				if err != nil {
					return
				}
				h := w.Header()
				h.Set("Asservat-Native-Disposition", "no-command")
				h.Set("Asservat-Native-Nonce", hello.Nonce)
				h.Set("Asservat-Native-Installation", hello.Reference.InstallationID)
				h.Set("Asservat-Native-Session", hello.Reference.SessionID)
				h.Set("Asservat-Native-Worker", hello.Reference.WorkerID)
				h.Set("Asservat-Native-Until", time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano))
				h.Set("Retry-After", "1")
				if tc.change != nil {
					tc.change(h)
				}
				w.WriteHeader(tc.status)
			}), true)
			ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			stream, err := client.Open(ctx, hello)
			if stream != nil {
				stream.Close()
				t.Fatal("unexpected stream")
			}
			var idle *contracts.NativeNoCommand
			if errors.As(err, &idle) != tc.idle {
				t.Fatalf("idle=%t error=%v", tc.idle, err)
			}
			if idle != nil && (idle.Reference != hello.Reference || idle.Nonce != hello.Nonce) {
				t.Fatal("wrong positive disposition")
			}
		})
	}
}
