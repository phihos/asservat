package presentation

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestBrowserSettingsWriterRequiresBothPrivateBindings(t *testing.T) {
	for _, mode := range []string{"authorized", "no browser", "no prepared reply", "other operation", "over limit", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			if mode != "no browser" {
				ctx = AuthenticatedBrowserSettingsView(ctx)
			}
			name := "get_capture_settings"
			if mode == "other operation" {
				name = "get_capture"
			}
			size := 128 << 10
			if mode == "over limit" {
				size = 160<<10 + 1
			}
			reply := OperationReply{Body: bytes.Repeat([]byte("x"), size), ValidUntil: until, browserSettings: mode != "no prepared reply"}
			if mode == "cancelled" {
				cancel()
			}
			w := &operationWriter{ResponseRecorder: httptest.NewRecorder()}
			sent, err := WriteBrowserOperationResponse(ctx, w, http.StatusOK, name, reply, until)
			if mode == "authorized" {
				if err != nil || !sent || !bytes.Equal(reply.Body, w.Body.Bytes()) {
					t.Fatal("bounded settings write failed", err)
				}
				return
			}
			if err == nil || sent || w.Body.Len() != 0 {
				t.Fatal("unbound/late bytes escaped", err)
			}
		})
	}
}

type operationWriter struct {
	*httptest.ResponseRecorder
	short                   bool
	writeEntered, writeStop chan struct{}
	once                    sync.Once
}

func (w *operationWriter) SetWriteDeadline(t time.Time) error {
	if w.writeStop != nil && !t.After(time.Now()) {
		w.once.Do(func() { close(w.writeStop) })
	}
	return nil
}
func (w *operationWriter) Write(p []byte) (int, error) {
	if w.writeEntered != nil {
		close(w.writeEntered)
		<-w.writeStop
		return 0, errors.New("canceled write")
	}
	if w.short {
		return len(p) - 1, nil
	}
	return w.ResponseRecorder.Write(p)
}

func TestOperationResponseChecksFinalGuardAndShortWrite(t *testing.T) {
	for _, mode := range []string{"ok", "denied", "short"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		w := &operationWriter{ResponseRecorder: httptest.NewRecorder(), short: mode == "short"}
		until, _ := ctx.Deadline()
		checks := 0
		sent, err := WriteOperationResponse(ctx, w, http.StatusOK, []byte("approved"), until, func(context.Context) error {
			checks++
			if mode == "denied" {
				return errors.New("revoked")
			}
			return nil
		})
		cancel()
		if checks != 1 {
			t.Fatal("missing final check")
		}
		if mode == "ok" && (err != nil || !sent || !w.Flushed || w.Body.String() != "approved") {
			t.Fatal("bounded response failed", err)
		}
		if mode == "denied" && (err == nil || sent || w.Body.Len() != 0) {
			t.Fatal("denied bytes escaped")
		}
		if mode == "short" && (err == nil || !sent || w.Flushed) {
			t.Fatal("short write reported completed")
		}
	}
}

func TestOperationResponseCancellationInterruptsActualWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	w := &operationWriter{ResponseRecorder: httptest.NewRecorder(), writeEntered: make(chan struct{}), writeStop: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := WriteOperationResponse(ctx, w, http.StatusOK, []byte("approved"), until, func(context.Context) error { return nil })
		done <- err
	}()
	<-w.writeEntered
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("socket cancellation was not joined")
	}
}
