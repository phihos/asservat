package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Actual HTTPS/client-go response handling: a valid403 also has a StatusError.
// Diagnostic categories cannot turn that expected denial into a failed proof.
func TestOwnerProbeFailureDiagnosticRealHTTPS(t *testing.T) {
	for _, mode := range []string{"valid403", "body", "deadline", "canceled", "transport"} {
		t.Run(mode, func(t *testing.T) {
			f := newOwnerOperationFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if mode == "deadline" {
				ctx, cancel = context.WithTimeout(t.Context(), 150*time.Millisecond)
				defer cancel()
			}
			f.probeResponse = func(w http.ResponseWriter, r *http.Request) bool {
				switch mode {
				case "valid403":
					return false
				case "body":
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte("private-invalid-response"))
					return true
				case "deadline":
					<-ctx.Done()
					return true
				case "canceled":
					cancel()
					<-ctx.Done()
					return true
				case "transport":
					h := w.(http.Hijacker)
					c, _, err := h.Hijack()
					if err != nil {
						t.Error(err)
					} else {
						_ = c.Close()
					}
					return true
				}
				return false
			}
			_, err := f.guard.proveObject(ctx, f.start)
			if mode == "valid403" {
				if err != nil {
					t.Fatal("valid forbidden StatusError refused", err)
				}
				return
			}
			var diagnostic interface {
				ProbeFailureDiagnostic() (string, time.Duration)
			}
			if !errors.Is(err, cfg.ErrUnavailable) || !errors.As(err, &diagnostic) {
				t.Fatalf("missing private probe diagnostic: %v", err)
			}
			category, remaining := diagnostic.ProbeFailureDiagnostic()
			if category != mode || remaining <= 0 || remaining > time.Second {
				t.Fatalf("probe category/entry remaining = %s/%s", category, remaining)
			}
			var step interface{ FixedStep() string }
			if !errors.As(err, &step) || step.FixedStep() != "source.probe-denial-body" {
				t.Fatal("changed existing refusal stage", err)
			}
			if f.observer.Load() != 1 || f.probe.Load() != 3 {
				t.Fatal("changed request count", f.observer.Load(), f.probe.Load())
			}
		})
	}
}
