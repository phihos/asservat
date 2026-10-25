package mtls

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/contextstart"
)

type contextProtectionDiagnosticError struct{}

func (contextProtectionDiagnosticError) Error() string { panic("private native error text inspected") }
func (contextProtectionDiagnosticError) FixedStep() string {
	return "protection.guard-last/source.guard-policy-read"
}

// This composes the successful attachment check and the separate work-send
// check over actual TLS/H2. The first armed protection read is the latter's
// single local authenticator boundary (the closing re-read seen in native44
// was removed in the 2026-10-23 reuse revision).
// Synthetic proof failures do not qualify native Kubernetes performance.
func TestContextStartActualHTTP2DispatchProtectionDiagnostic(t *testing.T) {
	for _, mode := range []string{"native-error", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			f := newContextStartTLSFixture(t)
			hubOwners := *f.owners
			f.ingress.owners = &hubOwners
			original := hubOwners.Protection
			var armed atomic.Bool
			var guards atomic.Int32
			var mu sync.Mutex
			var reports []string
			f.ingress.Refused = func(step string) {
				mu.Lock()
				reports = append(reports, step)
				mu.Unlock()
			}
			entered, canceled, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			var proofDeadline time.Time
			hubOwners.Protection = forwardGuard(func(ctx context.Context, pool value.OwnerPool) (value.OwnerProtection, error) {
				if !armed.Load() || guards.Add(1) != 1 {
					return original.ReadOwnerProtection(ctx, pool)
				}
				proofDeadline, _ = ctx.Deadline()
				close(entered)
				defer close(joined)
				if mode == "cancellation" {
					<-ctx.Done()
					close(canceled)
					<-release
					return value.OwnerProtection{}, ctx.Err()
				}
				if ctx.Err() != nil {
					t.Error("native failure was reached only after caller expiry")
				}
				return value.OwnerProtection{}, contextProtectionDiagnosticError{}
			})
			exchange, stream := f.open(t)
			parentUntil := time.Now().UTC().Truncate(time.Microsecond).Add(1500 * time.Millisecond)
			ctx, cancel := context.WithDeadline(t.Context(), parentUntil)
			work, signer, signed, _ := f.work(t, exchange.Receiver(), func(w *value.APIContextWork) { w.NotAfter = parentUntil })
			regional := &regionalOperationsFixture{t: t, work: work, process: f.api}
			local := contextstart.RegionalLocal{Process: regional, Targets: regional, Local: regional, Starts: regional, Output: regional, Collector: regional, Source: f.connector, Now: time.Now}
			regionalDone := make(chan struct{})
			go func() {
				defer close(regionalDone)
				defer stream.Close()
				_ = contextstart.ServeRegionalOperations(exchange.Context(), stream, exchange.Receiver(), signer, local, time.Now)
			}()
			attachment, err := f.router.Attach(ctx, f.connector.profile.Binding.ClusterID, ownerTestID)
			if err != nil {
				cancel()
				unblock()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cancel()
				unblock()
				attachment.Close()
				exchange.Close()
				<-regionalDone
			})
			if _, err = attachment.Receiver(ctx); err != nil {
				t.Fatal("attachment must succeed before dispatch failure", err)
			}
			armed.Store(true)
			var ran atomic.Bool
			runDone := make(chan error, 1)
			go func() {
				_, err := attachment.Run(work, signed, func(context.Context, *contextstart.HubOperations) (string, error) {
					ran.Store(true)
					return "StoredPendingVerification", nil
				})
				runDone <- err
			}()
			select {
			case <-entered:
			case err := <-runDone:
				t.Fatal("dispatch did not reach closing protection", err)
			case <-ctx.Done():
				t.Fatal("dispatch did not reach closing protection before original expiry")
			}
			if mode == "cancellation" {
				cancel()
				<-canceled
				closed := make(chan struct{})
				go func() { attachment.Close(); close(closed) }()
				select {
				case <-closed:
					t.Fatal("attachment released before blocked proof joined")
				default:
				}
				unblock()
				<-closed
			}
			if err = <-runDone; err == nil {
				t.Fatal("failed dispatch reported success")
			}
			attachment.Close()
			<-joined
			<-regionalDone
			if ran.Load() || regional.prepared || regional.captures != 0 || guards.Load() != 1 || f.dials.Load() != 1 {
				t.Fatal("refusal changed check count, replayed, or reached an execution effect")
			}
			if proofDeadline.IsZero() || proofDeadline.After(parentUntil) {
				t.Fatal("closing proof escaped the inherited deadline", proofDeadline, parentUntil)
			}
			want := "local/protection-before/read/protection.guard-last/source.guard-policy-read@"
			if mode == "cancellation" {
				want = "local/protection-before/read/canceled@"
			}
			mu.Lock()
			defer mu.Unlock()
			found := false
			for _, report := range reports {
				// A cancellation can also land in the concurrent owner registration
				// read, which reports its own closed refusal (5 in 100 runs).
				found = found || strings.HasPrefix(report, want) || mode == "cancellation" && report == "registration/unavailable"
			}
			if !found {
				t.Fatalf("composed dispatch lost exact safe failure: want %q in %v", want, reports)
			}
		})
	}
}
