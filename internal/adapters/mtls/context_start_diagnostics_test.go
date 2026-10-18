package mtls

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

func TestContextStartOpeningDiagnosticStages(t *testing.T) {
	for _, mode := range []string{"discovery", "setup-begin", "process-open", "tls", "peer", "process-first", "owner-first", "source", "headers", "finish", "process-closing", "owner-closing", "process-final", "close"} {
		t.Run(mode, func(t *testing.T) {
			p := newContextStartSetupFixture(t)
			owners := &contextStartSetupOwners{OwnerPeerAuthenticator: p.f.owners}
			p.f.client.owners = owners
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			private := errors.New("private-token-host-workload")
			want := error(value.ErrUnavailable)
			reads, sources, finishes, ownerCalls := int32(0), int32(0), int32(0), int32(0)
			switch mode {
			case "setup-begin":
				p.begin = func(context.Context) error { return private }
			case "process-open", "process-first", "process-closing", "process-final":
				at := map[string]int32{"process-open": 1, "process-first": 2, "process-closing": 3, "process-final": 4}[mode]
				p.read = func(_ context.Context, n int32) error {
					if n == at {
						return value.ErrUnavailable
					}
					return nil
				}
				reads = at
				if at >= 3 {
					sources, finishes, ownerCalls = 1, 1, 1
				}
				if at == 4 {
					ownerCalls = 2
				}
			case "tls":
				p.f.client.roots = newOwnerTestCA(t, time.Now()).roots
				reads, want = 1, value.ErrDenied
			case "peer":
				p.f.client.verifier.roots = newOwnerTestCA(t, time.Now()).roots
				reads, want = 1, value.ErrDenied
			case "owner-first", "owner-closing":
				at := int32(1)
				reads, ownerCalls, want = 2, 1, value.ErrDenied
				if mode == "owner-closing" {
					at, reads, sources, finishes, ownerCalls, want = 2, 3, 1, 1, 2, value.ErrUnavailable
				}
				owners.check = func(_ context.Context, n int32) error {
					if n == at {
						return private
					}
					return nil
				}
			case "source":
				p.source = func(context.Context) error { return private }
				reads, sources, ownerCalls = 2, 1, 1
			case "headers":
				p.f.intercept = func(w http.ResponseWriter, _ *http.Request) bool { w.WriteHeader(http.StatusForbidden); return true }
				reads, sources, ownerCalls, want = 2, 1, 1, value.ErrDenied
			case "finish":
				p.finish = func(context.Context) error { return private }
				reads, sources, finishes, ownerCalls = 2, 1, 1, 1
			case "close":
				p.close = cancel
				reads, sources, finishes, ownerCalls = 4, 1, 1, 2
			}
			var exchange *ContextStartExchange
			var err error
			if mode == "discovery" {
				exchange, err = p.f.client.OpenDiscovered(ctx, p.f.owner, value.APIContextOwnerCandidates{})
			} else {
				exchange, err = p.f.client.Open(ctx, p.f.owner)
			}
			if exchange != nil {
				exchange.Close()
				t.Fatal("refused opening returned exchange")
			}
			var detail interface {
				FixedStep() string
				OpeningTiming() (time.Duration, time.Duration)
			}
			if !errors.Is(err, want) || !errors.As(err, &detail) || detail.FixedStep() != mode {
				t.Fatalf("wrong opening diagnosis/classification: mode=%s error=%v detail=%v", mode, err, detail)
			}
			elapsed, remaining := detail.OpeningTiming()
			if elapsed < 0 || remaining < 0 || remaining > time.Second || strings.Contains(err.Error(), "private-") || errors.Is(err, private) {
				t.Fatal("diagnostic exposed dependency or changed old error chain", err, elapsed, remaining)
			}
			begins, closes := int32(1), int32(1)
			if mode == "discovery" {
				begins, closes = 0, 0
			}
			if p.begins.Load() != begins || p.closes.Load() != closes || p.full.Load() != 0 || p.reads.Load() != reads || p.sources.Load() != sources || p.finishes.Load() != finishes || owners.calls.Load() != ownerCalls {
				t.Fatalf("instrumentation changed calls: begin=%d close=%d full=%d reads=%d source=%d finish=%d owner=%d", p.begins.Load(), p.closes.Load(), p.full.Load(), p.reads.Load(), p.sources.Load(), p.finishes.Load(), owners.calls.Load())
			}
		})
	}
}

type contextSetupDiagnosticCause struct {
	step  string
	until time.Time
}

func (e *contextSetupDiagnosticCause) Error() string                     { return "private-source-metadata" }
func (e *contextSetupDiagnosticCause) ContextStartSetupStep() string     { return e.step }
func (e *contextSetupDiagnosticCause) ContextStartSetupUntil() time.Time { return e.until }

func TestContextStartOpeningDiagnosticRetainsKnownSetupBoundOnly(t *testing.T) {
	for _, mode := range []string{"source-close", "fresh", "private-source-metadata", "expired"} {
		t.Run(mode, func(t *testing.T) {
			p := newContextStartSetupFixture(t)
			until := time.Now().Add(200 * time.Millisecond)
			step, want := mode, "setup-"+mode
			if mode == "private-source-metadata" {
				want = "setup-begin"
			}
			if mode == "expired" {
				step, until, want = "source-close", time.Now().Add(-time.Second), "setup-source-close"
			}
			p.begin = func(context.Context) error { return &contextSetupDiagnosticCause{step, until} }
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := p.f.client.Open(ctx, p.f.owner)
			var detail *contextStartOpeningError
			if !errors.As(err, &detail) || detail.FixedStep() != want || !errors.Is(err, value.ErrUnavailable) || strings.Contains(err.Error(), "private-") {
				t.Fatal("setup metadata escaped its closed boundary", err)
			}
			_, remaining := detail.OpeningTiming()
			if mode == "expired" && remaining != 0 || mode == "source-close" && remaining > 200*time.Millisecond {
				t.Fatal("diagnostic renewed learned source cutoff", remaining)
			}
			if p.sources.Load() != 0 || p.reads.Load() != 0 || p.closes.Load() != 1 || p.begins.Load() != 1 {
				t.Fatal("diagnostic performed further work")
			}
		})
	}
}

func TestContextStartOpeningDiagnosticJoinsAndPreservesCancellationCause(t *testing.T) {
	p := newContextStartSetupFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.read = func(context.Context, int32) error { cancel(); return context.Canceled }
	p.close = func() { time.Sleep(30 * time.Millisecond) }
	started := time.Now()
	_, err := p.f.client.Open(ctx, p.f.owner)
	var detail *contextStartOpeningError
	if !errors.As(err, &detail) || !errors.Is(err, context.Canceled) || detail.FixedStep() != "process-open" || p.closes.Load() != 1 {
		t.Fatal("cancellation or joined owner changed", err)
	}
	elapsed, remaining := detail.OpeningTiming()
	if elapsed < 30*time.Millisecond || elapsed > time.Since(started) || remaining < 0 || remaining > 200*time.Millisecond {
		t.Fatal("timing omitted joined close or extended original bound", elapsed, remaining)
	}
}
