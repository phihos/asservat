package fleet

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

type administrationFunc func(context.Context) (value.Administration, error)

func (f administrationFunc) FleetAdministration(ctx context.Context) (value.Administration, error) {
	return f(ctx)
}

func TestConfigurationReconcilerIndependentSerialLoopsAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fleetEntered := make(chan struct{})
	var ownerCalls, ownerFences atomic.Int32
	s := &ConfigurationReconciler{
		Fleet: &TrustObserver{Settings: administrationFunc(func(ctx context.Context) (value.Administration, error) {
			close(fleetEntered)
			if d, ok := ctx.Deadline(); !ok || time.Until(d) > 5*time.Second {
				t.Error("unbounded observation")
			}
			<-ctx.Done()
			return value.Administration{}, ctx.Err()
		}), Projection: &trustObservationFixture{basis: trustObservationBasis(time.Now().UTC().Truncate(time.Microsecond))}, Now: time.Now},
		Owner: &OwnerConfigurationObserver{Reader: ownerConfigFunc(func(context.Context) (value.OwnerConfigurationObservation, error) {
			ownerCalls.Add(1)
			return value.OwnerConfigurationObservation{}, value.ErrUnavailable
		}),
			Ledger: ownerLedgerFake{fence: func(ctx context.Context, _ time.Time) error {
				if ctx.Err() != nil {
					t.Error("source fencing inherited cancelled context")
				}
				ownerFences.Add(1)
				return nil
			}},
			Audit: ownerAuditFunc(func(context.Context, value.OwnerConfiguration) (audit.Receipt, error) {
				t.Error("unavailable source reached audit")
				return audit.Receipt{}, value.ErrDenied
			}),
			Acknowledgements: ownerAckFunc(func(context.Context, value.OwnerConfiguration, audit.Receipt) error { return value.ErrDenied }), Now: time.Now},
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("reconciler did not join")
		}
	}()
	select {
	case <-fleetEntered:
	case <-time.After(time.Second):
		t.Fatal("fleet loop did not start")
	}
	if err := s.Run(ctx); err == nil {
		t.Fatal("duplicate concurrent loops accepted")
	}
	until := time.Now().Add(2 * time.Second)
	for ownerCalls.Load() < 2 && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	if ownerCalls.Load() != 2 || ownerFences.Load() != 2 {
		t.Fatal("blocked fleet source prevented owner fencing/retry")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		done <- err
	case <-time.After(time.Second):
		t.Fatal("work did not stop")
	}
	previous := ownerCalls.Load()
	time.Sleep(20 * time.Millisecond)
	if ownerCalls.Load() != previous {
		t.Fatal("work continued after joined cancellation")
	}
}
