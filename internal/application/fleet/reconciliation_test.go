package fleet

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type ownerWatchSource struct {
	list  func() (value.OwnerConfigurationObservation, string, error)
	watch func(context.Context, string) (string, error)
}

func (s ownerWatchSource) OwnerSourceSnapshot(context.Context) (value.OwnerConfigurationObservation, string, error) {
	return s.list()
}
func (s ownerWatchSource) WaitOwnerChange(ctx context.Context, rv string) (string, error) {
	return s.watch(ctx, rv)
}

func TestOwnerConfigurationReconcilerWatchesIdleBaselineAndFencesRemoval(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	now := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	var reads, observed, fenced atomic.Int32
	waiting := make(chan string, 4)
	change := make(chan struct{})
	source := ownerWatchSource{list: func() (value.OwnerConfigurationObservation, string, error) {
		n := reads.Add(1)
		if n == 2 {
			return value.OwnerConfigurationObservation{}, "", value.ErrUnavailable
		}
		rv := fmt.Sprint(n)
		if n == 4 {
			return value.OwnerConfigurationObservation{}, rv, nil
		}
		c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "hub", ServiceUID: id, Deployment: "hub", DeploymentUID: id, ServiceAccount: "hub", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: int64(n), Digest: [32]byte{1}}, ProtectionDigest: [32]byte{2}, IssuerRoots: [][]byte{{3}}}
		return value.OwnerConfigurationObservation{Configuration: c, ObservedAt: now, FreshUntil: now.Add(time.Hour)}, rv, nil
	}, watch: func(ctx context.Context, rv string) (string, error) {
		waiting <- rv
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-change:
			if rv == "3" {
				return "4", nil
			}
			return "", nil
		}
	}}
	ledger := ownerApplyFunc(func(ctx context.Context, rv string, o value.OwnerConfigurationObservation) error {
		if o.ObservedAt.IsZero() {
			if fenced.Add(1) == 1 {
				return value.ErrUnavailable
			}
		} else {
			observed.Add(1)
		}
		return nil
	})
	r := ConfigurationReconciler{Source: source, Ledger: ledger}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	wait := func(want string) {
		t.Helper()
		select {
		case got := <-waiting:
			if got != want {
				t.Fatalf("watch cursor %s, want %s", got, want)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	wait("1")
	// Cross the old idle polling interval on a healthy watch.
	select {
	case got := <-waiting:
		t.Fatal("idle re-observation", got)
	case <-time.After(1100 * time.Millisecond):
	}
	change <- struct{}{}
	wait("3")
	if fenced.Load() != 0 || observed.Load() != 2 {
		t.Fatal("transient failure displaced accepted source", fenced.Load(), observed.Load())
	}
	change <- struct{}{}
	wait("4")
	if fenced.Load() != 2 || reads.Load() != 3 {
		t.Fatal("deletion not fenced", fenced.Load(), reads.Load())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type ownerApplyFunc func(context.Context, string, value.OwnerConfigurationObservation) error

func (f ownerApplyFunc) ApplyOwnerConfiguration(ctx context.Context, rv string, o value.OwnerConfigurationObservation) error {
	return f(ctx, rv, o)
}
