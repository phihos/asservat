package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConfigurationProviderChildrenStartIndependentlyAndJoin(t *testing.T) {
	for _, first := range []string{"configuration", "provider"} {
		t.Run(first, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			configurationStarted, providerStarted := make(chan struct{}), make(chan struct{})
			cancelled, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			failure := errors.New("selected child stopped")
			child := func(name string, other <-chan struct{}) func(context.Context) error {
				return func(call context.Context) error {
					if name == "configuration" {
						close(configurationStarted)
					} else {
						close(providerStarted)
					}
					<-other
					if name == first {
						return failure
					}
					<-call.Done()
					close(cancelled)
					<-release // deliberately ignores cancellation until externally joined
					return call.Err()
				}
			}
			go func() {
				done <- runConfigurationProviderChildren(ctx,
					child("configuration", providerStarted), child("provider", configurationStarted))
			}()
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("first return did not cancel sibling")
			}
			select {
			case err := <-done:
				t.Fatalf("reported joined while sibling still owns work: %v", err)
			default:
			}
			close(release)
			select {
			case err := <-done:
				if !errors.Is(err, failure) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("did not join released sibling")
			}
		})
	}
}

func TestConfigurationProviderChildrenKeepOriginalLeaseDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	original, _ := ctx.Deadline()
	deadlines := make(chan time.Time, 2)
	child := func(call context.Context) error {
		deadline, _ := call.Deadline()
		deadlines <- deadline
		<-call.Done()
		return call.Err()
	}
	if err := runConfigurationProviderChildren(ctx, child, child); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	for range 2 {
		if got := <-deadlines; !got.Equal(original) {
			t.Fatal("child changed original Lease deadline")
		}
	}
}

func TestConfigurationProviderChildrenDoNotStartAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	child := func(context.Context) error { called = true; return nil }
	if runConfigurationProviderChildren(ctx, child, child) == nil || called {
		t.Fatal("closed callback started work")
	}
}
