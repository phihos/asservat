package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCapacityHubWorkerJoinsBothChildrenUnderOriginalLease(t *testing.T) {
	for _, first := range []string{"configuration", "capacity", "lease"} {
		t.Run(first, func(t *testing.T) {
			deadline := time.Now().Add(5 * time.Second)
			lease, lose := context.WithDeadline(context.Background(), deadline)
			defer lose()
			entered := make(chan struct{}, 2)
			fail, release := make(chan struct{}), make(chan struct{})
			canceled := make(chan struct{}, 2)
			failure := errors.New("synthetic original child failure")
			child := func(name string) func(context.Context) error {
				return func(call context.Context) error {
					if d, ok := call.Deadline(); !ok || !d.Equal(deadline) {
						t.Error("original Lease deadline changed")
					}
					entered <- struct{}{}
					if name == first {
						<-fail
						return failure
					}
					<-call.Done()
					canceled <- struct{}{}
					<-release
					return call.Err()
				}
			}
			done := make(chan error, 1)
			go func() { done <- runCapacityWorkerChildren(lease, child("configuration"), child("capacity")) }()
			<-entered
			<-entered
			if first == "lease" {
				lose()
			} else {
				close(fail)
			}
			<-canceled
			select {
			case <-done:
				close(release)
				t.Fatal("returned while canceled child remained unjoined")
			case <-time.After(20 * time.Millisecond):
			}
			close(release)
			select {
			case err := <-done:
				if first == "lease" && !errors.Is(err, context.Canceled) || first != "lease" && !errors.Is(err, failure) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("joined children did not return")
			}
		})
	}
}
