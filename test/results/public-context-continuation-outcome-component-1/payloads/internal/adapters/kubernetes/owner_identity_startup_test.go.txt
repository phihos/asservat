package kubernetes

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestOwnerStartupPassiveLaunchReceiptPinsAndBounds(t *testing.T) {
	for _, mode := range []string{"complete", "two-pending", "still-pending", "changed-launch", "changed-sibling", "read-error", "authority-error", "expired-proof", "cancelled", "root-expired", "blocked-read-expired"} {
		t.Run(mode, func(t *testing.T) {
			x := newOwnerIdentityObjectFixture(t)
			complete := x.state
			launch := *complete.OwnerLaunch
			launch.Receipt = nil
			original := complete
			original.OwnerLaunch = &launch
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var offset atomic.Int64
			now := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
			if mode == "cancelled" {
				cancel()
			}
			if mode == "root-expired" {
				original.Until = now().Add(-time.Second)
			}
			if mode == "blocked-read-expired" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 300*time.Millisecond)
				defer stop()
			}
			reads, verifies := 0, 0
			read := func(call context.Context) (contracts.InitialRuntimeResourceState, error) {
				reads++
				deadline, ok := call.Deadline()
				parent, _ := ctx.Deadline()
				if !ok || deadline.After(parent) || deadline.After(now().Add(5*time.Second)) {
					t.Fatal("passive read extended original deadline")
				}
				switch mode {
				case "two-pending":
					if reads < 3 {
						return contracts.InitialRuntimeResourceState{}, &ownerLaunchReceiptPending{state: original}
					}
				case "still-pending":
					// Original caller cancellation interrupts the subsequent
					// passive wait; the pending state itself yields no proof.
					cancel()
					return contracts.InitialRuntimeResourceState{}, &ownerLaunchReceiptPending{state: original}
				case "changed-launch":
					changed := *complete.OwnerLaunch
					changed.OperationID = ownerID(4001)
					complete.OwnerLaunch = &changed
				case "changed-sibling":
					complete.SetupID = ownerID(4002)
				case "read-error":
					return contracts.InitialRuntimeResourceState{}, cfg.ErrUnavailable
				case "blocked-read-expired":
					<-call.Done()
					// A backend returning an apparently positive late result
					// cannot rescue the original read/caller deadline.
					return complete, nil
				}
				return complete, nil
			}
			verify := func(call context.Context, expected contracts.InitialRuntimeResourceState) (time.Time, error) {
				verifies++
				if !equalJSON(expected, complete) || expected.OwnerLaunch.Receipt == nil {
					t.Fatal("full proof did not receive exact first completed receipt")
				}
				if mode == "authority-error" {
					return time.Time{}, cfg.ErrDenied
				}
				if mode == "expired-proof" {
					return now().Add(-time.Microsecond), nil
				}
				until, _ := call.Deadline()
				return until, nil
			}
			until, err := awaitOwnerLaunchReceipt(ctx, original, now, read, verify)
			if mode == "complete" || mode == "two-pending" {
				wantReads := 1
				if mode == "two-pending" {
					wantReads = 3
				}
				if err != nil || !until.After(now()) || reads != wantReads || verifies != 1 {
					t.Fatal("receipt did not require independent authority", reads, verifies, err)
				}
			} else {
				if err == nil || !until.IsZero() {
					t.Fatal("unavailable transition returned authority")
				}
				want := 0
				if mode == "authority-error" || mode == "expired-proof" {
					want = 1
				}
				if verifies != want {
					t.Fatal("authority ran before exact convergence", reads, verifies)
				}
				if (mode == "changed-launch" || mode == "changed-sibling") && !errors.Is(err, cfg.ErrChanged) {
					t.Fatal("changed pending source classification", err)
				}
				if mode == "authority-error" && !errors.Is(err, cfg.ErrDenied) {
					t.Fatal("current authority refusal changed", err)
				}
			}
			if !reflect.DeepEqual(original.OwnerLaunch, &launch) {
				t.Fatal("comparison mutated original launch")
			}
		})
	}
}
