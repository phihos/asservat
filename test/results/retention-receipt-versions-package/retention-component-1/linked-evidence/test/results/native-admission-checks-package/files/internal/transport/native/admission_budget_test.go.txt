package native_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

// A current authority port may consume a material part of the original call.
// The actual registrar/router must leave that original deadline intact while
// avoiding repeated constructor/Attach plumbing checks with no intervening I/O.
// Source, SQL and authority are explicit synthetic values; this is not native
// database latency qualification or evidence that every five-second flow fits.
func TestNativeRegistrationPreservesOriginalAdmissionBudget(t *testing.T) {
	origin, hello, _ := routerFixture(t)
	source := flowSourceValue(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	router, err := native.NewHubRouter(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	var checks atomic.Int32
	check := func(call context.Context, _ evidence.NativeOrigin) (value.NativeLease, error) {
		checks.Add(1)
		until, bounded := call.Deadline()
		if !bounded || until.After(deadline) {
			t.Error("current check extended the original caller deadline")
		}
		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return origin.Lease, nil
		case <-call.Done():
			return value.NativeLease{}, call.Err()
		}
	}
	registration, err := router.RegisterNativeExchange(ctx, evidence.NativeExchangeRegistration{Operation: origin.Lease.Operation, Source: source, Complete: syntheticNativeCompletion}, func(context.Context, evidence.NativeOrigin) error { return nil }, check)
	if err != nil {
		t.Fatal(err)
	}
	defer registration.Close()
	conversation, err := router.Attach(ctx, origin, hello)
	if err != nil || conversation == nil {
		t.Fatalf("duplicate admission checks exhausted original bounded call: checks=%d err=%v", checks.Load(), err)
	}
	if checks.Load() != 3 {
		t.Fatalf("expected fresh gate, post-Before, and exact attachment checks; got %d", checks.Load())
	}
	if until, bounded := conversation.Gate().Context().Deadline(); !bounded || until.After(deadline) {
		t.Fatal("conversation extended the original admission deadline")
	}
}
