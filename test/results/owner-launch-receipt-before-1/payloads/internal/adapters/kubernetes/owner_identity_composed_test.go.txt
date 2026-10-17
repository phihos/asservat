package kubernetes

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// One original concrete root is reused through the complete fixed sequence.
// Synthetic SQL receipts/provider material are explicit; no provider call or
// launched Pod is claimed. Every production call retains its original five
// seconds, including all current native proof and independent object reads.
func TestOwnerIdentityComposedUnknownObjectsAndLaunchAreLookupOnly(t *testing.T) {
	f, producer := newOwnerIdentityComposedFixture(t)
	advance := func(wantError bool) contracts.InitialRuntimeResourceState {
		t.Helper()
		ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		_, e := producer.Advance(ctx)
		end()
		if (e != nil) != wantError {
			t.Fatalf("composed projection (%.3fs): %v", time.Since(start).Seconds(), e)
		}
		return f.resourceState(t)
	}
	original := advance(false)
	if original.OwnerIdentity == nil || original.OwnerIdentity.Credentials != nil || original.OwnerIdentity.Configuration != nil || original.OwnerIdentity.Receipt != nil {
		t.Fatal("first advancement performed more than original intent claim")
	}
	parent := *original.OwnerIdentity
	// Even exact retained original identity cannot hide current admission loss.
	f.fault.Store(2)
	advance(true)
	f.fault.Store(0)
	if f.credentialCreates.Load() != 0 || f.configurationCreates.Load() != 0 {
		t.Fatal("negative current proof performed object effect")
	}
	for _, purpose := range []int32{1, 2} {
		f.lose.Store(purpose)
		unknown := advance(true)
		child := unknown.OwnerIdentity.Credentials
		if purpose == 2 {
			child = unknown.OwnerIdentity.Configuration
		}
		if child == nil || child.Receipt != nil {
			t.Fatal("unknown committed CREATE was treated as positive receipt")
		}
		originalChild := *child
		reconciled := advance(false)
		child = reconciled.OwnerIdentity.Credentials
		if purpose == 2 {
			child = reconciled.OwnerIdentity.Configuration
		}
		if child == nil || child.Receipt == nil || child.OperationID != originalChild.OperationID || !child.ClaimedAt.Equal(originalChild.ClaimedAt) || !child.Until.Equal(originalChild.Until) {
			t.Fatal("lookup replaced original object attempt")
		}
		if purpose == 1 && reconciled.OwnerIdentity.Configuration != nil {
			t.Fatal("first object receipt silently started second child")
		}
		if f.credentialCreates.Load() != 1 || f.configurationCreates.Load() != purpose-1 {
			t.Fatal("unknown object reply repeated CREATE or advanced another purpose")
		}
	}
	complete := advance(false)
	if complete.OwnerIdentity.Receipt == nil || complete.OwnerIdentity.OperationID != parent.OperationID || !complete.OwnerIdentity.ClaimedAt.Equal(parent.ClaimedAt) || !complete.OwnerIdentity.Until.Equal(parent.Until) || !complete.CreatedAt.Equal(original.CreatedAt) || !complete.Until.Equal(original.Until) {
		t.Fatal("joint acknowledgement changed original root/parent")
	}
	f.lose.Store(3)
	ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
	_, e := producer.Launch(ctx)
	end()
	if e == nil {
		t.Fatal("lost committed launch PUT reported positive completion")
	}
	unknownLaunch := f.resourceState(t)
	if unknownLaunch.OwnerLaunch == nil || unknownLaunch.OwnerLaunch.Receipt != nil || f.launchWrites.Load() != 1 {
		t.Fatal("unknown launch lost its original spent disposition")
	}
	ctx, end = context.WithTimeout(context.Background(), 5*time.Second)
	launched, e := producer.Launch(ctx)
	end()
	if e != nil || launched.State.OwnerLaunch == nil || launched.State.OwnerLaunch.Receipt == nil || f.launchWrites.Load() != 1 {
		t.Fatal("exact running lookup failed or repeated launch PUT", e)
	}
	if launched.State.OwnerLaunch.OperationID != unknownLaunch.OwnerLaunch.OperationID || !launched.State.OwnerLaunch.Until.Equal(unknownLaunch.OwnerLaunch.Until) || !equalJSON(launched.State.OwnerIdentity, complete.OwnerIdentity) {
		t.Fatal("launch completion replaced original identity/deadline")
	}
	// A new process can inspect positive original results, but cannot issue an
	// extra credential, ConfigMap or launch attempt through passive replay.
	reopened, e := NewOwnerIdentityProjection(f.root, ownerIdentityComposedVerification{f.root}, producer.input, producer.provider)
	if e != nil {
		t.Fatal(e)
	}
	ctx, end = context.WithTimeout(context.Background(), 5*time.Second)
	_, e = reopened.Advance(ctx)
	end()
	if e != nil {
		t.Fatal("completed projection replay", e)
	}
	ctx, end = context.WithTimeout(context.Background(), 5*time.Second)
	_, e = reopened.Launch(ctx)
	end()
	if e != nil {
		t.Fatal("completed launch replay", e)
	}
	if f.credentialCreates.Load() != 1 || f.configurationCreates.Load() != 1 || f.launchWrites.Load() != 1 {
		t.Fatal("positive original replay repeated an effect")
	}
	final := f.resourceState(t)
	if !equalJSON(final, launched.State) {
		t.Fatal("passive completed replay mutated original journal")
	}
}
