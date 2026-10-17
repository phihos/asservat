package kubernetes

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func ownerProjectionAdvanceTo(t *testing.T, f *ownerProjectionOperationFixture, count int) OwnerProjectionAdvance {
	t.Helper()
	var out OwnerProjectionAdvance
	statuses := []OwnerProjectionAdvanceStatus{OwnerProjectionAdvanceAcknowledged, OwnerProjectionAdvancePending, OwnerProjectionAdvanceAcknowledged, OwnerProjectionAdvancePending, OwnerProjectionAdvanceAcknowledged, OwnerProjectionAdvanceComplete}
	for i := 0; i < count; i++ {
		var err error
		out, err = f.projection.Advance(context.Background())
		if err != nil || out.Status != statuses[i] {
			t.Fatal("fixed projection phase", i, out.Status, err)
		}
	}
	return out
}

func TestProviderOwnerProjectionOperationCompleteAndLaunch(t *testing.T) {
	f := newOwnerProjectionOperationFixture(t)
	complete := ownerProjectionAdvanceTo(t, f, 6)
	if complete.Snapshot.State.OwnerIdentity.Receipt == nil || f.creates[0].Load() != 1 || f.creates[1].Load() != 1 {
		t.Fatal("projection did not retain both exact children")
	}
	projection := *complete.Snapshot.State.OwnerIdentity
	pending, err := f.projection.Launch(context.Background())
	if err != nil || pending.Status != OwnerProjectionAdvancePending || pending.Snapshot.State.OwnerLaunch == nil || pending.Snapshot.State.OwnerLaunch.Receipt != nil {
		t.Fatal("one-use launch pending", err)
	}
	claim := *pending.Snapshot.State.OwnerLaunch
	launched, err := f.projection.Launch(context.Background())
	if err != nil || launched.Status != OwnerProjectionAdvanceComplete || launched.Snapshot.State.OwnerLaunch.Receipt == nil || f.launches.Load() != 1 {
		t.Fatal("launch current acknowledgement", err)
	}
	if !equalJSON(projection, *launched.Snapshot.State.OwnerIdentity) || claim.OperationID != launched.Snapshot.State.OwnerLaunch.OperationID || !claim.Until.Equal(launched.Snapshot.State.OwnerLaunch.Until) {
		t.Fatal("launch changed original projection/claim")
	}
	writes := f.journalWrites.Load()
	replayed, err := f.projection.InspectLaunch(context.Background())
	if err != nil || replayed.Status != OwnerProjectionAdvanceComplete || f.launches.Load() != 1 || f.journalWrites.Load() != writes {
		t.Fatal("completed inspection performed effects", err)
	}
	if f.provider.requests.Load() != 17*16 || f.verification.checks != 8 || f.verification.finalizations != 9 {
		t.Fatal("provider/full SQL boundary omitted or duplicated", f.provider.requests.Load(), f.verification.checks)
	}
}

func TestProviderOwnerProjectionOperationLostCreateRemainsUnverified(t *testing.T) {
	f := newOwnerProjectionOperationFixture(t)
	ownerProjectionAdvanceTo(t, f, 1)
	f.lose.Store(1)
	if _, err := f.projection.Advance(context.Background()); err == nil {
		t.Fatal("unknown CREATE claimed success")
	}
	writes := f.journalWrites.Load()
	if _, err := f.projection.Inspect(context.Background()); err == nil {
		t.Fatal("lost UID was discovered by name")
	}
	if _, err := f.projection.Advance(context.Background()); err == nil {
		t.Fatal("unverified CREATE admitted another effect")
	}
	if f.creates[0].Load() != 1 || f.journalWrites.Load() != writes {
		t.Fatal("lost CREATE repeated effect or receipt")
	}
}

func TestProviderOwnerProjectionOperationUnknownReceiptCannotRepeatCAS(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "not-committed", true: "committed"}[committed], func(t *testing.T) {
			f := newOwnerProjectionOperationFixture(t)
			ownerProjectionAdvanceTo(t, f, 2)
			if committed {
				f.lose.Store(4)
			} else {
				f.dropJournal.Store(true)
			}
			if _, err := f.projection.Advance(context.Background()); err == nil {
				t.Fatal("unknown receipt reported acknowledgement")
			}
			writes := f.journalWrites.Load()
			inspected, err := f.projection.Inspect(context.Background())
			if committed {
				if err != nil || inspected.Status != OwnerProjectionAdvanceAcknowledged || inspected.Snapshot.State.OwnerIdentity.Credentials.Receipt == nil {
					t.Fatal("exact committed receipt not observed", err)
				}
			} else if err == nil {
				t.Fatal("uncommitted uncertain receipt admitted new CAS")
			}
			if f.journalWrites.Load() != writes || f.creates[0].Load() != 1 {
				t.Fatal("inspect repeated uncertain write")
			}
		})
	}
}

func TestProviderOwnerProjectionOperationRequiresPostLockAndFinalCurrentProof(t *testing.T) {
	for _, afterEffect := range []bool{false, true} {
		t.Run(map[bool]string{false: "post-lock", true: "final"}[afterEffect], func(t *testing.T) {
			f := newOwnerProjectionOperationFixture(t)
			ownerProjectionAdvanceTo(t, f, 1)
			if afterEffect {
				f.verification.beforeFinalizeCurrent = func() { f.fault.Store(6) }
			} else {
				f.verification.beforeCurrent = func() { f.fault.Store(6) }
			}
			if _, err := f.projection.Advance(context.Background()); err == nil {
				t.Fatal("changed current enforcement returned positive result")
			}
			want := int32(0)
			if afterEffect {
				want = 1
			}
			if f.creates[0].Load() != want {
				t.Fatal("failure reached wrong effect boundary", f.creates[0].Load())
			}
			f.fault.Store(0)
			f.verification.beforeCurrent = nil
			f.verification.beforeFinalizeCurrent = nil
			_, err := f.projection.Inspect(context.Background())
			if err == nil {
				t.Fatal("spent/unissued or consumed failed finalizer fabricated result")
			}
			if f.creates[0].Load() != want {
				t.Fatal("spent child was recreated")
			}
		})
	}
}

func TestProviderOwnerProjectionOperationProviderDenialPrecedesIntent(t *testing.T) {
	f := newOwnerProjectionOperationFixture(t)
	f.provider.deny.Store(true)
	if _, err := f.projection.Advance(context.Background()); err == nil {
		t.Fatal("missing actual provider setup admitted intent")
	}
	if f.journalWrites.Load() != 0 || f.verification.checks != 0 {
		t.Fatal("provider denial reached role locks or journal mutation")
	}
	if f.creates[0].Load() != 0 || f.creates[1].Load() != 0 {
		t.Fatal("provider denial reached immutable CREATE")
	}
	// Keep the public profile visible in the fixture boundary; no static runtime
	// token is supplied and no provider endpoint can be selected after binding.
	if f.projection.projection.input.ProviderAuthentication.Format != contracts.OwnerProviderAuthenticationFormat {
		t.Fatal("wrong provider profile")
	}
}
