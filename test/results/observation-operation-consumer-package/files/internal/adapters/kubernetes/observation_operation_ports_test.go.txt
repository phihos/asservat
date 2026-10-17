package kubernetes

import (
	"context"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

func TestObservationOperationPortsKeepConcreteNativeBrackets(t *testing.T) {
	t.Run("owner", func(t *testing.T) {
		f := newOwnerOperationFixture(t)
		ctx, cancel := context.WithDeadline(context.Background(), f.start.Add(5*time.Second))
		defer cancel()
		r := value.OwnerObservationRequest{RootID: f.pin.RootID, ID: ownerID(80), Challenge: ownerID(81), RequestedAt: f.start, NotAfter: f.start.Add(5 * time.Second)}
		var reader app.OwnerNativeObservationOperations = f.reader
		op, err := reader.OpenOwnerObservationOperation(ctx, r, []value.OwnerBinding{f.v.binding})
		if err != nil {
			t.Fatal(err)
		}
		defer op.Close()
		before, err := op.Original(ctx)
		if err != nil || before.Final || !before.Valid(f.start) {
			t.Fatal("missing original native values", err)
		}
		observer, probe := f.observer.Load(), f.probe.Load()
		before.Peers[0].Addresses[0] = "10.250.0.1"
		again, err := op.Original(ctx)
		if err != nil || again.Peers[0].Addresses[0] == "10.250.0.1" || f.observer.Load() != observer || f.probe.Load() != probe {
			t.Fatal("Original changed or re-observed native facts")
		}
		final, err := op.Final(ctx)
		if err != nil || !final.Final || !final.Valid(f.start) || !final.ObservedAt.Equal(again.ObservedAt) || final.FreshUntil.After(again.FreshUntil) || f.observer.Load() <= observer || f.probe.Load() <= probe {
			t.Fatal("final native bracket missing or renewed", err)
		}
		if _, err := op.Final(ctx); err == nil {
			t.Fatal("final bracket repeated")
		}
	})
	t.Run("regional", func(t *testing.T) {
		f := newConnectorOperationFixture(t)
		ctx, cancel := context.WithDeadline(context.Background(), f.base.start.Add(5*time.Second))
		defer cancel()
		r := value.OwnerObservationRequest{RootID: f.reader.pin.Profile.RootID, ID: ownerID(80), Challenge: ownerID(81), RequestedAt: f.base.start, NotAfter: f.base.start.Add(5 * time.Second)}
		var reader app.ConnectorNativeObservationOperations = f.reader
		op, err := reader.OpenConnectorObservationOperation(ctx, r, f.process)
		if err != nil {
			t.Fatal(err)
		}
		defer op.Close()
		for ordinal := 1; ordinal <= 4; ordinal++ {
			v, err := op.Read(ctx, ordinal)
			if err != nil || !v.Matches(f.reader.pin, r, ordinal, f.base.start) || v.Final != (ordinal == 4) {
				t.Fatal("source phase/observation lost", ordinal, err)
			}
		}
		if f.gets.Load() != 6 || f.reviews.Load() != 4 {
			t.Fatal("four real values plus two guard probe reads changed", f.gets.Load(), f.reviews.Load())
		}
	})
}

func TestObservationOperationPortsInvalidOpenReturnsNil(t *testing.T) {
	var owner *OwnerObservationOperationReader
	var connector *ConnectorObservationOperationReader
	if op, err := owner.OpenOwnerObservationOperation(context.Background(), value.OwnerObservationRequest{}, nil); err == nil || op != nil {
		t.Fatal("invalid owner open returned typed nil operation")
	}
	if op, err := connector.OpenConnectorObservationOperation(context.Background(), value.OwnerObservationRequest{}, value.ConnectorProcessIdentity{}); err == nil || op != nil {
		t.Fatal("invalid connector open returned typed nil operation")
	}
}
