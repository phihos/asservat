package bootstrap

import (
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"testing"
	"time"
)

// These are scheduling notices only; neither pending nor admitted work has a
// native/SQL/provider proof here. The actual wrapper still owns a concrete SQL
// adapter and calls this same completion only after that adapter returns.
func TestConfigurationRuntimeContentionInvalidatesPendingAndActiveNotices(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending-notice", true: "active-notice"}[active], func(t *testing.T) {
			gate, err := app.NewWorkerRuntimeAdmission(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer gate.Close()
			ticket, err := gate.WaitWrapRefresh(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer ticket.Release()
			const uid = "11111111-1111-4111-8111-111111111111"
			n := time.Now().UTC()
			a := value.Administration{InstallationID: uid, IssuerEpoch: uid, Issuer: "https://issuer.example", Revision: identity.Revision{UID: uid, Generation: 1, Digest: [32]byte{1}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Clients: []string{"client"}, DeliveryProfiles: []string{"context"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 2, MaxClusters: 1}
			gate.NoteFleetObservation(a)
			if active {
				gate.NoteFleetCommitted(t.Context(), a)
				if err = ticket.AwaitFleetObservation(); err != nil {
					t.Fatal(err)
				}
			}
			projection := &configurationRuntimeFleetProjection{admission: gate}
			err = projection.finishObservation(t.Context(), a, value.ErrObservationPersistenceContended)
			if !errors.Is(err, value.ErrObservationPersistenceContended) || ticket.Context().Err() == nil {
				t.Fatal("contention became scheduling success or retained active work")
			}
			if !active && ticket.AwaitFleetObservation() == nil {
				t.Fatal("failed persistence supplied a scheduling hint")
			}
			ticket.Release()
			// No hint survives for the next independently admitted ticket. This wait
			// has its own test-only caller deadline and selects no authority.
			short, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			next, err := gate.WaitWrapRefresh(short)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Release()
			if err = next.AwaitFleetObservation(); err == nil {
				t.Fatal("later ticket reused failed observation")
			}
		})
	}
}
