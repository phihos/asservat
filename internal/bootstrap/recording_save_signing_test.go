package bootstrap

import (
	"asservat.local/asservat/internal/adapters/jose"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"context"
	"crypto"
	"errors"
	"testing"
	"time"
)

type recordingSigningTrust struct{}

func (recordingSigningTrust) APIContextWorkTrust(context.Context) (fleet.APIContextWorkTrust, error) {
	return fleet.APIContextWorkTrust{}, fleet.ErrUnavailable
}
func TestPublicSnapshotCancellationReachesPurposeValidatorWithoutAcquisitionTarget(t *testing.T) {
	signer, err := jose.NewAPIContextWorkSignatures(recordingSigningTrust{}, "installed-key", func(context.Context) crypto.Signer { return nil }, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	signers := publicSigners{runtimeID: signer}
	for _, kind := range []string{"snapshot", "profile"} {
		t.Run(kind, func(t *testing.T) {
			work := fleetapp.SourceWork{NotAfter: time.Now().Add(time.Second)}
			work.Channel.Connector.Binding.ClusterID = runtimeID
			if kind == "snapshot" {
				work.StopSnapshot = &collector.SourceSnapshot{}
			} else {
				work.StopProfile = &collector.ProfileStop{}
			}
			// Reach the actual purpose validator, which refuses this deliberately
			// invalid descriptor. Restrictive work has no acquisition Target;
			// routing must not reject it before its own authority is checked.
			if _, err := signers.SignSourceWork(t.Context(), work); !errors.Is(err, fleet.ErrDenied) {
				t.Fatal("cancel did not reach purpose validation", err)
			}
			work.Channel.Connector.Binding.ClusterID = "uninstalled"
			if _, err := signers.SignSourceWork(t.Context(), work); !errors.Is(err, fleet.ErrUnavailable) {
				t.Fatal("cancellation routed to an uninstalled signer", err)
			}
		})
	}
	work := fleetapp.SourceWork{NotAfter: time.Now().Add(time.Second)}
	work.Channel.Connector.Binding.ClusterID = runtimeID
	if _, err = signers.SignSourceWork(t.Context(), work); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatal("ordinary arm accepted missing cluster target", err)
	}
}
