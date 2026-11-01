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
	work := fleetapp.SourceWork{StopSnapshot: &collector.SourceSnapshot{}, NotAfter: time.Now().Add(time.Second)}
	work.Channel.Connector.Binding.ClusterID = runtimeID
	// The routing layer must delegate to the existing purpose validator, which
	// refuses this deliberately invalid descriptor. It must not demand the empty
	// acquisition Target from a restrictive snapshot-only operation.
	if _, err = signers.SignSourceWork(t.Context(), work); !errors.Is(err, fleet.ErrDenied) {
		t.Fatal("snapshot cancel did not reach purpose validation", err)
	}
	work.StopSnapshot = nil
	if _, err = signers.SignSourceWork(t.Context(), work); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatal("ordinary arm accepted missing cluster target", err)
	}
	work.StopSnapshot = &collector.SourceSnapshot{}
	work.Channel.Connector.Binding.ClusterID = "uninstalled"
	if _, err = signers.SignSourceWork(t.Context(), work); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatal("cancellation routed to an uninstalled signer", err)
	}
}
