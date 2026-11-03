package bootstrap

import (
	"asservat.local/asservat/internal/adapters/jose"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
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
	for _, kind := range []string{"snapshot", "profile", "recording"} {
		t.Run(kind, func(t *testing.T) {
			work := fleetapp.SourceWork{NotAfter: time.Now().Add(time.Second)}
			work.Channel.Connector.Binding.ClusterID = runtimeID
			if kind == "snapshot" {
				work.StopSnapshot = &collector.SourceSnapshot{}
			} else if kind == "profile" {
				work.StopProfile = &collector.ProfileStop{}
			} else {
				work.StopRecording = &collector.RecordingStop{}
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

type recordingSigningTrustFunc func(context.Context) (fleet.APIContextWorkTrust, error)

func (f recordingSigningTrustFunc) APIContextWorkTrust(ctx context.Context) (fleet.APIContextWorkTrust, error) {
	return f(ctx)
}

func TestPublicRecordingStopRetainsRestrictivePurposeValidation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	const other = "22222222-2222-4222-8222-222222222222"
	channel := fleet.APIContextChannel{RootID: runtimeID, ExchangeID: runtimeID, Challenge: runtimeID,
		Hub:           fleet.OwnerBinding{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PodUID: runtimeID, ProcessEpoch: runtimeID},
		Connector:     fleet.ConnectorProcessIdentity{Binding: fleet.PeerBinding{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PeerID: runtimeID, Role: fleet.ConnectorPeer}, PodUID: runtimeID, ProcessEpoch: other},
		ConnectorLeaf: artifact.Digest{1}, Executor: fleet.APIContextExecutor{NamespaceUID: runtimeID, AccountUID: runtimeID, PodUID: runtimeID, ProcessEpoch: runtimeID, StartupDigest: artifact.Digest{1}, ImageDigest: artifact.Digest{1}}}
	stop := collector.RecordingStop{RootID: runtimeID, ClusterID: runtimeID, CaptureID: runtimeID, AttemptID: runtimeID, WriterPodUID: runtimeID, WriterEpoch: runtimeID, ExpectationDigest: artifact.Digest{1}, WriteUntil: now.Add(time.Minute)}
	base := fleetapp.SourceWork{Channel: channel, StopRecording: &stop, StopIssuedAt: now, NotAfter: now.Add(3 * time.Second)}
	if !base.Valid(now) {
		t.Fatal("invalid restrictive fixture")
	}
	mutations := map[string]func(*fleetapp.SourceWork){
		"original":           func(*fleetapp.SourceWork) {},
		"wrong writer":       func(w *fleetapp.SourceWork) { w.StopRecording.WriterEpoch = other },
		"wrong root":         func(w *fleetapp.SourceWork) { w.StopRecording.RootID = other },
		"mixed profile":      func(w *fleetapp.SourceWork) { w.StopProfile = &collector.ProfileStop{} },
		"mixed snapshot":     func(w *fleetapp.SourceWork) { w.StopSnapshot = &collector.SourceSnapshot{} },
		"mixed source stop":  func(w *fleetapp.SourceWork) { w.Stop = true },
		"source permit":      func(w *fleetapp.SourceWork) { w.Source.Permit.Binding.SourceID = runtimeID },
		"source node":        func(w *fleetapp.SourceWork) { w.Node.PodUID = runtimeID },
		"acquisition target": func(w *fleetapp.SourceWork) { w.Target.Request.ClusterID = runtimeID },
		"extended window":    func(w *fleetapp.SourceWork) { w.NotAfter = now.Add(6 * time.Second) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			work, copied := base, stop
			work.StopRecording = &copied
			mutate(&work)
			reads := 0
			unavailable := errors.New("independent signing trust unavailable")
			signer, err := jose.NewAPIContextWorkSignatures(recordingSigningTrustFunc(func(context.Context) (fleet.APIContextWorkTrust, error) {
				reads++
				return fleet.APIContextWorkTrust{}, unavailable
			}), "installed-key", func(context.Context) crypto.Signer { return nil }, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			_, err = (publicSigners{runtimeID: signer}).SignSourceWork(t.Context(), work)
			if name == "original" {
				if reads != 1 || !errors.Is(err, unavailable) {
					t.Fatal("restrictive work never reached independent trust", reads, err)
				}
			} else if reads != 0 || !errors.Is(err, fleet.ErrDenied) {
				t.Fatal("wrong or mixed purpose bypassed validation", reads, err)
			}
		})
	}
}
