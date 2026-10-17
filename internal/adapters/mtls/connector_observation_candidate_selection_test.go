package mtls

import (
	"context"
	"fmt"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

type branchObservationCandidates struct {
	legacy, installed observationCandidatesFunc
}

func (s branchObservationCandidates) ReadContextStartOwners(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return s.legacy(ctx)
}
func (s branchObservationCandidates) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return s.installed(ctx)
}

// The retained real TLS/exporter still requires four fresh selected candidate
// reads. Omitted legacy authority is neither a fallback nor a second source.
func TestConnectorObservationChannelSelectsCompleteOriginalCandidatesOnEveryProof(t *testing.T) {
	for _, mode := range []string{"four-fresh-reads", "unavailable-second-read", "changed-limit-second-read"} {
		t.Run(mode, func(t *testing.T) {
			x := newObservationChannelFixture(t, 17)
			legacy, installed := 0, 0
			source := branchObservationCandidates{
				legacy: func(context.Context) (value.APIContextOwnerCandidates, error) {
					legacy++
					return value.APIContextOwnerCandidates{}, value.ErrUnavailable
				},
				installed: func(context.Context) (value.APIContextOwnerCandidates, error) {
					installed++
					v := value.APIContextOwnerCandidates{Pool: x.ownerPin.Pool, ObservedAt: x.f.clock(), ValidUntil: x.f.clock().Add(5 * time.Second)}
					for i := 1; i <= 16; i++ {
						b := x.owner.Binding
						b.ProcessEpoch = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
						v.Owners = append(v.Owners, b)
					}
					v.Owners = append(v.Owners, x.owner.Binding)
					if installed > 1 && mode == "unavailable-second-read" {
						return value.APIContextOwnerCandidates{}, value.ErrUnavailable
					}
					if installed > 1 && mode == "changed-limit-second-read" {
						v.Pool.NativeCandidateLimit = 18
					}
					return v, nil
				},
			}
			selected, err := app.NewOwnerObservationCandidateSelection(x.ownerPin.Pool, source)
			if err != nil {
				t.Fatal(err)
			}
			x.channel.candidates = selected
			r := x.request()
			if _, err = x.channel.AnswerConnectorObservation(x.ctx, x.probe(t, r, 1)); err != nil {
				t.Fatal("first complete current candidate read", err)
			}
			_, err = x.channel.AnswerConnectorObservation(x.ctx, x.probe(t, r, 2))
			if mode != "four-fresh-reads" {
				if err == nil || legacy != 0 || installed != 2 || x.metadataCalls != 0 {
					t.Fatal("unavailable/changed selected source reached metadata", err, legacy, installed)
				}
				if _, err = x.channel.AnswerConnectorObservation(x.ctx, x.probe(t, r, 2)); err == nil || installed != 2 {
					t.Fatal("unknown selected read retried")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := x.channel.ObserveCluster(x.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range []int{3, 4} {
				if _, err = x.channel.AnswerConnectorObservation(x.ctx, x.probe(t, r, n)); err != nil {
					t.Fatal(err)
				}
			}
			receipt := contracts.ClusterObservationReceipt{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: ownerOtherID, RequestID: r.ID, Challenge: r.Challenge, RequestDigest: ownerObservationHex(result.RequestDigest)}
			if err = x.channel.AcceptObservationReceipt(x.ctx, receipt); err != nil || legacy != 0 || installed != 4 || x.metadataCalls != 1 {
				t.Fatal("current candidate count/receipt", err, legacy, installed, x.metadataCalls)
			}
		})
	}
}

func TestConnectorObservationChannelRejectsAnotherOriginalCandidateSelection(t *testing.T) {
	x := newObservationChannelFixture(t, 17)
	p := x.ownerPin.Pool
	p.NativeCandidateLimit = 18
	source := branchObservationCandidates{
		legacy: func(context.Context) (value.APIContextOwnerCandidates, error) {
			return value.APIContextOwnerCandidates{}, value.ErrUnavailable
		},
		installed: func(context.Context) (value.APIContextOwnerCandidates, error) {
			return value.APIContextOwnerCandidates{}, value.ErrUnavailable
		},
	}
	selected, err := app.NewOwnerObservationCandidateSelection(p, source)
	if err != nil {
		t.Fatal(err)
	}
	before := value.APIContextOwnerCandidates{Pool: x.ownerPin.Pool, Owners: []value.OwnerBinding{x.owner.Binding}, ObservedAt: x.f.clock(), ValidUntil: x.f.clock().Add(5 * time.Second)}
	channel, err := NewConnectorObservationChannel(x.ctx, ownerOtherID, x.ownerPin, x.ownerCA.roots, before, &x.channel.state, x.leaf, x.channel.producer, selected, x.channel.registry, x.channel.metadata, x.f.clock)
	if err == nil || channel != nil {
		if channel != nil {
			channel.Close()
		}
		t.Fatal("channel accepted a different original installed population limit")
	}
}
