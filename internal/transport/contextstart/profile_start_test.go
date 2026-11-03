package contextstart

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/targets"
)

type fakeProfileOutput struct{ fakeRecorderOutput }

func (o *fakeProfileOutput) StartProfile(_ context.Context, _ artifact.PinnedPod, started, until time.Time, _ targets.ProfileEndpointRequest) (time.Time, error) {
	o.started++
	return started, nil
}
func TestProfileStartRequiresOriginalCommittedTimeAndTypedExpectation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	w := workFixture().Work
	pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: "ns", Name: "web", UID: w.Target.PodUID}
	req := profileRequest{Pin: pin, Started: now, Until: now.Add(time.Second)}
	for _, change := range []string{"missing", "renewed", "pin", "noProfile", "valid"} {
		t.Run(change, func(t *testing.T) {
			local := (&countingLocal{}).local()
			out := &fakeProfileOutput{}
			s := &regionalSession{local: local, work: w, prepared: out, resolved: &targets.PodResolution{Pin: pin}, expectation: &artifact.ContextExpectation{Profile: &artifact.GoProfileAcquisition{}}, consumed: &value.Disposition{MayStart: true, Phase: value.StartCommitted, CommittedAt: now, ValidUntil: now.Add(2 * time.Second)}}
			r := req
			switch change {
			case "missing":
				s.consumed = nil
			case "renewed":
				r.Started = now.Add(time.Microsecond)
			case "pin":
				r.Pin.UID = "other"
			case "noProfile":
				s.expectation.Profile = nil
			}
			b, _ := json.Marshal(r)
			op := contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: opStartProfile, Body: b}
			_, err := s.handle(context.Background(), op)
			if change != "valid" {
				if err == nil || out.started != 0 {
					t.Fatal("invalid start", err)
				}
				return
			}
			if err != nil || out.started != 1 {
				t.Fatal("valid start", err)
			}
			if _, err := s.handle(context.Background(), op); err == nil || out.started != 1 {
				t.Fatal("replayed start", err)
			}
		})
	}
}
