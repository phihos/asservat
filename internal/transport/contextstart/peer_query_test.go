package contextstart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type regionPeers struct {
	countingLocal
	err error
}

func (p *regionPeers) ResolvePacketPeers(_ context.Context, r targets.PeerRequest) (targets.PeerResolution, error) {
	return targets.PeerResolution{Request: r, Members: []targets.PeerMember{{Kind: "Pod", UID: "pod-a", IP: "10.0.0.11"}}}, p.err
}

// ADR-283 PR 2: the region answers resolved members, and its closed peer
// failures cross the exchange as their own labels so the hub can name the
// remedy; a region without the resolver answers unsupported.
func TestPacketPeersCrossRegionalExchange(t *testing.T) {
	work := workFixture()
	request := targets.PeerRequest{ClusterID: work.Work.Channel.Connector.Binding.ClusterID, Namespace: cfg.NamespaceRef{Name: "app", UID: "namespace"}, MaxEndpoints: 8,
		Entries: []targets.PeerEntry{{Resource: &targets.PeerResourceRef{Kind: "Deployment", Namespace: "app", Name: "db"}}}}
	for name, tc := range map[string]struct {
		local   any
		failure string
		want    error
	}{
		"answer":      {&regionPeers{}, "", nil},
		"limit":       {&regionPeers{err: targets.ErrPeerLimit}, "peer-limit", targets.ErrPeerLimit},
		"unsupported": {&regionPeers{err: targets.ErrPeerUnsupported}, "peer-unsupported", targets.ErrPeerUnsupported},
		"missing":     {&regionPeers{err: targets.ErrPeerMissing}, "peer-missing", targets.ErrPeerMissing},
		"busy":        {&regionPeers{err: targets.ErrPeerVerifierBusy}, "peer-busy", targets.ErrPeerVerifierBusy},
		"old region":  {&countingLocal{}, "unsupported", targets.ErrUnsupported},
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
			var output bytes.Buffer
			stream, err := newFrameStream(ctx, work.Work.Channel, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil }, bytes.NewReader(nil), &output, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() {})
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			stream.targets = tc.local.(QueryTargets)
			raw, _ := json.Marshal(request)
			payload, err := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: queryResolvePacketPeers, Body: raw})
			if err != nil {
				t.Fatal(err)
			}
			if err = stream.answerQuery(ctx, contracts.APIContextFrame{Kind: contracts.APIContextQueryFrame, Payload: payload}); err != nil {
				t.Fatal(err)
			}
			frame, err := contracts.ReadAPIContextFrame(&output)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := contracts.DecodeAPIContextOperationReply(frame.Payload)
			if err != nil || reply.Failure != tc.failure {
				t.Fatal(reply, err)
			}
			if tc.want != nil {
				if !errors.Is(queryFailureError(reply.Failure), tc.want) {
					t.Fatal("failure label lost", reply.Failure)
				}
				return
			}
			var answer targets.PeerResolution
			if json.Unmarshal(reply.Body, &answer) != nil || !answer.Answers(request) || len(answer.Members) != 1 {
				t.Fatalf("answer %s", reply.Body)
			}
		})
	}
}

// ADR-283 part 3: the connector's start refusals cross the operation
// exchange with their own closed labels.
func TestPeerStartFailuresCrossOperationExchange(t *testing.T) {
	for label, err := range map[string]error{"peers-changed": targets.ErrPeersChanged, "peers-stale": targets.ErrPeersStale, "peer-busy": targets.ErrPeerVerifierBusy} {
		if got := operationFailureLabel(fmt.Errorf("start: %w", err)); got != label || !errors.Is(operationFailureError(got), err) {
			t.Fatal(label, got)
		}
	}
}
