package contextstart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type workloadIdentityQueryResolver struct {
	countingLocal
	resolution targets.WorkloadIdentityResolution
	requests   []targets.WorkloadRequest
}

func (p *workloadIdentityQueryResolver) ResolveWorkloadIdentity(_ context.Context, r targets.WorkloadRequest) (targets.WorkloadIdentityResolution, error) {
	p.requests = append(p.requests, r)
	return p.resolution, nil
}
func TestWorkloadIdentityRegionalQueryDispatchAndUnsupportedPeerFailClosed(t *testing.T) {
	for _, mode := range []string{"current-peer", "unsupported-resolver", "unknown-method"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			work := workFixture()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			request := targets.WorkloadRequest{ClusterID: work.Work.Channel.Connector.Binding.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"}
			root := targets.WorkloadIdentityResolution{Reference: request, ClusterID: request.ClusterID, Namespace: cfg.NamespaceRef{Name: "app", UID: "namespace"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: "deployment"}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			resolver := &workloadIdentityQueryResolver{resolution: root}

			receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
			checks := 0
			var output bytes.Buffer
			stream, err := newFrameStream(ctx, work.Work.Channel, func(context.Context) (fleet.APIContextReceiver, error) { checks++; return receiver, nil }, bytes.NewReader(nil), &output, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() {})
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			stream.targets = resolver
			if mode == "unsupported-resolver" {
				stream.targets = &resolver.countingLocal
			}
			method := queryResolveWorkloadIdentity
			if mode == "unknown-method" {
				method = "unknown-future-query"
			}
			raw, _ := json.Marshal(request)
			payload, err := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: method, Body: raw})
			if err != nil {
				t.Fatal(err)
			}
			err = stream.answerQuery(ctx, contracts.APIContextFrame{Kind: contracts.APIContextQueryFrame, Payload: payload})
			if mode == "unknown-method" {
				if !errors.Is(err, contracts.ErrAPIContextProtocol) || output.Len() != 0 || len(resolver.requests) != 0 || resolver.calls != 0 {
					t.Fatal("unknown method dispatched or replied", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			frame, err := contracts.ReadAPIContextFrame(&output)
			if err != nil || frame.Kind != contracts.APIContextAnswerFrame {
				t.Fatal("missing closed reply", err)
			}
			reply, err := contracts.DecodeAPIContextOperationReply(frame.Payload)
			if err != nil || reply.Method != method || checks != 1 || resolver.calls != 0 {
				t.Fatal("repeated owner or old target dispatch", reply, checks, resolver.calls, err)
			}
			if mode == "unsupported-resolver" {
				if reply.Failure != "unsupported" || len(resolver.requests) != 0 || len(reply.Body) != 0 {
					t.Fatal("unsupported peer fabricated/fell back", reply)
				}
				return
			}
			var got targets.WorkloadIdentityResolution
			if reply.Failure != "" || json.Unmarshal(reply.Body, &got) != nil || got != resolver.resolution || len(resolver.requests) != 1 || resolver.requests[0] != request {
				t.Fatal("current peer did not compose one exact read", reply, got, resolver.requests)
			}
		})
	}
}
