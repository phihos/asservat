package contextstart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type regionProfileDefinition struct{ countingLocal }

func (*regionProfileDefinition) ResolveProfileEndpointDefinition(_ context.Context, r targets.ProfileEndpointDefinitionRequest) (targets.ProfileEndpointDefinitionResolution, error) {
	return targets.ProfileEndpointDefinitionResolution{Request: r, SourceClusterID: r.ClusterID, SourceUID: r.ClusterID, SourceName: "go-pprof", SourceDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, Host: "localhost", PathPolicy: "go-pprof/v1", LoopbackFamily: "ipv4", AddressModes: []string{"targetLoopback"}, MinimumPort: 6000, MaximumPort: 6999, SourceKind: targets.ProfileEndpointTemplateBinding, AddressMode: "targetLoopback", Binding: &r.Bindings[0]}, nil
}

func TestProfileEndpointDefinitionCrossesExistingRegionalExchange(t *testing.T) {
	for _, mode := range []string{"answer", "old-region", "wrong-answer", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			w := workFixture()
			cluster := w.Work.Target.ClusterID
			now := time.Now()
			receiver := fleet.APIContextReceiver{Channel: w.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
			router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
			if err != nil {
				t.Fatal(err)
			}
			standby, err := router.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer standby.Finish()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			r := targets.ProfileEndpointDefinitionRequest{ClusterID: cluster, Namespace: cfg.NamespaceRef{Name: "app", UID: "namespace"}, SourceRef: "local", Bindings: []targets.ProfileEndpointBinding{{Name: "local", TemplateRef: "go-pprof", AddressMode: "targetLoopback", PortName: "diagnostics"}}}
			done := make(chan error, 1)
			go func() {
				answer, e := (Targets{Router: router, Now: time.Now}).ResolveProfileEndpointDefinition(ctx, r)
				if e == nil && !answer.Answers(r) {
					e = targets.ErrInvalid
				}
				done <- e
			}()
			var job *queryJob
			select {
			case job = <-standby.query:
			case <-ctx.Done():
				t.Fatal("definition not dispatched")
			}
			if job.method != queryProfileEndpointDefinition {
				t.Fatal("wrong private operation")
			}
			var output bytes.Buffer
			stream, err := newFrameStream(ctx, w.Work.Channel, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil }, bytes.NewReader(nil), &output, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() {})
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			stream.targets = &regionProfileDefinition{}
			if mode == "old-region" {
				stream.targets = &countingLocal{}
			}
			raw, _ := json.Marshal(job.in)
			payload, err := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: job.method, Body: raw})
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
			if err != nil {
				t.Fatal(err)
			}
			var resultErr error
			if reply.Failure != "" {
				resultErr = queryFailureError(reply.Failure)
			} else if json.Unmarshal(reply.Body, job.out) != nil {
				t.Fatal("definition wire decode")
			}
			if mode == "wrong-answer" {
				job.out.(*targets.ProfileEndpointDefinitionResolution).Request.Namespace.UID = "replacement"
			}
			if mode == "cancelled" {
				cancel()
			}
			job.result <- queryResult{until: receiver.ValidUntil, err: resultErr}
			err = <-done
			if mode == "answer" && err != nil || mode != "answer" && err == nil {
				t.Fatal("definition result", mode, err)
			}
			if mode == "old-region" && !errors.Is(err, targets.ErrUnsupported) {
				t.Fatal("unsupported region changed refusal", err)
			}
		})
	}
}
