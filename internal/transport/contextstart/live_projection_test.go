package contextstart

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type liveQueryResolver struct {
	countingLocal
	reply     v.NodeReply
	callsLive int
}

func (r *liveQueryResolver) ReadLiveProjections(ctx context.Context, in []collector.LiveRead) ([]v.NodeReply, error) {
	r.callsLive++
	return []v.NodeReply{r.reply}, nil
}
func TestLiveRegionalQueryChecksOriginalChannelAndNeverAcquires(t *testing.T) {
	for _, mode := range []string{"exact", "wrong-root", "wrong-cluster", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			work, _ := sourceStreamWorkFixture()
			now := time.Now()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			r := collector.LiveRead{Binding: work.Source.Permit.Binding, ClusterID: work.Channel.Connector.Binding.ClusterID, NamespaceUID: "ns", WorkloadUID: "work", Projection: v.Packet, PrivacyUntil: work.Source.Permit.HardUntil, Head: true, Limit: 100, ReplyBytes: 24 << 10}
			if mode == "wrong-root" {
				r.Binding.RootID = "22222222-2222-4222-8222-222222222222"
			}
			if mode == "wrong-cluster" {
				r.ClusterID = "22222222-2222-4222-8222-222222222222"
			}
			resolver := &liveQueryResolver{reply: v.NodeReply{WorkID: r.Binding.SourceID, SourceID: r.Binding.SourceID, Fence: r.Binding.Fence, BootID: r.Binding.BootID, Clock: "monotonic", Sample: 100, Rows: []v.StampedRow{}, Position: v.Position{Sequence: 1}}}
			receiver := fleet.APIContextReceiver{Channel: work.Channel, Window: identity.Check(now, identity.Recheck).Narrow(now.Add(5 * time.Second))}
			var output bytes.Buffer
			checks := 0
			stream, e := newFrameStream(ctx, work.Channel, func(context.Context) (fleet.APIContextReceiver, error) { checks++; return receiver, nil }, bytes.NewReader(nil), &output, func(time.Time) error { return nil }, func(time.Time) error { return nil }, func() error { return nil }, func() {})
			if e != nil {
				t.Fatal(e)
			}
			defer stream.Close()
			stream.targets = resolver
			if mode == "unsupported" {
				stream.targets = &resolver.countingLocal
			}
			raw, _ := json.Marshal(liveBatchWire([]collector.LiveRead{r}))
			payload, e := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: queryLiveProjection, Body: raw})
			if e != nil {
				t.Fatal(e)
			}
			e = stream.answerQuery(ctx, contracts.APIContextFrame{Kind: contracts.APIContextQueryFrame, Payload: payload})
			if mode == "wrong-root" || mode == "wrong-cluster" {
				if e == nil || resolver.callsLive != 0 || output.Len() != 0 {
					t.Fatal("foreign root/cluster dispatched", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			frame, e := contracts.ReadAPIContextFrame(&output)
			if e != nil {
				t.Fatal(e)
			}
			reply, e := contracts.DecodeAPIContextOperationReply(frame.Payload)
			if e != nil {
				t.Fatal(e)
			}
			if resolver.calls != 0 || checks != 1 {
				t.Fatal("live query acquired or repeated owner observation")
			}
			if mode == "unsupported" {
				if reply.Failure != "unsupported" || resolver.callsLive != 0 || len(reply.Body) != 0 {
					t.Fatal(reply)
				}
				return
			}
			var values []contracts.NodeLiveResult
			var got contracts.NodeLiveResult
			if json.Unmarshal(reply.Body, &values) == nil && len(values) == 1 {
				got = values[0]
			}
			if reply.Failure != "" || len(values) != 1 || got.SourceID != r.Binding.SourceID || got.Sequence != 1 || resolver.callsLive != 1 {
				t.Fatal("source epoch changed", reply, got)
			}
		})
	}
}

func TestLiveRegionalMaximumReferenceBatchFitsExistingFrame(t *testing.T) {
	work, _ := sourceStreamWorkFixture()
	requests := make([]collector.LiveRead, 16)
	for n := range requests {
		b := work.Source.Permit.Binding
		b.SourceID = fmt.Sprintf("11111111-1111-4111-8111-%012d", n)
		b.Fence = b.SourceID
		b.PolicyUID = strings.Repeat("p", 128)
		b.ActionID = strings.Repeat("a", 128)
		for i := range b.Scope {
			b.Scope[i] = 255
			b.ExpectationDigest[i] = 255
			b.ProgramDigest[i] = 255
			b.ResourceDigest[i] = 255
			b.AudienceDigest[i] = 255
		}
		requests[n] = collector.LiveRead{Binding: b, ClusterID: work.Channel.Connector.Binding.ClusterID, NamespaceUID: strings.Repeat("n", 128), WorkloadUID: strings.Repeat("w", 128), Projection: v.Packet, PrivacyUntil: time.Now().Add(time.Hour), AfterSequence: 1<<53 - 1, AfterLost: 1<<63 - 1, Limit: 7, ReplyBytes: (28 << 10) / 16, WaitMS: 5000}
	}
	if !validLiveBatch(requests) {
		t.Fatal("valid reference batch rejected")
	}
	raw, e := json.Marshal(liveBatchWire(requests))
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 8, Method: queryLiveProjection, Body: raw})
	if e != nil {
		t.Fatalf("maximum sixteen references overflow existing32KiB frame: body%d, %v", len(raw), e)
	}
	t.Logf("maximum private live request%d bytes (body%d)", len(encoded), len(raw))
}
