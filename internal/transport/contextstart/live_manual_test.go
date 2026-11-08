package contextstart

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/node"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLiveManualQueryKeepsOriginalRegionalProcess(t *testing.T) {
	work := workFixture()
	cluster := work.Work.Target.ClusterID
	r, e := NewRouter(RouterLimits{Standby: 2, Captures: 1, Clusters: []ClusterLimit{{cluster, 2, 1}}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(r.Close)
	makeStandby := func(wrong bool) *Standby {
		c := work.Work.Channel
		if wrong {
			c.ExchangeID = "00000000-0000-4000-8000-000000000091"
			c.Executor.PodUID = "00000000-0000-4000-8000-000000000092"
			c.Connector.PodUID = c.Executor.PodUID
			c.Executor.ProcessEpoch = "00000000-0000-4000-8000-000000000093"
		}
		now := time.Now()
		receiver := fleet.APIContextReceiver{Channel: c, Window: identity.Check(now, identity.Recheck).Narrow(now.Add(5 * time.Second))}
		s, e := r.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(s.Finish)
		return s
	}
	original := makeStandby(false)
	wrong := makeStandby(true)
	call, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := r.QueryProcess(call, cluster, queryManualLive, struct{}{}, &struct{}{}, work.Work.Channel.Executor.PodUID, work.Work.Channel.Executor.ProcessEpoch)
		done <- e
	}()
	select {
	case job := <-original.query:
		job.result <- queryResult{until: time.Now().Add(time.Second)}
	case job := <-wrong.query:
		job.result <- queryResult{until: time.Now().Add(time.Second)}
		t.Fatal("passive manual query substituted another regional process")
	case <-call.Done():
		t.Fatal("original holder was not selected")
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	// An absent original process cannot fall through to a different live holder.
	missing, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer stop()
	done = make(chan error, 1)
	go func() {
		_, e := r.QueryProcess(missing, cluster, queryManualLive, struct{}{}, &struct{}{}, work.Work.Channel.Executor.PodUID, "00000000-0000-4000-8000-000000000094")
		done <- e
	}()
	select {
	case job := <-wrong.query:
		job.result <- queryResult{until: time.Now().Add(time.Second)}
		t.Fatal("missing process fell back")
	case e := <-done:
		if e == nil {
			t.Fatal("missing holder accepted")
		}
	}
	original.Finish()
	wrong.Finish()
}

func TestLiveManualInspectionMaximumBatchFitsOriginalFrames(t *testing.T) {
	work := workFixture()
	c := work.Work.Channel
	id := c.Executor.PodUID
	now := time.Now().UTC()
	process := execution.APIProcessBinding{InstallationID: c.Connector.Binding.InstallationID, ClusterID: c.Connector.Binding.ClusterID, IssuerEpoch: c.Connector.Binding.IssuerEpoch, NamespaceUID: c.Executor.NamespaceUID, AccountUID: c.Executor.AccountUID, PodUID: c.Executor.PodUID, ProcessEpoch: c.Executor.ProcessEpoch, StartupDigest: c.Executor.StartupDigest, ImageDigest: c.Executor.ImageDigest}
	in := make([]targets.ManualLiveTarget, 16)
	out := make([]manualLiveWire, 16)
	for n := range in {
		capture := fmt.Sprintf("00000000-0000-4000-8000-%012d", n+1)
		in[n] = targets.ManualLiveTarget{RootID: c.RootID, CaptureID: capture, AttemptID: id, ActionID: strings.Repeat("a", 128), Scope: artifact.Digest{1}, ExpectationDigest: artifact.Digest{2}, Target: work.Work.Target, Executor: process, WriteUntil: now.Add(5 * time.Minute), Projection: "syscallMetadata", ObservationKind: "arguments", ObservationSessionID: id, ObservationFence: id}
		m := collector.ManualLiveSource{RootID: c.RootID, CaptureID: capture, AttemptID: id, ActionID: in[n].ActionID, WorkID: id, PodUID: work.Work.Target.PodUID, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, ExecutorPodUID: c.Executor.PodUID, ExecutorEpoch: c.Executor.ProcessEpoch, Scope: [32]byte(in[n].Scope), ExpectationDigest: [32]byte(in[n].ExpectationDigest), StartedAt: now, HardUntil: now.Add(time.Minute), ObservationKind: "arguments", ObservationSessionID: id, ObservationFence: id}
		wire := node.WireManualLive(m)
		out[n] = manualLiveWire{CaptureID: capture, Source: &wire, ObservedAt: now, FreshUntil: now.Add(time.Second)}
	}
	request, _ := json.Marshal(in)
	response, _ := json.Marshal(out)
	encoded, e := contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: queryManualLive, Body: request})
	if e != nil {
		t.Fatal("16-source original request frame", len(request), e)
	}
	reply, e := contracts.EncodeAPIContextOperationReply(contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: queryManualLive, Body: response})
	if e != nil {
		t.Fatal("16-source original response frame", len(response), e)
	}
	if len(encoded) > contracts.APIContextOperationBytes || len(reply) > contracts.APIContextOperationBytes {
		t.Fatal("unbounded source frame")
	}
	t.Logf("16 finite sources original request=%d reply=%d under unchanged %d-byte frame", len(encoded), len(reply), contracts.APIContextOperationBytes)
}

// Exercise the actual hub decoder after the regional response is encoded with
// the compact node-observed shape. Accepted provenance is never node authority.
func TestLiveManualRegionalCompactReplyRebindsSixteenOriginals(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			work := workFixture()
			c := work.Work.Channel
			now := time.Now().UTC()
			router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{work.Work.Target.ClusterID, 1, 1}}})
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			receiver := fleet.APIContextReceiver{Channel: c, Window: identity.Check(now, identity.Recheck).Narrow(now.Add(5 * time.Second))}
			standby, err := router.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer standby.Finish()
			requests := make([]collector.LiveRead, 16)
			wire := make([]contracts.NodeLiveResult, 16)
			for n := range requests {
				id := fmt.Sprintf("00000000-0000-4000-8000-%012d", n+1)
				m := collector.ManualLiveSource{RootID: c.RootID, CaptureID: id, AttemptID: c.Executor.PodUID, ActionID: "packet", WorkID: id, PodUID: work.Work.Target.PodUID, NodeUID: c.Executor.PodUID, BootID: c.Executor.PodUID, CollectorPodUID: c.Executor.PodUID, CollectorEpoch: c.Executor.ProcessEpoch, ExecutorPodUID: c.Executor.PodUID, ExecutorEpoch: c.Executor.ProcessEpoch, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, StartedAt: now.Add(-time.Second), HardUntil: now.Add(9 * time.Second)}
				requests[n] = collector.LiveRead{Manual: &m, ClusterID: work.Work.Target.ClusterID, NamespaceUID: work.Work.Target.NamespaceUID, WorkloadUID: work.Work.Target.WorkloadUID, Projection: v.Packet, PrivacyUntil: m.HardUntil, Limit: 1, ReplyBytes: (28 << 10) / 16}
				observed := collector.ManualObserved(m)
				if changed && n == 15 {
					observed.WorkID = c.Executor.PodUID
				}
				row := v.Row{ID: id + ":1", SourceID: id, Sequence: 1, PodUID: m.PodUID, ObservedAt: now, ReceivedAt: now, ExpiresAt: now.Add(time.Second), Projection: v.Packet, Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", Direction: "egress"}}
				wire[n], err = node.WireLiveReply(m.CollectorEpoch, v.NodeReply{ObservedManual: &observed, SourceID: id, Fence: id, BootID: m.BootID, Clock: "monotonic", Sample: 100, Position: v.Position{Sequence: 1}, Rows: []v.StampedRow{{Row: row, Nanos: 100, Clock: "monotonic"}}, Examined: 1})
				if err != nil {
					t.Fatal(err)
				}
			}
			raw, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				select {
				case job := <-standby.query:
					e := json.Unmarshal(raw, job.out)
					job.result <- queryResult{until: now.Add(time.Second), err: e}
				case <-ctx.Done():
				}
			}()
			got, err := (Targets{Router: router, Now: time.Now}).ReadLiveBatch(ctx, requests)
			<-joined
			if changed {
				if err == nil || len(got) != 0 {
					t.Fatal("foreign final runtime tuple disclosed earlier rows")
				}
				return
			}
			if err != nil || len(got) != 16 || standby.queries != 1 {
				t.Fatal("compact original batch refused", len(got), err)
			}
			for n, p := range got {
				if p.Manual == nil || *p.Manual != *requests[n].Manual || p.ObservedManual != nil || len(p.Rows) != 1 {
					t.Fatal("accepted provenance not rebound after exact runtime check", n)
				}
			}
			t.Logf("16 compact replies=%d bytes; one original regional query; exact observed tuples rebound", len(raw))
		})
	}
}
