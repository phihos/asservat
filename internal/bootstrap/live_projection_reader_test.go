package bootstrap

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"context"
	"testing"
	"time"
)

type liveRemoteFunc func(context.Context, collector.LiveRead) (v.NodeReply, error)

func (f liveRemoteFunc) ReadLiveBatch(ctx context.Context, requests []collector.LiveRead) ([]v.NodeReply, error) {
	out := make([]v.NodeReply, len(requests))
	for n, r := range requests {
		value, e := f(ctx, r)
		if e != nil {
			return nil, e
		}
		out[n] = value
	}
	return out, nil
}
func TestLivePrivateProjectionUsesOriginalClockAndLossDelta(t *testing.T) {
	now := time.Now()
	p := sourceOwnerPermit(now)
	source := v.Source{Binding: p.Binding, Target: authorization.Target{ClusterID: p.Binding.RootID, NamespaceUID: "ns", WorkloadUID: "work", PodUID: p.Binding.PodUID}, OwnerKind: "policy", OwnerID: "policy", State: "Ready", SaveVia: "recordingSave", Projections: []string{v.Packet}, LeaseUntil: p.LeafUntil, HardUntil: p.HardUntil, PrivacyUntil: p.HardUntil}
	remote := liveRemoteFunc(func(ctx context.Context, r collector.LiveRead) (v.NodeReply, error) {
		if r.Binding != source.Binding || r.AfterSequence != 3 || r.AfterLost != 5 || r.Head || r.WaitMS != 0 {
			t.Fatal("substituted source/request", r)
		}
		row := v.Row{ID: p.Binding.SourceID + ":4", SourceID: p.Binding.SourceID, Sequence: 4, PodUID: p.Binding.PodUID, Projection: v.Packet, Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", Direction: "egress"}}
		return v.NodeReply{SourceID: source.ID(), Fence: p.Binding.Fence, BootID: source.Boot(), Clock: "monotonic", Sample: int64(time.Hour), Position: v.Position{Sequence: 4, Lost: 7}, Examined: 1, Bytes: 500, Rows: []v.StampedRow{{Row: row, Nanos: int64(time.Hour - time.Second), Clock: "monotonic"}}}, nil
	})
	reader := liveProjectionReader{remote: remote, now: func() time.Time { return now }}
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(5*time.Second))
	defer cancel()
	out, e := reader.Read(ctx, []v.Source{source}, v.Packet, []v.Position{{Sequence: 3, Lost: 5}}, 100, 4096, 0)
	if e != nil || len(out.Rows) != 1 || !out.Rows[0].ObservedAt.Equal(now.Add(-time.Second)) || !out.Rows[0].ExpiresAt.Equal(now.Add(29*time.Second)) || len(out.Gaps) != 1 || out.Gaps[0].Count == nil || *out.Gaps[0].Count != 2 {
		t.Fatal(out, e)
	}
	// The same cumulative lost count is not counted again next time.
	remote = func(ctx context.Context, r collector.LiveRead) (v.NodeReply, error) {
		return v.NodeReply{SourceID: source.ID(), Fence: p.Binding.Fence, BootID: source.Boot(), Clock: "monotonic", Sample: int64(time.Hour), Position: v.Position{Sequence: 4, Lost: 7}}, nil
	}
	reader.remote = remote
	again, e := reader.Read(ctx, []v.Source{source}, v.Packet, out.Positions, 100, 4096, 0)
	if e != nil || len(again.Gaps) != 0 || len(again.Rows) != 0 {
		t.Fatal("recounted old loss", again, e)
	}
}
func TestLivePrivateProjectionRejectsWrongClockAndForeignEpoch(t *testing.T) {
	now := time.Now()
	p := sourceOwnerPermit(now)
	source := v.Source{Binding: p.Binding, Target: authorization.Target{ClusterID: p.Binding.RootID, NamespaceUID: "ns", WorkloadUID: "work", PodUID: p.Binding.PodUID}, OwnerKind: "policy", OwnerID: "policy", State: "Ready", SaveVia: "recordingSave", Projections: []string{v.Packet}, LeaseUntil: p.LeafUntil, HardUntil: p.HardUntil, PrivacyUntil: p.HardUntil}
	for _, kind := range []string{"clock", "source"} {
		t.Run(kind, func(t *testing.T) {
			reader := liveProjectionReader{now: func() time.Time { return now }, remote: liveRemoteFunc(func(context.Context, collector.LiveRead) (v.NodeReply, error) {
				row := v.Row{ID: "row", SourceID: source.ID(), Sequence: 1, PodUID: source.Pod(), Projection: v.Packet, Packet: &v.PacketFields{Protocol: "TCP", RemoteIP: "192.0.2.1", Direction: "egress"}}
				reply := v.NodeReply{SourceID: source.ID(), Fence: p.Binding.Fence, BootID: source.Boot(), Clock: "monotonic", Sample: int64(time.Hour), Position: v.Position{Sequence: 1}, Rows: []v.StampedRow{{Row: row, Nanos: int64(time.Hour), Clock: "boottime"}}}
				if kind == "source" {
					reply.Fence = "replacement"
				}
				return reply, nil
			})}
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Second))
			defer cancel()
			out, e := reader.Read(ctx, []v.Source{source}, v.Packet, []v.Position{{}}, 100, 4096, 0)
			if kind == "source" {
				if e == nil {
					t.Fatal("foreign source")
				}
				return
			}
			if e != nil || len(out.Rows) != 0 || len(out.Gaps) != 1 || out.Gaps[0].Reason != "clockUncertain" {
				t.Fatal(out, e)
			}
		})
	}
}
