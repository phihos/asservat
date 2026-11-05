package analysis

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
)

type packetSourceRouteFixture struct {
	profileRouteFixture
	source value.ContextProjectionCandidate
}

func (r packetSourceRouteFixture) ResolvePacketProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	return r.source, nil
}

func TestRawPacketSummaryServiceUsesTypedSourceAndOriginalOwner(t *testing.T) {
	for _, mode := range []string{"ready", "pending-to-ready", "legacy-no-raw", "metadata-result", "metadata-route", "selection-in-route", "other-source", "other-route"} {
		t.Run(mode, func(t *testing.T) {
			f, request, summary := packetServiceFixture(t)
			s := &f.a.Scope
			s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, value.RawPacketSummaryDisplayVersion
			summary.CaptureMode = "rawPackets"
			summary.Packets = 2
			unclassified := int64(1)
			summary.UnclassifiedPackets = &unclassified
			c := s.Candidate()
			legacy := c
			legacy.NativeType = ""
			route := packetSourceRouteFixture{profileRouteFixture{legacy}, c}
			f.s.PacketRoutes = route
			switch mode {
			case "pending-to-ready":
				f.ready = false
			case "legacy-no-raw":
				f.s.PacketRoutes = profileRouteFixture{legacy}
			case "metadata-result":
				summary.CaptureMode = "networkHeaders"
				summary.Packets = 1
				summary.UnclassifiedPackets = nil
			case "metadata-route":
				route.source.NativeType = artifact.PCAPNGArtifact
				f.s.PacketRoutes = route
			case "selection-in-route":
				route.source.Selection = value.LineSelection{LineStart: 1, MaxLines: 1}
				f.s.PacketRoutes = route
			case "other-source":
				route.source.NativeType = artifact.PprofArtifact
				f.s.PacketRoutes = route
			case "other-route":
				route.source.PodUID = "different-original-pod"
				f.s.PacketRoutes = route
			}
			inv := f.invocation("get_pcap_summary")
			inv.input = ContextQueryInput{Packet: request}
			reads, _ := f.s.PacketSummaries()
			d, err := reads.Begin(t.Context(), f, inv, request)
			if mode != "ready" && mode != "pending-to-ready" {
				if err == nil || d != nil {
					t.Fatal("invalid raw summary route/result delivered", mode)
				}
				if mode != "metadata-result" && f.admissions != 0 {
					t.Fatal("unresolved source reached admission")
				}
				return
			}
			if err != nil || d == nil {
				t.Fatal("exact raw source did not reach fixed aggregate", err)
			}
			if mode == "pending-to-ready" {
				id := d.Association().QueryID
				if !d.Pending() {
					t.Fatal("missing pending")
				}
				if err := d.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				f.ready = true
				poll := f.invocation("get_query_result")
				poll.input = ContextQueryInput{QueryID: id}
				d, err = f.s.Results.GetQueryResult(t.Context(), f, poll, id)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, ok := d.PacketSummary()
			if !ok || got.CaptureMode != "rawPackets" || got.UnclassifiedPackets == nil || *got.UnclassifiedPackets != 1 || f.starts != 1 || f.admissions != 1 || f.reads != 1 || f.q.Scope.QueryUnits() != 2 {
				t.Fatal("raw aggregate changed source/owner/accounting")
			}
			*got.UnclassifiedPackets = 9
			again, ok := d.PacketSummary()
			if !ok || *again.UnclassifiedPackets != 1 {
				t.Fatal("unclassified counter aliases held result")
			}
			if err := d.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, ok := d.PacketSummary(); ok || summary.UnclassifiedPackets != nil || summary.Conversations != nil || !f.lastRead.closed {
				t.Fatal("raw aggregate survived joined close")
			}
		})
	}
}

func TestPacketSummaryTypedMetadataRoutePreservesExistingResult(t *testing.T) {
	f, request, _ := packetServiceFixture(t)
	c := f.a.Scope.Candidate()
	legacy := c
	legacy.NativeType = ""
	f.s.PacketRoutes = packetSourceRouteFixture{profileRouteFixture{legacy}, c}
	inv := f.invocation("get_pcap_summary")
	inv.input = ContextQueryInput{Packet: request}
	reads, _ := f.s.PacketSummaries()
	d, err := reads.Begin(t.Context(), f, inv, request)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(context.Background())
	summary, ok := d.PacketSummary()
	if !ok || summary.CaptureMode != "networkHeaders" || summary.UnclassifiedPackets != nil {
		t.Fatal("typed routing changed legacy metadata result")
	}
}
