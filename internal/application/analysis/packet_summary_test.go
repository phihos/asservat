package analysis

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
)

type packetReaderFixture struct {
	*projectionFixture
	summary *value.PacketSummary
}

func (f packetReaderFixture) ReadProjection(ctx context.Context, start value.ContextReadStart, owner ContextProjectionRequestOwner) (ContextProjectionRead, error) {
	r, err := f.projectionFixture.ReadProjection(ctx, start, owner)
	if err != nil {
		return r, err
	}
	return packetResultFixture{ContextProjectionRead: r, summary: f.summary}, nil
}

type packetResultFixture struct {
	ContextProjectionRead
	summary *value.PacketSummary
}

func (f packetResultFixture) Projection(context.Context) (value.ProjectionResult, error) {
	return value.ProjectionResult{PacketSummary: f.summary}, nil
}
func packetServiceFixture(t *testing.T) (*projectionFixture, value.PacketSummaryRequest, *value.PacketSummary) {
	f := newProjectionFixture(t)
	s := &f.a.Scope
	s.NativeType = artifact.PCAPNGArtifact
	s.SourceFormat = artifact.PCAPNGFormat
	s.DisplayVersion = value.PacketSummaryDisplayVersion
	s.SourceProjectionDigest = artifact.Digest{}
	s.Selection = value.LineSelection{}
	f.p.Profile.Worker.MemoryBytes = value.PacketSummaryWorkerBytes
	f.p.Profile.Worker.WorkerTransientBytes = value.PacketSummaryWorkerBytes
	c := s.Candidate()
	c.NativeType = ""
	f.s.PacketRoutes = profileRouteFixture{c}
	drops := int64(3)
	summary := &value.PacketSummary{CaptureMode: "networkHeaders", Packets: 1, Drops: &drops, DropReporting: "captureExclusions", Conversations: []value.PacketConversation{{Source: "192.0.2.1:123", Destination: "192.0.2.2:456", Protocol: "TCP", Packets: 1}}, ConversationsTotal: 1}
	f.s.Results.Reader = packetReaderFixture{f, summary}
	return f, value.PacketSummaryRequest{CaseID: s.CaseID, ArtifactID: s.ArtifactID}, summary
}
func TestPacketSummaryAdmissionPinsToolRouteBudgetAndInput(t *testing.T) {
	for _, mode := range []string{"ready", "pending", "disabled", "wrong-tool", "wrong-input", "source-in-route", "selection-in-route", "underfunded-memory", "underfunded-transient", "authority-refused", "admit-error", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f, request, summary := packetServiceFixture(t)
			f.ready = mode != "pending"
			inv := f.invocation("get_pcap_summary")
			inv.input = ContextQueryInput{Packet: request}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "disabled":
				f.s.PacketRoutes = nil
			case "wrong-tool":
				inv.call.Tool = "get_profile_summary"
			case "wrong-input":
				inv.input.Packet.ArtifactID = f.next()
			case "source-in-route":
				c := f.a.Scope.Candidate()
				f.s.PacketRoutes = profileRouteFixture{c}
			case "selection-in-route":
				c := f.a.Scope.Candidate()
				c.NativeType = ""
				c.Selection = value.LineSelection{LineStart: 1, MaxLines: 1}
				f.s.PacketRoutes = profileRouteFixture{c}
			case "underfunded-memory":
				f.p.Profile.Worker.MemoryBytes = 64 << 20
			case "underfunded-transient":
				f.p.Profile.Worker.WorkerTransientBytes = 8 << 20
			case "authority-refused":
				f.authorityErr = value.ErrUnavailable
			case "admit-error":
				f.queryErr = value.ErrUnavailable
			case "cancelled":
				cancel()
			}
			service, enabled := f.s.PacketSummaries()
			if enabled != (mode != "disabled") {
				t.Fatal("optional facet changed")
			}
			d, err := service.Begin(ctx, f, inv, request)
			if mode != "ready" && mode != "pending" {
				if err == nil || d != nil || f.starts+f.reads != 0 {
					t.Fatal("refused input reached worker/read", mode, err)
				}
				if mode == "authority-refused" && (!PacketSummaryUnavailableBeforeAdmission(err) || f.admissions != 0) {
					t.Fatal("pre-admission refusal lost classification")
				}
				if mode == "admit-error" && PacketSummaryUnavailableBeforeAdmission(err) {
					t.Fatal("attempted admission misclassified effect-free")
				}
				return
			}
			if err != nil || d == nil || d.Pending() != (mode == "pending") || d.Tool() != "get_pcap_summary" || f.admissions != 1 || f.starts != 1 || f.q.Scope.QueryUnits() != 2 || f.q.Scope.ReadBatches() != 1 {
				t.Fatal("packet query changed original admission", err)
			}
			inv.outcome = d
			if mode == "ready" {
				first, ok := d.PacketSummary()
				if !ok || !first.Valid() || f.reads != 1 {
					t.Fatal("ready summary missing")
				}
				*first.Drops = 99
				first.Conversations[0].Source = "198.51.100.1:1"
				second, ok := d.PacketSummary()
				if !ok || *second.Drops != 3 || second.Conversations[0].Source != "192.0.2.1:123" {
					t.Fatal("public summary aliases held result")
				}
				if !d.RefuseOversizedResult() {
					t.Fatal("size refusal could not retain charged read")
				}
				if _, ok := d.PacketSummary(); ok || f.lastRead.closed {
					t.Fatal("size refusal disclosed/closed before outcome")
				}
			}
			if err := d.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, ok := d.PacketSummary(); ok {
				t.Fatal("closed result disclosed")
			}
			if mode == "ready" && (summary.Conversations != nil || summary.Drops != nil || !f.lastRead.closed || f.completions != 1) {
				t.Fatal("packet result/read not cleared and joined")
			}
		})
	}
}
func TestPacketSummaryPollUsesSamePaidQueryAndDoesNotAcquire(t *testing.T) {
	f, request, _ := packetServiceFixture(t)
	f.ready = false
	inv := f.invocation("get_pcap_summary")
	inv.input = ContextQueryInput{Packet: request}
	reads, _ := f.s.PacketSummaries()
	pending, err := reads.Begin(t.Context(), f, inv, request)
	if err != nil {
		t.Fatal(err)
	}
	id := pending.Association().QueryID
	if err := pending.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.ready = true
	poll := f.invocation("get_query_result")
	poll.input = ContextQueryInput{QueryID: id}
	d, err := f.s.Results.GetQueryResult(t.Context(), f, poll, id)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(context.Background())
	if _, ok := d.PacketSummary(); !ok || d.Association().QueryID != id || f.polls != 1 || f.starts != 1 || f.admissions != 1 || f.reads != 1 {
		t.Fatal("pending poll changed paid original query/worker")
	}
}
