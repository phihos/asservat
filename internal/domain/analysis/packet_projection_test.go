package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"testing"
)

func packetProjectionScope() ContextProjectionScope {
	s := sourceTestScope()
	s.NativeType = artifact.PCAPNGArtifact
	s.SourceFormat = artifact.PCAPNGFormat
	s.DisplayVersion = PacketSummaryDisplayVersion
	s.SourceProjectionDigest = artifact.Digest{}
	s.Selection = LineSelection{}
	return s
}
func TestPacketSummaryClosedPublishedSource(t *testing.T) {
	s := packetProjectionScope()
	src, ok := s.Source()
	if !ok || !s.Valid() || src.DataClass != "metadata" || src.EvidenceType != "packetCapture" || src.ReadOperation() != authorization.ReadApproved || src.OutputClass() != "extract" || s.BeginTool() != "get_pcap_summary" || s.ReadBatches() != 1 || s.QueryUnits() != 2 {
		t.Fatal("saved metadata packet summary not admitted as exact closed source")
	}
	for _, n := range []int64{1, artifact.RecordingNativeLimit} {
		if !src.Matches(artifact.PCAPNGArtifact, artifact.PCAPNGFormat, "metadata", "packetCapture", n, artifact.Digest{}) {
			t.Fatal("bounded saved packet input refused", n)
		}
	}
	for _, n := range []int64{0, -1, artifact.RecordingNativeLimit + 1} {
		if src.Matches(artifact.PCAPNGArtifact, artifact.PCAPNGFormat, "metadata", "packetCapture", n, artifact.Digest{}) {
			t.Fatal("invalid packet source size accepted", n)
		}
	}
	if src.Matches(artifact.PCAPNGArtifact, artifact.PCAPNGFormat, "raw", "packetCapture", 1, artifact.Digest{}) {
		t.Fatal("raw packet source became approved metadata query")
	}
	for _, change := range []func(*ContextProjectionScope){func(s *ContextProjectionScope) { s.Selection = LineSelection{1, 1} }, func(s *ContextProjectionScope) { s.Headers = HTTPHeaderWindow{Limit: 1} }, func(s *ContextProjectionScope) { s.Profile = ProfileSummarySelection{SampleType: "cpu", TopN: 20} }, func(s *ContextProjectionScope) { s.NativeType = artifact.RawPCAPNGArtifact }, func(s *ContextProjectionScope) { s.SourceProjectionDigest = artifact.Digest{1} }, func(s *ContextProjectionScope) { s.DisplayVersion = ProfileSummaryDisplayVersion }} {
		bad := s
		change(&bad)
		if bad.Valid() {
			t.Fatal("packet source accepted another selection/type/display")
		}
	}
}

func TestPacketSummaryResultIsExclusiveAndCleared(t *testing.T) {
	s := packetProjectionScope()
	summary := PacketSummary{CaptureMode: "networkHeaders", DropReporting: "unavailable", Conversations: []PacketConversation{}}
	r := ProjectionResult{PacketSummary: &summary}
	if !r.Valid(s) {
		t.Fatal("valid empty authenticated summary refused")
	}
	mixed := r
	mixed.Summary = &ProfileSummary{}
	if mixed.Valid(s) {
		t.Fatal("packet result accepted another source branch")
	}
	if r.Valid(sourceTestScope()) {
		t.Fatal("packet summary used as context excerpt")
	}
	r.Clear()
	if r.PacketSummary != nil || summary.Conversations != nil {
		t.Fatal("packet result retained after clear")
	}
}
func TestPacketSummaryRequiresPhysicalAndTransientBudget(t *testing.T) {
	a := testAuthority()
	a.Scope.NativeType = artifact.PCAPNGArtifact
	a.Scope.SourceFormat = artifact.PCAPNGFormat
	a.Scope.DisplayVersion = PacketSummaryDisplayVersion
	a.Scope.SourceProjectionDigest = artifact.Digest{}
	a.Scope.Selection = LineSelection{}
	p := queryPlan(a)
	if p.Matches(a.Scope) {
		t.Fatal("packet parser accepted old small physical/transient profile")
	}
	p.Profile.Worker.MemoryBytes = PacketSummaryWorkerBytes
	p.Profile.Worker.WorkerTransientBytes = PacketSummaryWorkerBytes
	if !p.Matches(a.Scope) {
		t.Fatal("declared packet worker rejected")
	}
	p.Profile.Worker.WorkerTransientBytes--
	if p.Matches(a.Scope) {
		t.Fatal("physical memory substituted for transient reservation")
	}
}

func TestRawPacketSummaryRequiresBothResourceReservations(t *testing.T) {
	a := testAuthority()
	a.Scope.NativeType=artifact.PCAPNGArtifact; a.Scope.SourceFormat=artifact.PCAPNGFormat;a.Scope.DisplayVersion=PacketSummaryDisplayVersion;a.Scope.SourceProjectionDigest=artifact.Digest{};a.Scope.Selection=LineSelection{}
	a.Scope.NativeType = artifact.RawPCAPNGArtifact
	a.Scope.SourceFormat = artifact.RawPCAPNGFormat
	a.Scope.DisplayVersion = RawPacketSummaryDisplayVersion
	p := queryPlan(a)
	p.Profile.Worker.MemoryBytes = PacketSummaryWorkerBytes
	p.Profile.Worker.WorkerTransientBytes = PacketSummaryWorkerBytes
	if !p.Matches(a.Scope) {
		t.Fatal("valid raw summary profile refused")
	}
	for _, physical := range []bool{true, false} {
		bad := p
		if physical {
			bad.Profile.Worker.MemoryBytes--
			bad.Profile.Worker.WorkerTransientBytes--
		} else {
			bad.Profile.Worker.WorkerTransientBytes--
		}
		if bad.Matches(a.Scope) {
			t.Fatal("raw summary accepted undersized reservation", physical)
		}
	}
}
