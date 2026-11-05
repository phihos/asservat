package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testPacketSelection() PacketQuerySelection {
	return PacketQuerySelection{Fields: []PacketQueryField{PacketIndex, PacketTCPAck}, MaxPackets: 100, MaxScanBytes: 1 << 20}
}
func TestPacketQueryClosedSelectionAndLegacyScopeBytes(t *testing.T) {
	s := testPacketSelection()
	w, e := s.Window()
	if e != nil || !w.Valid() || !w.Selection().Valid() {
		t.Fatal(e)
	}
	w.Fields[31] = PacketIndex
	if w.Valid() {
		t.Fatal("unused arraydata allowed")
	}
	for _, mutate := range []func(*PacketQuerySelection){func(s *PacketQuerySelection) { s.Fields = append(s.Fields, PacketIndex) }, func(s *PacketQuerySelection) { s.TCPFlags = &PacketQueryTCPFlags{Mask: 1, Value: 2} }, func(s *PacketQuerySelection) {
		s.Fields = []PacketQueryField{PacketFramePrefixHex}
		s.FramePrefix = &PacketQueryFramePrefix{1499, 2}
	}} {
		bad := testPacketSelection()
		mutate(&bad)
		if bad.Valid() {
			t.Fatal("invalid selection", bad)
		}
	}
	b, _ := json.Marshal(sourceTestScope())
	for _, k := range []string{"PacketQuery", "RawGrantID", "Grant", "InvocationKey"} {
		if strings.Contains(string(b), k) {
			t.Fatal("legacy scope encoding changed", string(b))
		}
	}
}
func TestPacketQueryZeroNullAndCopiedOwnership(t *testing.T) {
	s := testPacketSelection()
	zero := uint32(0)
	idx := uint32(1)
	r := PacketQueryResult{CaptureMode: "rawPackets", Fields: s.Fields, Rows: [][]PacketQueryCell{{{Number: &idx}, {Number: &zero}}}, ScannedBytes: 10, ScannedPackets: 1}
	if !r.Valid(s, artifact.RawPCAPNGArtifact) {
		t.Fatal("numeric zero lost")
	}
	copy := ClonePacketQueryResult(r)
	*copy.Rows[0][1].Number = 9
	if *r.Rows[0][1].Number != 0 {
		t.Fatal("borrowed number")
	}
	r.Rows[0][1] = PacketQueryCell{}
	if !r.Valid(s, artifact.RawPCAPNGArtifact) {
		t.Fatal("missing ack notnullable")
	}
	r.Rows[0][0] = PacketQueryCell{}
	if r.Valid(s, artifact.RawPCAPNGArtifact) {
		t.Fatal("missing ordinal accepted")
	}
}
func TestPacketQueryGrantAndInvocationRemainPinned(t *testing.T) {
	a := testAuthority()
	a.Scope.NativeType = artifact.RawPCAPNGArtifact
	a.Scope.SourceFormat = artifact.RawPCAPNGFormat
	a.Scope.DisplayVersion = PacketQueryDisplayVersion
	a.Scope.SourceProjectionDigest = artifact.Digest{}
	a.Scope.Selection = LineSelection{}
	a.Scope.RawGrantID = "10000000-0000-4000-8000-000000000001"
	a.Scope.PacketQuery, _ = testPacketSelection().Window()
	a.Grant = ContextQueryGrant{a.Scope.RawGrantID, "10000000-0000-4000-8000-000000000002"}
	p := queryPlan(a)
	p.Profile.Worker.MemoryBytes = PacketQueryWorkerBytes
	p.Profile.Worker.WorkerTransientBytes = PacketQueryWorkerBytes
	k := ContextQueryInvocationKey{"query-key", artifact.Digest{1}}
	q, e := NewContextQuery("10000000-0000-4000-8000-000000000003", "10000000-0000-4000-8000-000000000004", "10000000-0000-4000-8000-000000000005", a, p, a.CheckedAt, k)
	if e != nil || !q.Current(a, a.CheckedAt) || q.Scope.ReadBatches() != 2 || q.Scope.QueryUnits() != 4 {
		t.Fatal("valid query", e)
	}
	changed := a
	changed.Grant.ChildID = "10000000-0000-4000-8000-000000000006"
	if q.Current(changed, a.CheckedAt) {
		t.Fatal("changed child selected")
	}
	q.InvocationKey = ContextQueryInvocationKey{}
	if q.Valid() {
		t.Fatal("unkeyed query")
	}
}

func TestPacketQueryAuditedCallIsRecognized(t *testing.T) {
	a := testAuthority()
	call := ContextQueryCall{ID: queryTestID, RootID: a.Scope.RootID, Tool: "pcap_query", InputFormat: "context-query-input/v1", MACVersion: "v1", InputDigest: artifact.Digest{1}, PrincipalDigest: artifact.Digest{2}, Principal: a.Scope.Principal, StartedAt: a.CheckedAt, Until: a.ValidUntil, WriteUntil: a.CheckedAt.Add(30 * time.Second)}
	if !call.Valid(a.CheckedAt) {
		t.Fatal("pcap query failed before authority/admission")
	}
	call.Tool = "arbitrary-packet-eval"
	if call.Valid(a.CheckedAt) {
		t.Fatal("unknown query call allowed")
	}
}

func TestPacketQueryMissingGrantCanOnlyDiscoverProtectedSource(t *testing.T) {
	s := packetProjectionScope()
	s.NativeType = artifact.RawPCAPNGArtifact
	s.SourceFormat = artifact.RawPCAPNGFormat
	s.DisplayVersion = PacketQueryDisplayVersion
	s.PacketQuery, _ = testPacketSelection().Window()
	if !s.Candidate().Valid() || !s.PreGrantValid() || s.Valid() {
		t.Fatal("pregrant source treated as authority or undiscoverable")
	}
	a := testAuthority()
	a.Scope = s
	if a.Valid(a.CheckedAt) {
		t.Fatal("missinggrant authority accepted")
	}
	bad := s
	bad.Version = artifact.Digest{}
	if bad.PreGrantValid() {
		t.Fatal("unversioned source discovered")
	}
	s.RawGrantID = "10000000-0000-4000-8000-000000000001"
	if s.PreGrantValid() || !s.Valid() {
		t.Fatal("complete scope/grant boundary")
	}
	s.RawGrantID = "not-a-grant"
	if s.Valid() || s.PreGrantValid() || s.Candidate().Valid() {
		t.Fatal("malformed parent accepted")
	}
}
