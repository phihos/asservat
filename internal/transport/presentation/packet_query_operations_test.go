package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type packetBridgeCompiler struct{}

func (packetBridgeCompiler) CompilePacketQueryFilter(context.Context, string) (value.PacketQueryProgram, error) {
	return value.PacketQueryProgram{}, nil
}

type packetBridgePort struct {
	*bridgeFixture
	calls map[string]value.ContextQueryRequest
}

func newPacketBridgePort(f *bridgeFixture) packetBridgePort {
	return packetBridgePort{bridgeFixture: f, calls: make(map[string]value.ContextQueryRequest)}
}
func (p packetBridgePort) AdmitQuery(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) (analysisapp.ContextQueryAdmission, error) {
	out, err := p.bridgeFixture.AdmitQuery(ctx, q, r, a)
	if err == nil {
		p.calls[r.Call.ID] = r
	}
	return out, err
}
func (p packetBridgePort) AdmitQueryPoll(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) error {
	if err := p.bridgeFixture.AdmitQueryPoll(ctx, q, r, a); err != nil {
		return err
	}
	p.calls[r.Call.ID] = r
	return nil
}
func (p packetBridgePort) RegisterQueryReplayCall(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) error {
	_, ok := p.calls[q.OperationID]
	if !ok || !q.InvocationKey.Valid() || !reflect.DeepEqual(q, p.q) || r.Call.ID == q.OperationID || r.Call.Tool != q.Scope.BeginTool() || r.Call.Principal != q.Scope.Principal {
		return value.ErrUnavailable
	}
	if old, exists := p.calls[r.Call.ID]; exists && !reflect.DeepEqual(old, r) {
		return value.ErrUnavailable
	}
	p.calls[r.Call.ID] = r
	return p.bridgeFixture.PermitQuery(ctx, q, r, a)
}
func (p packetBridgePort) PermitQuery(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) error {
	old, ok := p.calls[r.Call.ID]
	if !ok || !reflect.DeepEqual(old, r) {
		return value.ErrUnavailable
	}
	return p.bridgeFixture.PermitQuery(ctx, q, r, a)
}

func (f packetBridgePort) ResolvePacketProjectionRoute(context.Context, string, string, identity.Identity) (value.ContextProjectionCandidate, error) {
	return f.a.Scope.Candidate(), nil
}
func (f packetBridgePort) LookupQueryInvocation(_ context.Context, _ identity.Principal, key string, digest artifact.Digest) (value.ContextQuery, bool, error) {
	if f.q.ID == "" {
		return value.ContextQuery{}, false, nil
	}
	if f.q.InvocationKey.Key != key || f.q.InvocationKey.RequestDigest != digest {
		return value.ContextQuery{}, false, value.ErrQueryConflict
	}
	return f.q, true, nil
}
func TestPacketQueryActualAuditedBeginReplayAndReadyEnvelope(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "raw"}[raw], func(t *testing.T) {
			s, f, g, p := bridgeAuditFixture(t)
			f.ready = false
			r := value.PacketQueryRequest{CaseID: bridgeID, ArtifactID: bridgeID, IdempotencyKey: "originalpacketkey", Fields: []value.PacketQueryField{value.PacketIndex, value.PacketTCPAck}, MaxPackets: 1, MaxScanBytes: value.PacketQueryMaxScanBytes}
			f.a.Scope.NativeType = artifact.PCAPNGArtifact
			f.a.Scope.SourceFormat = artifact.PCAPNGFormat
			mode := "networkHeaders"
			class := "extract"
			if raw {
				mode = "rawPackets"
				class = "raw"
				f.a.Scope.NativeType = artifact.RawPCAPNGArtifact
				f.a.Scope.SourceFormat = artifact.RawPCAPNGFormat
				r.GrantID = f.next()
				f.a.Scope.RawGrantID = r.GrantID
				f.a.Grant = value.ContextQueryGrant{ParentID: r.GrantID, ArtifactRef: f.next()}
			}
			f.a.Scope.DisplayVersion = value.PacketQueryDisplayVersion
			f.a.Scope.SourceProjectionDigest = artifact.Digest{}
			f.a.Scope.Selection = value.LineSelection{}
			f.a.Scope.PacketQuery, _ = r.Selection(value.PacketQueryProgram{}).Window()
			f.p.Profile.Worker.MemoryBytes = value.PacketQueryWorkerBytes
			f.p.Profile.Worker.WorkerTransientBytes = value.PacketQueryWorkerBytes
			port := newPacketBridgePort(f)
			f.s.Results.Ledger = port
			f.s.PacketRoutes = port
			f.s.PacketCompiler = packetBridgeCompiler{}
			reads, _ := f.s.PacketQueries()
			adapter, e := NewContextProjectionOperations(f.s, f.s.Results)
			if e == nil {
				p.adapter, e = adapter.WithPacketQueries(reads)
			}
			if e != nil {
				t.Fatal(e)
			}
			input, _ := json.Marshal(packetQueryJSON(r))
			first, e := s.Call(t.Context(), f, "query_artifact", input)
			if e != nil {
				t.Fatalf("begin %v %#v", e, e)
			}
			if e = first.Close(context.Background()); e != nil {
				t.Fatal(e)
			}
			repeat, e := s.Call(t.Context(), f, "query_artifact", input)
			if e != nil {
				t.Fatalf("replay %v %#v", e, e)
			}
			if e = repeat.Close(context.Background()); e != nil {
				t.Fatal(e)
			}
			if f.admissions != 1 || f.starts != 1 || f.reads != 0 || f.polls != 0 || len(g.events) != 2 || g.events[1].Effect != "none" {
				t.Fatal("replaynotpassive", f.admissions, f.starts, f.reads, g.events)
			}
			f.ready = true
			index, zero := uint32(1), uint32(0)
			f.result = &value.ProjectionResult{PacketQuery: &value.PacketQueryResult{CaptureMode: mode, Fields: r.Fields, Rows: [][]value.PacketQueryCell{{{Number: &index}, {Number: &zero}}}, ScannedBytes: 100, ScannedPackets: 1, RowLimitReached: true}}
			ready, e := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
			if e != nil {
				t.Fatalf("ready %v %#v", e, e)
			}
			defer ready.Close(context.Background())
			var out struct {
				DataClass string `json:"data_class"`
				Truncated bool   `json:"truncated"`
				Data      struct {
					Tool   string `json:"tool_name"`
					Result struct {
						DataClass string `json:"data_class"`
						Truncated bool   `json:"truncated"`
						Data      struct {
							CaptureMode string  `json:"capture_mode"`
							Rows        [][]any `json:"rows"`
						}
					} `json:"result"`
				} `json:"data"`
			}
			if json.Unmarshal(ready.Body, &out) != nil || out.DataClass != class || out.Truncated || out.Data.Tool != "query_artifact" || out.Data.Result.DataClass != class || !out.Data.Result.Truncated || out.Data.Result.Data.CaptureMode != mode || out.Data.Result.Data.Rows[0][1] != float64(0) {
				t.Fatalf("queryenvelope %s", ready.Body)
			}
		})
	}
}

type packetQueryUnavailable struct{}

func (packetQueryUnavailable) Begin(context.Context, identities.CurrentIdentity, string, value.PacketQueryRequest) (*analysisapp.ContextProjectionDelivery, error) {
	return nil, value.ErrUnavailable
}

type missingPacketApproval struct{}

func (missingPacketApproval) Error() string                     { return "approval required" }
func (missingPacketApproval) PacketQueryApprovalRequired() bool { return true }

type packetMissingAuthority struct{ *bridgeFixture }

func (f packetMissingAuthority) ResolveProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionCandidate) (value.ContextProjectionAuthority, error) {
	return value.ContextProjectionAuthority{}, missingPacketApproval{}
}
func TestPacketQueryMissingRawGrantIsActionableWithoutEffects(t *testing.T) {
	s, f, g, p := bridgeAuditFixture(t)
	r := value.PacketQueryRequest{CaseID: bridgeID, ArtifactID: bridgeID, IdempotencyKey: "missinggrant", Fields: []value.PacketQueryField{value.PacketIndex}, MaxPackets: 1, MaxScanBytes: value.PacketQueryMaxScanBytes}
	f.a.Scope.NativeType = artifact.RawPCAPNGArtifact
	f.a.Scope.SourceFormat = artifact.RawPCAPNGFormat
	f.a.Scope.DisplayVersion = value.PacketQueryDisplayVersion
	f.a.Scope.SourceProjectionDigest = artifact.Digest{}
	f.a.Scope.Selection = value.LineSelection{}
	f.a.Scope.PacketQuery, _ = r.Selection(value.PacketQueryProgram{}).Window()
	port := newPacketBridgePort(f)
	f.s.Results.Ledger = port
	f.s.Results.Authority = packetMissingAuthority{f}
	f.s.PacketRoutes = port
	f.s.PacketCompiler = packetBridgeCompiler{}
	reads, _ := f.s.PacketQueries()
	adapter, e := NewContextProjectionOperations(f.s, f.s.Results)
	if e == nil {
		p.adapter, e = adapter.WithPacketQueries(reads)
	}
	if e != nil {
		t.Fatal(e)
	}
	input, _ := json.Marshal(packetQueryJSON(r))
	reply, e := s.Call(t.Context(), f, "query_artifact", input)
	if e != nil {
		t.Fatalf("semanticapproval %v %#v", e, e)
	}
	defer reply.Close(context.Background())
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Code string `json:"code"`
			Role string `json:"responsible_role"`
		}
	}
	if json.Unmarshal(reply.Body, &out) != nil || out.Status != "error" || out.Data.Code != "RawApprovalRequired" || out.Data.Role != "approver" || f.admissions+f.starts+f.batches+f.reads != 0 || len(g.events) != 1 || g.events[0].Effect != "none" {
		t.Fatalf("approvalrefusal %s effects=%d", reply.Body, f.admissions+f.starts+f.batches+f.reads)
	}
}

// Full primitive rows are bounded before payment; both actual public wrappers
// must fit without trimming any admitted row after the read has been spent.
func TestPacketQueryMaximumAdmittedPageFitsDirectAndNestedEnvelope(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "nested"}[nested], func(t *testing.T) {
			s, f, _, p := bridgeAuditFixture(t)
			fields := []value.PacketQueryField{value.PacketIndex, value.PacketTime, value.PacketCapturedLength, value.PacketWireLength, value.PacketSourceAddress, value.PacketDestinationAddress, value.PacketSourcePort, value.PacketDestinationPort, value.PacketProtocol, value.PacketTCPFlags, value.PacketTCPSeq, value.PacketTCPAck, value.PacketTCPWindow, value.PacketICMPType, value.PacketICMPCode, value.PacketFramePrefixHex}
			r := value.PacketQueryRequest{CaseID: bridgeID, ArtifactID: bridgeID, GrantID: f.next(), IdempotencyKey: "maxpage", Fields: fields, MaxPackets: 100, MaxScanBytes: value.PacketQueryMaxScanBytes, FramePrefix: &value.PacketQueryFramePrefix{Length: 64}}
			page := value.PacketQueryResult{CaptureMode: "rawPackets", Fields: fields, ScannedBytes: 150000, ScannedPackets: 100, OutputLimitReached: true}
			num := func(n uint32) value.PacketQueryCell { return value.PacketQueryCell{Number: &n} }
			text := func(s string) value.PacketQueryCell { return value.PacketQueryCell{Text: &s} }
			for n := uint32(1); n <= 100; n++ {
				row := []value.PacketQueryCell{num(n), text("2026-11-05T10:11:12.123456789Z"), num(1500), num(1500), text("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), text("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"), num(65535), num(65535), text("TCP"), num(511), num(4294967295), num(4294967295), num(65535), {}, {}, text(strings.Repeat("ff", 64))}
				page.Rows = append(page.Rows, row)
				if page.EncodedSize() > value.PacketQueryPageBytes {
					page.Rows = page.Rows[:len(page.Rows)-1]
					break
				}
			}
			selection := r.Selection(value.PacketQueryProgram{})
			if len(page.Rows) < 50 || !page.Valid(selection, artifact.RawPCAPNGArtifact) {
				t.Fatal("invalid max fixture", len(page.Rows), page.EncodedSize())
			}
			f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, value.PacketQueryDisplayVersion
			f.a.Scope.SourceProjectionDigest = artifact.Digest{}
			f.a.Scope.Selection = value.LineSelection{}
			f.a.Scope.RawGrantID = r.GrantID
			f.a.Scope.PacketQuery, _ = selection.Window()
			f.a.Grant = value.ContextQueryGrant{ParentID: r.GrantID, ArtifactRef: f.next()}
			f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.PacketQueryWorkerBytes, value.PacketQueryWorkerBytes
			admittedRows, admittedBytes := len(page.Rows), page.EncodedSize()
			f.result = &value.ProjectionResult{PacketQuery: &page}
			port := newPacketBridgePort(f)
			f.s.Results.Ledger = port
			f.s.PacketRoutes = port
			f.s.PacketCompiler = packetBridgeCompiler{}
			reads, _ := f.s.PacketQueries()
			adapter, e := NewContextProjectionOperations(f.s, f.s.Results)
			if e == nil {
				p.adapter, e = adapter.WithPacketQueries(reads)
			}
			if e != nil {
				t.Fatal(e)
			}
			input, _ := json.Marshal(packetQueryJSON(r))
			f.ready = !nested
			reply, e := s.Call(t.Context(), f, "query_artifact", input)
			if e != nil {
				t.Fatal("begin", e)
			}
			if nested {
				if e = reply.Close(context.Background()); e != nil {
					t.Fatal(e)
				}
				f.ready = true
				reply, e = s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
			}
			if e != nil {
				t.Fatalf("paid valid page failed: rows=%d primitive=%d: %v", admittedRows, admittedBytes, e)
			}
			defer reply.Close(context.Background())
			if len(reply.Body) > contracts.InvestigationOutputLimit || !bytes.Contains(reply.Body, []byte(`"output_limit_reached":true`)) {
				t.Fatal("shape", len(reply.Body))
			}

			name := "query_artifact"
			var envelope struct {
				Truncated bool    `json:"truncated"`
				Hint      *string `json:"narrowing_hint"`
				Data      struct {
					Result json.RawMessage `json:"result"`
				} `json:"data"`
			}
			if json.Unmarshal(reply.Body, &envelope) != nil {
				t.Fatal("envelope decode")
			}
			inner := reply.Body
			if nested {
				name = "get_query_result"
				if envelope.Truncated || envelope.Hint != nil {
					t.Fatal("outer query wrapper gained inner limit metadata")
				}
				inner = envelope.Data.Result
			}
			var limited struct {
				Truncated bool    `json:"truncated"`
				Hint      *string `json:"narrowing_hint"`
			}
			if json.Unmarshal(inner, &limited) != nil || !limited.Truncated || limited.Hint == nil || *limited.Hint == "" {
				t.Fatal("limited page lost narrowing hint")
			}
			validatePacketQueryCanonicalOutput(t, name, reply.Body)
			if nested {
				validatePacketQueryCanonicalOutput(t, "query_artifact", inner)
			}
			t.Logf("rows=%d primitive=%d envelope=%d nested=%v", admittedRows, admittedBytes, len(reply.Body), nested)
		})
	}
}

// Validate the actual audited body against the embedded canonical output.
func validatePacketQueryCanonicalOutput(t *testing.T, name string, body []byte) {
	t.Helper()
	wire, e := contracts.NewInvestigationContracts()
	if e != nil || wire.ValidateOutput(name, body) != nil {
		t.Fatalf("actual %s body violates canonical output: %s", name, wire.OutputViolation(name, body))
	}
}

// packetQueryJSON is the query_artifact packets input of r.
func packetQueryJSON(r value.PacketQueryRequest) projectionInput {
	in := projectionInput{Operation: "packets", CaseID: r.CaseID, ArtifactID: r.ArtifactID, GrantID: r.GrantID, IdempotencyKey: r.IdempotencyKey, PacketFilter: r.PacketFilter, Fields: r.Fields, StartTime: r.StartTime, EndTime: r.EndTime, Limit: r.MaxPackets}
	if r.TCPFlags != nil {
		in.TCPFlags = &packetQueryFlagInput{r.TCPFlags.Mask, r.TCPFlags.Value}
	}
	if r.FramePrefix != nil {
		in.FramePrefix = &packetQueryPrefixInput{r.FramePrefix.Offset, r.FramePrefix.Length}
	}
	return in
}
