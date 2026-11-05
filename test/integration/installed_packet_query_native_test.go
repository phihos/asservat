package integration

import (
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"encoding/json"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"strings"
	"testing"
	"time"
)

type installedPacketQuerySource struct {
	CaseID, ArtifactID, Version, PodUID, GrantID string
	Expires                                      time.Time
	CaptureMode                                  string
}

func packetQueryCaptureMode(source installedPacketQuerySource) string {
	if source.CaptureMode == "" {
		return "rawPackets"
	}
	return source.CaptureMode
}
func installedPacketQueryRequest(source installedPacketQuerySource, key string) map[string]any {
	selection := installedPacketQuerySelection(packetQueryCaptureMode(source))
	fields := make([]string, len(selection.Fields))
	for i, f := range selection.Fields {
		fields[i] = string(f)
	}
	request := map[string]any{"case_id": source.CaseID, "artifact_id": source.ArtifactID, "idempotency_key": key, "packet_filter": "tcp port 8080", "fields": fields, "max_packets": 20, "max_scan_bytes": artifact.RecordingNativeLimit}
	if packetQueryCaptureMode(source) == "rawPackets" {
		request["grant_id"] = source.GrantID
		request["frame_prefix"] = map[string]int{"offset": 0, "length": 64}
	}
	return request
}
func installedPacketQuerySelection(mode ...string) query.PacketQuerySelection {
	s := query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex, query.PacketTime, query.PacketCapturedLength, query.PacketWireLength, query.PacketSourceAddress, query.PacketDestinationAddress, query.PacketSourcePort, query.PacketDestinationPort, query.PacketProtocol, query.PacketTCPFlags, query.PacketTCPSeq, query.PacketTCPAck, query.PacketTCPWindow, query.PacketICMPType, query.PacketICMPCode, query.PacketFramePrefixHex}, MaxPackets: 20, MaxScanBytes: artifact.RecordingNativeLimit, FramePrefix: &query.PacketQueryFramePrefix{Offset: 0, Length: 64}}
	if len(mode) == 1 && mode[0] == "networkHeaders" {
		s.Fields = s.Fields[:len(s.Fields)-1]
		s.FramePrefix = nil
	}
	return s
}
func queryInstalledPacketQuery(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin string, source installedPacketQuerySource, check installedProjectionCheck) query.PacketQueryResult {
	t.Helper()
	if check == nil {
		t.Fatal("packet query requires independent SQL proof")
	}
	verify := check(source.ArtifactID)
	token := identity.packetQueryTokenSource(origin)
	if _, err := token.Token(ctx); err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-packet-query", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, token.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	call := func(name string, args any) installedComparisonReply {
		t.Helper()
		started := time.Now()
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal("packet query outcome unavailable; no replay", name, err)
		}
		raw, err := json.Marshal(result.StructuredContent)
		var out installedComparisonReply
		if err != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
			t.Fatal("canonical packet query response", name)
		}
		t.Logf("installed packet query %s status=%s elapsed=%s", name, out.Status, time.Since(started))
		return out
	}
	denied := call("prepare_artifact_download", map[string]string{"artifact_id": source.ArtifactID, "idempotency_key": "raw-query-no-native"})
	if denied.Status != "error" {
		t.Fatal("read+raw session obtained native preparation")
	}
	verify("", "")
	return queryInstalledPacketQueryWithCall(t, ctx, source, installedPacketQueryRequest(source, "installed-packet-query-mcp-"+source.ArtifactID), call, verify, true)
}

// Same-key Begin replay is exercised only by the MCP caller. Browser mode
// starts one real React query; it does not fabricate an extra UI invocation.
func queryInstalledPacketQueryWithCall(t *testing.T, ctx context.Context, source installedPacketQuerySource, request map[string]any, call func(string, any) installedComparisonReply, verify func(string, string) func(), replayBegin ...bool) query.PacketQueryResult {
	t.Helper()
	result := call("pcap_query", request)
	operation, handle := result.RequestID, ""
	var observed, until time.Time
	directReady := result.Status == "ok"
	var directObserved time.Time
	if result.Status != "ok" && result.Status != "pending" {
		t.Fatal("initial packet query unavailable; no effect replay", result.Status)
	}
	if len(replayBegin) > 0 && replayBegin[0] {
		var first struct {
			Handle   string    `json:"query_handle"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if json.Unmarshal(result.Data, &first) != nil || first.Observed.IsZero() || !first.Expires.After(first.Observed) {
			t.Fatal("initial query replay association")
		}
		replay := call("pcap_query", request)
		var again struct {
			Handle   string    `json:"query_handle"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if replay.Status != "pending" || json.Unmarshal(replay.Data, &again) != nil || again.Handle == "" || !again.Expires.Equal(first.Expires) || first.Handle != "" && again.Handle != first.Handle || again.Observed.IsZero() || !again.Expires.After(again.Observed) {
			t.Fatal("same-key Begin disclosed/read or changed original query")
		}
		if directReady {
			handle, observed, until = again.Handle, first.Observed, first.Expires
			directObserved = first.Observed
		}
		t.Log("installed packet query same-key Begin: original pending handle/deadline, no page disclosure; exact query/batch/use counts checked in SQL")
	}
	for poll := 0; result.Status == "pending"; poll++ {
		var p struct {
			Handle   string    `json:"query_handle"`
			Retry    int       `json:"retry_after_seconds"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if json.Unmarshal(result.Data, &p) != nil || p.Handle == "" || p.Retry < 1 || p.Observed.IsZero() || !p.Expires.After(p.Observed) || p.Expires.After(source.Expires) {
			t.Fatal("invalid pending packet query")
		}
		if poll == 0 {
			handle, observed, until = p.Handle, p.Observed, p.Expires
		}
		if p.Handle != handle || !p.Expires.Equal(until) || poll >= 4 {
			t.Fatal("packet query changed original handle/deadline or exhausted polls")
		}
		next, err := installedProjectionPollTime(observed, until, time.Now(), time.Duration(p.Retry)*time.Second, poll)
		if err != nil {
			t.Fatal(err)
		}
		if installedJourneyPause(ctx, time.Until(next)) != nil {
			t.Fatal(ctx.Err())
		}
		result = call("get_query_result", map[string]string{"query_handle": handle})
	}
	if result.Status != "ok" {
		t.Fatal("packet query unavailable", result.Status)
	}
	outerObserved := directObserved
	if handle != "" && !directReady {
		var nested struct {
			Handle   string                   `json:"query_handle"`
			Tool     string                   `json:"tool_name"`
			Result   installedComparisonReply `json:"result"`
			Observed time.Time                `json:"query_observed_at"`
			Expires  time.Time                `json:"query_expires_at"`
		}
		if json.Unmarshal(result.Data, &nested) != nil || nested.Handle != handle || nested.Tool != "pcap_query" || nested.Result.RequestID != result.RequestID || !nested.Expires.Equal(until) {
			t.Fatal("packet query changed poll association")
		}
		outerObserved = nested.Observed
		result = nested.Result
	}
	expectedMode := packetQueryCaptureMode(source)
	expectedClass, nativeType := "raw", artifact.RawPCAPNGArtifact
	if expectedMode == "networkHeaders" {
		expectedClass, nativeType = "extract", artifact.PCAPNGArtifact
	}
	if result.Status != "ok" || result.DataClass != expectedClass || len(result.Provenance) != 1 || result.Provenance[0].ArtifactID != source.ArtifactID || result.Provenance[0].Digest != source.Version {
		t.Fatal("packet query changed raw source/version")
	}
	var page struct {
		contracts.PacketQueryPage
		Observed time.Time `json:"query_observed_at"`
		Expires  time.Time `json:"query_expires_at"`
	}
	if json.Unmarshal(result.Data, &page) != nil || page.Observed.IsZero() || !page.Expires.After(page.Observed) || page.Expires.After(source.Expires) || !until.IsZero() && (!page.Expires.Equal(until) || !page.Observed.Equal(outerObserved)) {
		t.Fatal("packet query lost current observation/original expiry")
	}
	out := query.PacketQueryResult{CaptureMode: page.CaptureMode, ScannedBytes: page.ScannedBytes, ScannedPackets: page.ScannedPackets, RowLimitReached: page.RowLimitReached, ScanLimitReached: page.ScanLimitReached, OutputLimitReached: page.OutputLimitReached, Fields: make([]query.PacketQueryField, len(page.Fields)), Rows: make([][]query.PacketQueryCell, len(page.Rows))}
	for i, f := range page.Fields {
		out.Fields[i] = query.PacketQueryField(f)
	}
	for i, row := range page.Rows {
		out.Rows[i] = make([]query.PacketQueryCell, len(row))
		for j, c := range row {
			out.Rows[i][j] = query.PacketQueryCell{Text: c.Text, Number: c.Number}
		}
	}
	if out.CaptureMode != expectedMode || !out.Valid(installedPacketQuerySelection(expectedMode), nativeType) || len(out.Rows) == 0 {
		t.Fatal("packet query primitive selection invalid/empty")
	}
	if verify(handle, operation) == nil {
		t.Fatal("packet query missing joined SQL proof")
	}
	return out
}

// Only the installed raw four-query journey uses this two-slot FIFO. These
// callbacks inspect already admitted originals; they never stop a Job, release
// a charge, extend a deadline, or issue another query.
type installedPacketTerminalPipeline struct {
	pending          []func()
	admitted, joined int
	limit            int // zero retains the original four-query packet fixture; arguments funds seven.
}

func (p *installedPacketTerminalPipeline) add(t *testing.T, wait func()) {
	t.Helper()
	maximum := p.limit
	if maximum == 0 {
		maximum = 4
	}
	if maximum != 4 && maximum != 7 || wait == nil || len(p.pending) >= 2 || p.admitted >= maximum {
		t.Fatal("raw fixture exceeded two original query workers or its originally funded query count")
	}
	p.pending = append(p.pending, wait)
	p.admitted++
}
func (p *installedPacketTerminalPipeline) drain(t *testing.T) {
	t.Helper()
	if len(p.pending) == 0 {
		t.Fatal("missing original raw-query terminal proof")
	}
	wait := p.pending[0]
	p.pending = p.pending[1:]
	wait()
	p.joined++
}
func (p *installedPacketTerminalPipeline) finish(t *testing.T) {
	t.Helper()
	pending := p.pending
	p.pending = nil
	// Preserve all known joins even if one assertion Goexits.
	for i := len(pending) - 1; i >= 0; i-- {
		defer func(wait func()) { wait(); p.joined++ }(pending[i])
	}
}
