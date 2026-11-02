package presentation

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// The ADR-282 get_http_headers query composes the real C-18 coordinator with
// the synthetic bridge ports: these establish C-20 ordering, wire shape and
// audit classification only, never SQL, worker or native authority.

var headerDigest = artifact.Digest{9, 8, 7}

// httpBridge turns the bridge fixture into a published httpHeaders extract
// read with window w, composed with get_http_headers.
func httpBridge(t *testing.T, w value.HTTPHeaderWindow) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, *projectionAuditTarget) {
	t.Helper()
	s, f, g, p := bridgeAuditFixture(t)
	f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion = artifact.HTTPHeadersArtifact, artifact.HTTPHeadersFormat, value.HTTPHeadersDisplayVersion
	f.a.Scope.SourceProjectionDigest, f.a.Scope.Selection, f.a.Scope.Headers = artifact.Digest{}, value.LineSelection{}, w
	if !f.a.Valid(f.now) {
		t.Fatal("invalid extract fixture")
	}
	f.s.HeaderRoutes = f
	headers, ok := f.s.HTTPHeaders()
	if !ok {
		t.Fatal("http headers not composed")
	}
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		p.adapter, err = adapter.WithHTTPHeaders(headers)
	}
	if err != nil {
		t.Fatal(err)
	}
	return s, f, g, p
}

func headerRecords(n int, value string) []value.HTTPHeaderRecord {
	out := make([]analysisRecord, 0, n)
	at := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	for i := range n {
		out = append(out, analysisRecord{Timestamp: at.Add(time.Duration(i) * time.Millisecond), Method: "GET", Status: 200,
			Headers: []fieldValue{{Name: "content-type", Value: value}}})
	}
	return out
}

type (
	analysisRecord = value.HTTPHeaderRecord
	fieldValue     = value.HTTPHeaderField
)

func headerInput(cursor string, limit int) []byte {
	b, _ := json.Marshal(HTTPHeaderOperationInput{CaseID: bridgeID, ArtifactID: bridgeID, Cursor: cursor, Limit: limit})
	return b
}

type headerPageBody struct {
	Status     string  `json:"status"`
	DataClass  string  `json:"data_class"`
	NextCursor *string `json:"next_cursor"`
	Provenance []struct {
		ArtifactID string `json:"artifactID"`
	} `json:"provenance"`
	Data struct {
		Records []struct {
			Status  int `json:"status"`
			Headers []struct {
				Value string `json:"value"`
			} `json:"headers"`
		} `json:"records"`
		Code string `json:"code"`
	} `json:"data"`
}

func TestHTTPHeaderQueryBeginsPendingAndServesPageByPoll(t *testing.T) {
	s, f, g, p := httpBridge(t, value.HTTPHeaderWindow{Limit: 100})
	f.ready = false
	first, err := s.Call(context.Background(), f, "get_http_headers", headerInput("", 0))
	if err != nil {
		t.Fatal(err)
	}
	var pending struct {
		Status string `json:"status"`
		Data   map[string]any
	}
	if json.Unmarshal(first.Body, &pending) != nil || pending.Status != "pending" || s.contracts.ValidateOutput("get_http_headers", first.Body) != nil ||
		len(pending.Data) != 2 || pending.Data["query_handle"] != f.q.ID {
		t.Fatalf("not the canonical pending reply: %s", first.Body)
	}
	if f.admissions != 1 || f.starts != 1 || f.reads != 0 || g.intents[0].InputFormat != "context-query-input/v1" || g.outcomes[0].Effect != "accepted" {
		t.Fatal("begin did not admit one audited query")
	}
	if f.q.Scope.BeginTool() != "get_http_headers" || f.q.Scope.Headers != (value.HTTPHeaderWindow{Limit: 100}) {
		t.Fatal("query does not bind the record window")
	}
	_ = first.Close(context.Background())
	f.ready = true
	f.result = &value.ProjectionResult{Headers: value.HTTPHeaderPage{ProjectionDigest: headerDigest, Total: 150, Records: headerRecords(100, "text/plain"),
		DroppedFlows: 2, CoverageGaps: []string{"frame losses"}}}
	second, err := s.Call(context.Background(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	if s.contracts.ValidateOutput("get_query_result", second.Body) != nil || p.last.delivery == nil || p.last.delivery.Tool() != "get_http_headers" {
		t.Fatal("invalid nested page")
	}
	var poll struct {
		DataClass string `json:"data_class"`
		Data      struct {
			ToolName string          `json:"tool_name"`
			Result   json.RawMessage `json:"result"`
		} `json:"data"`
	}
	var page headerPageBody
	if json.Unmarshal(second.Body, &poll) != nil || poll.DataClass != "extract" || poll.Data.ToolName != "get_http_headers" || json.Unmarshal(poll.Data.Result, &page) != nil {
		t.Fatalf("wrong poll: %s", second.Body)
	}
	if page.Status != "ok" || page.DataClass != "extract" || len(page.Data.Records) != 100 || page.NextCursor == nil ||
		*page.NextCursor != value.HTTPHeaderCursor(100, headerDigest) || len(page.Provenance) != 1 || page.Provenance[0].ArtifactID != bridgeID {
		t.Fatalf("wrong page: %s", poll.Data.Result)
	}
	if f.reads != 1 || g.outcomes[1].Effect != "accepted" || g.outcomes[1].Status != "success" {
		t.Fatal("page not charged and audited as a read")
	}
}

// The worker may deliver a shorter prefix; the response trims further to
// its 24 KiB limit and the cursor continues at the first omitted record.
func TestHTTPHeaderPageTrimsToResponseLimitWithoutSkipping(t *testing.T) {
	w := value.HTTPHeaderWindow{Start: 10, Limit: 100, Binding: strings.Split(value.HTTPHeaderCursor(10, headerDigest), ":")[1]}
	s, f, _, _ := httpBridge(t, w)
	f.ready = false
	first, err := s.Call(context.Background(), f, "get_http_headers", headerInput(value.HTTPHeaderCursor(10, headerDigest), 0))
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close(context.Background())
	f.ready = true
	long := strings.Repeat("a", 400)
	f.result = &value.ProjectionResult{Headers: value.HTTPHeaderPage{ProjectionDigest: headerDigest, Start: 10, Total: 500, Records: headerRecords(90, "text/"+long)}}
	reply, err := s.Call(context.Background(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close(context.Background())
	var poll struct {
		Data struct {
			Result headerPageBody `json:"result"`
		} `json:"data"`
	}
	if len(reply.Body) > 24<<10 || json.Unmarshal(reply.Body, &poll) != nil {
		t.Fatal("response exceeds its limit")
	}
	n := len(poll.Data.Result.Data.Records)
	if n < 1 || n >= 90 || poll.Data.Result.NextCursor == nil || *poll.Data.Result.NextCursor != value.HTTPHeaderCursor(10+n, headerDigest) {
		t.Fatalf("trimmed page skipped records: %d %v", n, poll.Data.Result.NextCursor)
	}
}

func TestHTTPHeaderCursorRefusals(t *testing.T) {
	t.Run("malformed-before-lookup", func(t *testing.T) {
		s, f, g, _ := httpBridge(t, value.HTTPHeaderWindow{Limit: 100})
		reply, err := s.Call(context.Background(), f, "get_http_headers", headerInput("1:zz", 0))
		var body headerPageBody
		if err != nil || json.Unmarshal(reply.Body, &body) != nil || body.Status != "error" || body.Data.Code != "InvalidCursor" ||
			f.admissions != 0 || g.outcomes[0].Effect != "none" || g.outcomes[0].Status != "invalid" {
			t.Fatalf("malformed cursor: %v %s", err, reply.Body)
		}
	})
	t.Run("worker-judged", func(t *testing.T) {
		w := value.HTTPHeaderWindow{Start: 3, Limit: 5, Binding: strings.Repeat("0", 32)}
		s, f, g, _ := httpBridge(t, w)
		f.ready = false
		first, err := s.Call(context.Background(), f, "get_http_headers", headerInput("3:"+w.Binding, 5))
		if err != nil {
			t.Fatal(err)
		}
		_ = first.Close(context.Background())
		f.ready = true
		f.result = &value.ProjectionResult{InvalidCursor: true}
		reply, err := s.Call(context.Background(), f, "get_query_result", bridgePoll(f.q.ID))
		var body headerPageBody
		if err != nil || json.Unmarshal(reply.Body, &body) != nil || body.Status != "error" || body.Data.Code != "InvalidCursor" ||
			s.contracts.ValidateOutput("get_query_result", reply.Body) != nil || f.reads != 1 || g.outcomes[1].Effect != "accepted" || g.outcomes[1].Status != "invalid" {
			t.Fatalf("worker cursor refusal: %v %s %+v", err, reply.Body, g.outcomes)
		}
	})
}

func TestHTTPHeaderQueryIsAdvertisedOnlyWhenComposed(t *testing.T) {
	s, _, _ := auditedFixture(t)
	base := s.inner.(*InvestigationOperations)
	f := newBridgeFixture(t)
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := NewInvestigationProjectionOperations(base, adapter)
	if err != nil || slices.Contains(plain.ToolNames(), "get_http_headers") {
		t.Fatal("advertised without composition", err)
	}
	if _, ok := plain.Tool("get_http_headers"); ok {
		t.Fatal("uncomposed tool routed")
	}
	f.s.HeaderRoutes = f
	headers, _ := f.s.HTTPHeaders()
	composed, err := adapter.WithHTTPHeaders(headers)
	if err != nil {
		t.Fatal(err)
	}
	with, err := NewInvestigationProjectionOperations(base, composed)
	if err != nil || !slices.Contains(with.ToolNames(), "get_http_headers") {
		t.Fatal("not advertised when composed", err)
	}
	if _, ok := with.Tool("get_http_headers"); !ok || !BrowserOperationSupported(with, "get_http_headers") {
		t.Fatal("tool missing")
	}
	var _ HTTPHeaderQueryService = analysisapp.HTTPHeaderReads{}
}
