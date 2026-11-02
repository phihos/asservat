package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/client-go/rest"
)

// ADR-282 manual-http focus: the namespace CaptureProfile "http-capture" v1
// is the builtin network profile republished with an httpHeaders profile at
// the specified defaults (and maxima): 1024 flows, 32 KiB header block,
// 256 KiB per flow, 16 MiB total reassembly, 30 s idle timeout.
const (
	manualHTTPProfileName    = "http-capture"
	manualHTTPProfileVersion = "v1"
	// manualHTTPMarker is synthetic: the traffic sends it in the URL query and
	// a request Cookie, and the fixture workload returns it in Set-Cookie. No
	// byte of it may reach the projection.
	manualHTTPMarker = "synthetic-http-secret-5d2c91"
)

// manualHTTPLimits are the projector limits the profile below selects.
func manualHTTPLimits() httpheaders.Limits {
	return httpheaders.Limits{MaxFlows: 1024, MaxHeaderBytes: 32 << 10, MaxFlowBytes: 256 << 10, MaxTotalBytes: 16 << 20, IdleTimeout: 30 * time.Second}
}

// manualHTTPProfileDefinition copies the builtin network-connections v1
// definition with an httpHeaders profile and sensitiveRead impact.
func manualHTTPProfileDefinition() (map[string]any, error) {
	l := manualHTTPLimits()
	return builtinNetworkDefinitionWith(map[string]any{"kind": "httpHeaders", "protocol": "http1",
		"projectionRef": map[string]any{"name": "http-response-headers", "version": "v1"},
		"maxFlows":      l.MaxFlows, "maxHeaderBytes": l.MaxHeaderBytes,
		"maxReassemblyBytesPerFlow": l.MaxFlowBytes, "maxReassemblyBytes": l.MaxTotalBytes, "idleTimeout": "30s"})
}

// manualHTTPArguments is the public finite HTTP header request: one
// on-trigger action, no history, five seconds after start, a reviewed filter.
// Unlike raw output, the extract downloads under ordinary eligibility, so the
// request carries no result_access.
func manualHTTPArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "namespace", "name": manualHTTPProfileName, "version": manualHTTPProfileVersion},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": "onTrigger"},
					map[string]any{"actionID": "sample", "field": "packetBefore", "value": "0s"},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "5s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "15s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "15s",
		},
	}
}

// publishManualHTTPProfile is the workload team's step, as for manual-raw.
func publishManualHTTPProfile(t *testing.T, ctx context.Context, regionalConfig, namespace string) {
	t.Helper()
	definition, err := manualHTTPProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	publishNamespaceCaptureProfile(t, ctx, regionalConfig, namespace, manualHTTPProfileName, manualHTTPProfileVersion, definition)
}

// manualHTTPTraffic is one request of the focus's traffic loop: the fixture
// workload's /log?headers=1 answers with Connection: close (so every request
// opens a new connection whose SYN the finite recording can see, instead of
// reusing the API server's kept-alive proxy connection), a text body and a
// Set-Cookie carrying the marker. The request carries the marker in its
// query and a Cookie.
func manualHTTPTraffic(r *rest.Request) *rest.Request {
	return r.Param("line", manualHTTPMarker).Param("headers", "1").SetHeader("Cookie", "session="+manualHTTPMarker)
}

// manualHTTPExtension is the registered native filename extension.
func manualHTTPExtension(t *testing.T) string {
	t.Helper()
	native, ok := artifact.LookupNativeType(artifact.HTTPHeadersArtifact)
	if !ok || native.Extension == "" {
		t.Fatal("httpHeaders native type is not registered")
	}
	return native.Extension
}

// manualHTTPSummary is what the focus logs from the downloaded projection.
type manualHTTPSummary struct {
	Records, Answered int
	Counters          httpheaders.Counters
}

// checkManualHTTPProjection strictly decodes the downloaded projection,
// rechecks it with the publisher's independent check, and requires at least
// one GET record with a status, only content-type/content-length header
// names, and no byte of the synthetic marker or a credential header name.
func checkManualHTTPProjection(native []byte) (manualHTTPSummary, error) {
	var s manualHTTPSummary
	decoder := json.NewDecoder(bytes.NewReader(native))
	decoder.DisallowUnknownFields()
	var p httpheaders.Projection
	if err := decoder.Decode(&p); err != nil {
		return s, fmt.Errorf("projection does not decode strictly: %w", err)
	}
	s.Counters = p.Counters
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return s, errors.New("projection has trailing data")
	}
	l := manualHTTPLimits()
	want := httpheaders.LimitsRecord{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleTimeoutSeconds: int64(l.IdleTimeout / time.Second), Snaplen: httpheaders.Snaplen}
	if p.Format != artifact.HTTPHeadersFormat || p.Protocol != "http1" || p.Limits != want {
		return s, fmt.Errorf("projection format %q protocol %q limits %+v", p.Format, p.Protocol, p.Limits)
	}
	if _, err := httpheaders.CheckProjection(bytes.NewReader(native), l, artifact.HTTPHeadersNativeLimit); err != nil {
		return s, fmt.Errorf("independent projection check: %w", err)
	}
	for _, r := range p.Records {
		for _, h := range r.Headers {
			if h.Name != "content-type" && h.Name != "content-length" {
				return s, fmt.Errorf("unapproved header name %q", h.Name)
			}
		}
		if r.Method == "GET" && r.Status != 0 {
			s.Answered++
		}
	}
	lower := bytes.ToLower(native)
	for _, forbidden := range []string{manualHTTPMarker, "cookie", "authorization"} {
		if bytes.Contains(lower, []byte(forbidden)) {
			return s, fmt.Errorf("projection contains %q", forbidden)
		}
	}
	s.Records = len(p.Records)
	if s.Answered == 0 {
		return s, errors.New("no GET record with a status")
	}
	return s, nil
}

// qualifyManualHTTPProjection writes the native projection and checks it.
func qualifyManualHTTPProjection(t *testing.T, native []byte) manualHTTPSummary {
	t.Helper()
	if err := os.WriteFile("../results/manual-http.json", native, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := checkManualHTTPProjection(native)
	if err != nil {
		t.Fatalf("HTTP header projection: %v; counters %+v", err, s.Counters)
	}
	return s
}

// manualHTTPReply is one get_http_headers or get_query_result MCP reply.
type manualHTTPReply struct {
	RequestID  string          `json:"request_id"`
	Status     string          `json:"status"`
	NextCursor *string         `json:"next_cursor"`
	Data       json.RawMessage `json:"data"`
	Provenance []struct {
		ArtifactID string `json:"artifactID"`
	} `json:"provenance"`
}

// manualHTTPPage is the disclosed page data of get_http_headers.
type manualHTTPPage struct {
	ProjectionDigest string `json:"projection_digest"`
	Records          []struct {
		Timestamp time.Time `json:"timestamp"`
		Method    string    `json:"method"`
		Status    int       `json:"status"`
		Headers   []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
		Partial bool `json:"partial"`
	} `json:"records"`
	DroppedFlows    uint64   `json:"dropped_flows"`
	IncompleteFlows uint64   `json:"incomplete_flows"`
	CoverageGaps    []string `json:"coverage_gaps"`
	Code            string   `json:"code"`
}

// qualifyManualHTTPQuery reads the published extract through get_http_headers
// over MCP (ADR-282 slice 5): each page is an approved query answered pending
// and served by get_query_result. Every delivered record, counter, gap and the
// cursor binding must equal httpheaders.ReadPage on the downloaded native
// bytes; the record limit is chosen for about three pages, of which at most
// three are followed. A cursor with a foreign binding is InvalidCursor.
func qualifyManualHTTPQuery(t *testing.T, ctx context.Context, session *sdk.ClientSession, wire *contracts.InvestigationContracts, caseID, artifactID string, native []byte) {
	t.Helper()
	call := func(name string, args any) (manualHTTPReply, time.Duration) {
		t.Helper()
		started := time.Now()
		bounded, end := context.WithTimeout(ctx, 45*time.Second)
		defer end()
		result, err := session.CallTool(bounded, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil || result == nil {
			t.Fatal("get_http_headers MCP", name, err)
		}
		raw, err := json.Marshal(result.StructuredContent)
		var out manualHTTPReply
		if err != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
			t.Fatalf("%s reply violates its contract: %s", name, raw)
		}
		return out, time.Since(started)
	}
	// read admits one page query and polls it within the original query
	// lifetime; it returns the get_http_headers envelope of the page.
	read := func(cursor string, limit int) (manualHTTPReply, string) {
		t.Helper()
		args := map[string]any{"case_id": caseID, "artifact_id": artifactID, "limit": limit}
		if cursor != "" {
			args["cursor"] = cursor
		}
		started := time.Now()
		reply, begin := call("get_http_headers", args)
		if reply.Status != "pending" {
			if reply.Status == "ok" {
				return reply, fmt.Sprintf("begin=%dms immediate", begin.Milliseconds())
			}
			return reply, fmt.Sprintf("begin=%dms refused", begin.Milliseconds())
		}
		var pending struct {
			Handle string `json:"query_handle"`
			Retry  int    `json:"retry_after_seconds"`
		}
		if json.Unmarshal(reply.Data, &pending) != nil || pending.Handle == "" || pending.Retry < 1 {
			t.Fatal("invalid get_http_headers pending reply")
		}
		// The canonical pending reply carries no query times. The installed
		// profile's query lifetime is the 60 s maximum; spreading the poll
		// allowance over its first half leaves the deadline unreached.
		until := started.Add(query.ContextMaxQueryTime / 2)
		for poll := 0; ; poll++ {
			next, err := installedProjectionPollTime(started, until, time.Now(), time.Duration(pending.Retry)*time.Second, poll)
			if err != nil {
				t.Fatal("get_http_headers query did not become ready within its lifetime", err)
			}
			if installedJourneyPause(ctx, time.Until(next)) != nil {
				t.Fatal("get_http_headers poll canceled", ctx.Err())
			}
			result, took := call("get_query_result", map[string]string{"query_handle": pending.Handle})
			if result.Status == "pending" {
				continue
			}
			if result.Status != "ok" {
				return result, fmt.Sprintf("begin=%dms ready-after=%dms result=%dms", begin.Milliseconds(), time.Since(started).Milliseconds(), took.Milliseconds())
			}
			var resolved struct {
				Handle string          `json:"query_handle"`
				Tool   string          `json:"tool_name"`
				Result json.RawMessage `json:"result"`
			}
			var page manualHTTPReply
			if json.Unmarshal(result.Data, &resolved) != nil || resolved.Handle != pending.Handle || resolved.Tool != "get_http_headers" || json.Unmarshal(resolved.Result, &page) != nil {
				t.Fatal("get_query_result did not serve the original get_http_headers page")
			}
			return page, fmt.Sprintf("begin=%dms ready-after=%dms result=%dms polls=%d", begin.Milliseconds(), time.Since(started).Milliseconds(), took.Milliseconds(), poll+1)
		}
	}
	all, err := query.NormalizeHTTPHeaderSelection(caseID, artifactID, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := httpheaders.ReadPage(native, manualHTTPLimits(), artifact.RecordingNativeLimit, all)
	if err != nil || whole.Total < 1 {
		t.Fatal("downloaded projection has no readable record", err)
	}
	digest := sha256.Sum256(native)
	limit := min(max((whole.Total+2)/3, 1), query.HTTPHeaderPageRecords)
	cursor, delivered := "", 0
	for n := 0; n < 3; n++ {
		page, timing := read(cursor, limit)
		var data manualHTTPPage
		if page.Status != "ok" || json.Unmarshal(page.Data, &data) != nil || len(page.Provenance) != 1 || page.Provenance[0].ArtifactID != artifactID {
			t.Fatalf("page %d not disclosed: %s %s", n, page.Status, page.Data)
		}
		sel, err := query.NormalizeHTTPHeaderSelection(caseID, artifactID, cursor, limit)
		if err != nil {
			t.Fatal(err)
		}
		want, err := httpheaders.ReadPage(native, manualHTTPLimits(), artifact.RecordingNativeLimit, sel)
		if err != nil || data.ProjectionDigest != hex.EncodeToString(digest[:]) || data.ProjectionDigest != hex.EncodeToString(want.ProjectionDigest[:]) ||
			data.DroppedFlows != want.DroppedFlows || data.IncompleteFlows != want.IncompleteFlows || strings.Join(data.CoverageGaps, "\n") != strings.Join(want.CoverageGaps, "\n") {
			t.Fatalf("page %d digest or gap report differs from the native document", n)
		}
		if len(data.Records) < 1 || len(data.Records) > len(want.Records) {
			t.Fatalf("page %d is not a non-empty prefix of its selection: %d of %d", n, len(data.Records), len(want.Records))
		}
		for i, r := range data.Records {
			w := want.Records[i]
			same := r.Timestamp.Equal(w.Timestamp) && r.Method == w.Method && r.Status == w.Status && r.Partial == w.Partial && len(r.Headers) == len(w.Headers)
			for j := 0; same && j < len(r.Headers); j++ {
				same = r.Headers[j].Name == w.Headers[j].Name && r.Headers[j].Value == w.Headers[j].Value
			}
			if !same {
				t.Fatalf("page %d record %d differs from the native document", n, i)
			}
		}
		next := want.Next(len(data.Records))
		if next == "" && page.NextCursor != nil || next != "" && (page.NextCursor == nil || *page.NextCursor != next) {
			t.Fatalf("page %d cursor does not continue at the first omitted record", n)
		}
		delivered += len(data.Records)
		t.Logf("get_http_headers page %d: start %d, %d records of %d, %s", n, sel.Start, len(data.Records), want.Total, timing)
		if next == "" {
			break
		}
		cursor = next
	}
	// A cursor bound to another document is judged after current read
	// rights, by the worker, and discloses nothing.
	foreign := "1:" + strings.Repeat("0", 32)
	if strings.HasPrefix(hex.EncodeToString(digest[:]), strings.Repeat("0", 32)) {
		foreign = "1:" + strings.Repeat("f", 32)
	}
	refused, timing := read(foreign, limit)
	var failure manualHTTPPage
	if refused.Status != "error" || json.Unmarshal(refused.Data, &failure) != nil || failure.Code != "InvalidCursor" {
		t.Fatalf("foreign cursor binding was not InvalidCursor: %s %s", refused.Status, refused.Data)
	}
	t.Logf("get_http_headers: %d of %d records over MCP equal the native document; foreign cursor InvalidCursor (%s)", delivered, whole.Total, timing)
}
