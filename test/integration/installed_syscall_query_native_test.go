package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const installedRawSyscallQueries = 2
const installedArgumentQueryUnits = installedSyscallProjectionQueries*query.SyscallProjectionQueryUnits + installedRawSyscallQueries*query.SyscallQueryQueryUnits

type installedSyscallQueryContinuation struct {
	BeforeQuery func()
	RawQueries  func(afterEach func())
}
type installedSyscallArgumentPage struct {
	Kind     string                      `json:"kind"`
	Events   []artifact.RawArgumentEvent `json:"events"`
	Coverage struct {
		Dropped     *uint64  `json:"dropped_events"`
		Unmatched   uint64   `json:"unmatched_events"`
		Unfinished  uint64   `json:"unfinished_events"`
		Unknown     uint64   `json:"unknown_events"`
		RecordCount uint64   `json:"record_count"`
		Truncated   *bool    `json:"truncated"`
		Gaps        []string `json:"gaps"`
	} `json:"coverage"`
	Observed time.Time `json:"query_observed_at"`
	Expires  time.Time `json:"query_expires_at"`
}

func installedRawSyscallRequest(s installedSyscallQueryBrowserSource, key string) map[string]any {
	return map[string]any{"case_id": s.CaseID, "artifact_id": s.ArtifactID, "grant_id": s.GrantID, "idempotency_key": key, "limit": 20, "syscall_names": []string{"write"}, "errors_only": false}
}

func queryInstalledRawSyscalls(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin string, s installedSyscallQueryBrowserSource, check installedProjectionCheck) installedSyscallArgumentPage {
	t.Helper()
	if check == nil {
		t.Fatal("raw syscall query requires independent SQL check")
	}
	verify := check(s.ArtifactID)
	token := identity.packetQueryTokenSource(origin) // Existing read+raw/no download/capture session.
	if _, e := token.Token(ctx); e != nil {
		t.Fatal(e)
	}
	wire, e := contracts.NewInvestigationContracts()
	if e != nil {
		t.Fatal(e)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-raw-syscalls", Version: "1"}, nil)
	session, e := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, token.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	call := func(name string, args any) installedComparisonReply {
		t.Helper()
		start := time.Now()
		r, e := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if e != nil {
			t.Fatal("raw syscall outcome unavailable; no unknown replay", name, e)
		}
		raw, e := json.Marshal(r.StructuredContent)
		var out installedComparisonReply
		if e != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || r.IsError != (out.Status == "error") {
			t.Fatal("raw syscall canonical reply", name)
		}
		t.Logf("installed raw syscall %s status=%s elapsed=%s", name, out.Status, time.Since(start))
		return out
	}
	if r := call("prepare_artifact_download", map[string]string{"artifact_id": s.ArtifactID, "idempotency_key": "raw-syscall-no-native"}); r.Status != "error" {
		t.Fatal("raw query session obtained native authority")
	}
	verify("", "")
	return queryInstalledRawSyscallsWithCall(t, ctx, s, installedRawSyscallRequest(s, "installed-syscall-mcp-"+s.ArtifactID), call, verify, true)
}
func queryInstalledRawSyscallsBrowser(t *testing.T, ctx context.Context, b *installedBrowser, address string, s installedSyscallQueryBrowserSource, check installedProjectionCheck) installedSyscallArgumentPage {
	t.Helper()
	if check == nil {
		t.Fatal("raw syscall browser needs independent SQL proof")
	}
	verify := check(s.ArtifactID)
	operation, handle := "", ""
	checked := false
	defer func() {
		if !checked && operation != "" {
			verify(handle, operation)
		}
	}()
	request := installedRawSyscallRequest(s, "not-injected-ui-key")
	call, finish := installedSyscallQueryBrowser(t, ctx, b, address, s, request, func(r installedComparisonReply) {
		if operation == "" {
			operation = r.RequestID
		}
		if handle == "" && r.Status == "pending" {
			var p struct {
				Handle string `json:"query_handle"`
			}
			if json.Unmarshal(r.Data, &p) == nil {
				handle = p.Handle
			}
		}
	})
	defer finish()
	return queryInstalledRawSyscallsWithCall(t, ctx, s, request, call, func(qid, op string) func() { finish(); checked = true; return verify(qid, op) }, false)
}
func queryInstalledRawSyscallsWithCall(t *testing.T, ctx context.Context, s installedSyscallQueryBrowserSource, request map[string]any, call func(string, any) installedComparisonReply, verify func(string, string) func(), replay bool) installedSyscallArgumentPage {
	t.Helper()
	out := call("syscall_query", request)
	operation, handle := out.RequestID, ""
	checked := false
	defer func() {
		if !checked && operation != "" {
			verify(handle, operation)
		}
	}()
	var observed, until, outerObserved time.Time
	direct := out.Status == "ok"
	var directObserved time.Time
	times := func(r installedComparisonReply) (string, time.Time, time.Time, int) {
		var p struct {
			Handle   string    `json:"query_handle"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
			Retry    int       `json:"retry_after_seconds"`
		}
		if json.Unmarshal(r.Data, &p) != nil || p.Observed.IsZero() || !p.Expires.After(p.Observed) || p.Expires.After(s.Expires) {
			t.Fatal("raw syscall original interval")
		}
		return p.Handle, p.Observed, p.Expires, p.Retry
	}
	if out.Status != "pending" && !direct {
		t.Fatal("initial raw syscall unavailable", out.Status)
	}
	if replay {
		firstHandle, firstObserved, firstExpiry, _ := times(out)
		again := call("syscall_query", request)
		h, o, u, _ := times(again)
		if again.Status != "pending" || h == "" || firstHandle != "" && h != firstHandle || !u.Equal(firstExpiry) {
			t.Fatal("raw syscall same-key replay changed query/deadline or disclosed")
		}
		if direct {
			handle, observed, until, directObserved = h, firstObserved, firstExpiry, firstObserved
		}
		_ = o
		t.Log("raw syscall exact-key Begin replay returned original pending handle without read/debit; SQL checks original/replay call rows")
	}
	for n := 0; out.Status == "pending"; n++ {
		h, o, u, retry := times(out)
		if n == 0 {
			handle, observed, until = h, o, u
		}
		if n >= 4 || h == "" || h != handle || !u.Equal(until) || retry < 1 {
			t.Fatal("raw syscall pending changed bounds")
		}
		target := observed.Add(time.Duration(n+1) * time.Duration(retry) * time.Second)
		if delay := time.Until(target); delay > 0 {
			if e := installedJourneyPause(ctx, delay); e != nil {
				t.Fatal(e)
			}
		}
		out = call("get_query_result", map[string]string{"query_handle": handle})
		if out.Status == "ok" {
			var poll struct {
				Handle   string          `json:"query_handle"`
				Tool     string          `json:"tool_name"`
				Result   json.RawMessage `json:"result"`
				Observed time.Time       `json:"query_observed_at"`
				Expires  time.Time       `json:"query_expires_at"`
			}
			if json.Unmarshal(out.Data, &poll) != nil || poll.Handle != handle || poll.Tool != "syscall_query" || !poll.Expires.Equal(until) || poll.Observed.IsZero() || !poll.Expires.After(poll.Observed) {
				t.Fatal("raw syscall nested current/original association")
			}
			outerObserved = poll.Observed
			var inner installedComparisonReply
			if json.Unmarshal(poll.Result, &inner) != nil || inner.RequestID != out.RequestID || inner.DataClass != "raw" || out.DataClass != "raw" {
				t.Fatal("raw syscall nested raw result")
			}
			out = inner
		}
	}
	if direct {
		outerObserved = directObserved
	}
	var page installedSyscallArgumentPage
	if out.Status != "ok" || out.DataClass != "raw" || len(out.Provenance) != 1 || out.Provenance[0].ArtifactID != s.ArtifactID || out.Provenance[0].Digest != s.Version || json.Unmarshal(out.Data, &page) != nil || page.Kind != "syscallQuery" || page.Observed.IsZero() || !page.Expires.After(page.Observed) || page.Expires.After(s.Expires) || !until.IsZero() && (!page.Expires.Equal(until) || !page.Observed.Equal(outerObserved)) || len(page.Events) < 1 || len(page.Events) > 20 {
		t.Fatal("raw syscall source/class/page/original dates")
	}
	for _, e := range page.Events {
		if !e.WellFormed() || e.Identity.PodUID != s.PodUID || e.Syscall != "write" {
			t.Fatal("raw syscall value/selection changed")
		}
	}
	checked = true
	if verify(handle, operation) == nil {
		t.Fatal("raw syscall missing SQL/key/worker proof")
	}
	return page
}

// Independent typed JSONL oracle, after the existing immutable session/native
// verifier. It does not call the product query projector or decode raw values.
func installedRawSyscallOracle(native []byte, pod string) ([]artifact.RawArgumentEvent, error) {
	if len(native) == 0 || native[len(native)-1] != '\n' {
		return nil, errors.New("incomplete argument JSONL")
	}
	scan := bufio.NewScanner(bytes.NewReader(native))
	scan.Buffer(make([]byte, 1024), 8192)
	header, footer := false, false
	var events []artifact.RawArgumentEvent
	decode := func(raw []byte, v any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if e := d.Decode(v); e != nil {
			return e
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return errors.New("extra JSON value")
		}
		return nil
	}
	for scan.Scan() {
		if footer {
			return nil, errors.New("tail after footer")
		}
		var tag struct {
			Record string `json:"record"`
		}
		if json.Unmarshal(scan.Bytes(), &tag) != nil {
			return nil, errors.New("bad JSONL")
		}
		switch tag.Record {
		case "header":
			var h artifact.ArgumentHeader
			if header || len(events) != 0 || decode(scan.Bytes(), &h) != nil || h.PodUID != pod {
				return nil, errors.New("header changed")
			}
			header = true
		case "event":
			var line artifact.ArgumentEventLine
			if !header || decode(scan.Bytes(), &line) != nil || !line.Event.WellFormed() || line.Event.Identity.PodUID != pod {
				return nil, errors.New("event changed")
			}
			events = append(events, line.Event)
		case "footer":
			var f artifact.ArgumentFooter
			if !header || decode(scan.Bytes(), &f) != nil || f.Retained != uint64(len(events)) {
				return nil, errors.New("footer changed")
			}
			footer = true
		default:
			return nil, errors.New("unknown native record")
		}
	}
	if scan.Err() != nil || !footer {
		return nil, errors.New("incomplete native tail")
	}
	return events, nil
}
func qualifyInstalledRawSyscallParity(t *testing.T, native []byte, s installedSyscallQueryBrowserSource, pages ...installedSyscallArgumentPage) {
	t.Helper()
	events, e := installedRawSyscallOracle(native, s.PodUID)
	if e != nil {
		t.Fatal(e)
	}
	_, _, counts, e := installedSyscallExpected(native, artifact.SyscallArgumentsArtifact, s.PodUID)
	if e != nil {
		t.Fatal(e)
	}
	var filtered []artifact.RawArgumentEvent
	for _, event := range events {
		if event.Syscall == "write" {
			filtered = append(filtered, event)
		}
	}
	if len(filtered) < 1 {
		t.Fatal("native lacks original selected writes")
	}
	for _, p := range pages {
		if !reflect.DeepEqual(p.Events, filtered[:min(20, len(filtered))]) || p.Coverage.Dropped != nil || p.Coverage.Truncated != nil || p.Coverage.RecordCount != counts.RecordCount || p.Coverage.Unmatched != counts.UnmatchedEvents || p.Coverage.Unfinished != counts.UnfinishedEvents || p.Coverage.Unknown != counts.UnknownEvents || len(p.Coverage.Gaps) == 0 {
			t.Fatal("raw query differs from SAME original recorded values/order/full-file counters")
		}
	}
	t.Logf("raw syscall MCP+React: exact recorded arguments/value bytes/truncation and counters match SAME authenticated nativeJSONL (%d records), no decoding/execution/new acquisition", len(events))
}
