package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/google/pprof/profile"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// One query through the installed public service, using a real OAuth session
// without native-download scope. SQL inspection supplies no runtime authority.
func qualifyInstalledProfileSummary(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID, version string, native []byte, expires time.Time, check installedProjectionCheck) {
	t.Helper()
	summary := queryInstalledProfileSummary(t, ctx, identity, transport, origin, caseID, artifactID, version, "cpu", expires, check)
	if err := installedProfileSummaryMatchesNative(summary, native, "burn"); err != nil || summary.Total <= 0 {
		t.Fatal("CPU summary differs from authenticated native samples", err)
	}
	t.Log("installed profile summary: ordinary read-only OAuth, native-download denial, exact CPU total, closed hotspots and original joined worker/key lifetime verified; no raw query or additional approval")
}

// Query and join before a separately authorized native download. The returned
// aggregate supplies no raw authority; the downloaded original validates it.
// Heap may replace only the query/polls with the installed React caller. The
// read-only MCP native denial still runs, without admitting a second query.
func queryInstalledProfileSummary(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin, caseID, artifactID, version, sampleType string, expires time.Time, check installedProjectionCheck, browserCall ...func(string, any) installedComparisonReply) query.ProfileSummary {
	t.Helper()
	if check == nil || len(browserCall) > 1 {
		t.Fatal("profile summary requires independent SQL readback and at most one browser caller")
	}
	verify := check(artifactID)
	source := identity.approvedTokenSource(origin)
	if _, err := source.Token(ctx); err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-profile-summary", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, source.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	type summaryReply = installedComparisonReply
	call := func(name string, args any) summaryReply {
		t.Helper()
		began := time.Now()
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal("summary operation outcome unavailable; no replay", name, err)
		}
		raw, err := json.Marshal(result.StructuredContent)
		var out summaryReply
		if err != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
			t.Fatal("profile summary response contract", name)
		}
		t.Logf("installed profile summary %s status=%s elapsed=%s", name, out.Status, time.Since(began))
		return out
	}
	denied := call("prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": "profile-read-only-denied"})
	if denied.Status != "error" {
		t.Fatal("read-only profile session obtained native download")
	}
	verify("", "")
	if len(browserCall) == 1 {
		call = browserCall[0]
	}
	return queryInstalledProfileSummaryWithCall(t, ctx, caseID, artifactID, version, sampleType, expires, call, verify)
}

// Preserve the exact canonical source/handle/deadline checks across MCP and
// installed React. The caller supplies an already independently funded verifier.
func queryInstalledProfileSummaryWithCall(t *testing.T, ctx context.Context, caseID, artifactID, version, sampleType string, expires time.Time, call func(string, any) installedComparisonReply, verify func(string, string) func()) query.ProfileSummary {
	t.Helper()
	type summaryReply = installedComparisonReply
	result := call("get_profile_summary", map[string]any{"case_id": caseID, "artifact_id": artifactID, "sample_type": sampleType, "top_n": 20})
	operation, handle := result.RequestID, ""
	var observed, until time.Time
	for poll := 0; result.Status == "pending"; poll++ {
		var pending struct {
			Handle   string    `json:"query_handle"`
			Retry    int       `json:"retry_after_seconds"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if json.Unmarshal(result.Data, &pending) != nil || pending.Handle == "" || pending.Retry < 1 || pending.Observed.IsZero() || !pending.Expires.After(pending.Observed) || pending.Expires.After(expires) {
			t.Fatal("invalid pending profile query")
		}
		if poll == 0 {
			handle, observed, until = pending.Handle, pending.Observed, pending.Expires
		}
		if pending.Handle != handle || !pending.Expires.Equal(until) || poll >= 4 {
			t.Fatal("profile query changed original identity/deadline or exhausted polls")
		}
		next, err := installedProjectionPollTime(observed, until, time.Now(), time.Duration(pending.Retry)*time.Second, poll)
		if err != nil {
			t.Fatal(err)
		}
		if installedJourneyPause(ctx, time.Until(next)) != nil {
			t.Fatal(ctx.Err())
		}
		result = call("get_query_result", map[string]string{"query_handle": handle})
	}
	if result.Status != "ok" {
		t.Fatal("profile summary did not return a result", string(result.Data))
	}
	if handle != "" {
		var nested struct {
			Handle  string       `json:"query_handle"`
			Tool    string       `json:"tool_name"`
			Result  summaryReply `json:"result"`
			Expires time.Time    `json:"query_expires_at"`
		}
		if json.Unmarshal(result.Data, &nested) != nil || nested.Handle != handle || nested.Tool != "get_profile_summary" || nested.Result.RequestID != result.RequestID || !nested.Expires.Equal(until) {
			t.Fatal("profile result changed its original query association")
		}
		result = nested.Result
	}
	if result.Status != "ok" || result.DataClass != "extract" || len(result.Provenance) != 1 || result.Provenance[0].ArtifactID != artifactID || result.Provenance[0].Digest != version {
		t.Fatal("profile summary changed source version or result class")
	}
	var resultTimes struct {
		Observed time.Time `json:"query_observed_at"`
		Expires  time.Time `json:"query_expires_at"`
	}
	if json.Unmarshal(result.Data, &resultTimes) != nil || resultTimes.Observed.IsZero() || !resultTimes.Expires.After(resultTimes.Observed) || resultTimes.Expires.After(expires) || !until.IsZero() && !resultTimes.Expires.Equal(until) {
		t.Fatal("profile summary changed original expiry")
	}
	var summary query.ProfileSummary
	if json.Unmarshal(result.Data, &summary) != nil || !summary.Valid(query.ProfileSummarySelection{SampleType: sampleType, TopN: 20}) || len(summary.Top) == 0 {
		t.Fatal("invalid closed summary")
	}
	if verify(handle, operation) == nil {
		t.Fatal("profile query lacks exact joined worker/key readback")
	}
	return summary
}

func installedProfileSummaryMatchesNative(summary query.ProfileSummary, native []byte, workloadFunction string) error {
	if !summary.Valid(query.ProfileSummarySelection{SampleType: summary.SampleType, TopN: 20}) {
		return fmt.Errorf("invalid summary")
	}
	p, err := profile.ParseData(native)
	if err != nil {
		return err
	}
	if err := p.CheckValid(); err != nil {
		return err
	}
	selected := -1
	for n, s := range p.SampleType {
		if s.Type == summary.SampleType {
			if selected >= 0 {
				return fmt.Errorf("ambiguous native sample type")
			}
			selected = n
			if summary.Unit != s.Unit {
				return fmt.Errorf("summary changed native unit")
			}
		}
	}
	if selected < 0 {
		return fmt.Errorf("fixture profile lacks selected samples")
	}
	if p.DurationNanos <= 0 {
		if summary.DurationSeconds != nil {
			return fmt.Errorf("summary invented a native duration")
		}
	} else if summary.DurationSeconds == nil || *summary.DurationSeconds != float64(p.DurationNanos)/float64(time.Second) {
		return fmt.Errorf("summary changed native duration")
	}
	var total int64
	for _, s := range p.Sample {
		total += s.Value[selected]
	}
	if summary.Total != total {
		return fmt.Errorf("summary total %d differs from authenticated native samples %d", summary.Total, total)
	}
	found := workloadFunction == ""
	for _, row := range summary.Top {
		if row.Function != nil && strings.Contains(*row.Function, workloadFunction) && row.Cumulative > 0 {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("summary lacks the sampled fixture workload")
	}
	return nil
}
