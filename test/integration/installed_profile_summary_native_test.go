package integration

import (
	"context"
	"encoding/json"
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
	if check == nil {
		t.Fatal("profile summary requires independent SQL readback")
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
	type summaryReply struct {
		installedJourneyEnvelope
		DataClass  string `json:"data_class"`
		Provenance []struct {
			ArtifactID string `json:"artifactID"`
			Digest     string `json:"digest"`
		} `json:"provenance"`
	}
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
	result := call("get_profile_summary", map[string]any{"case_id": caseID, "artifact_id": artifactID, "sample_type": "cpu", "top_n": 20})
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
	if json.Unmarshal(result.Data, &summary) != nil || !summary.Valid(query.ProfileSummarySelection{SampleType: "cpu", TopN: 20}) || summary.SampleType != "cpu" || len(summary.Top) == 0 || len(summary.Top) > 20 {
		t.Fatal("invalid closed summary")
	}
	p, err := profile.ParseData(native)
	if err != nil {
		t.Fatal(err)
	}
	selected := -1
	for n, s := range p.SampleType {
		if s.Type == "cpu" {
			selected = n
			if summary.Unit != s.Unit {
				t.Fatal("summary changed native unit")
			}
		}
	}
	if selected < 0 {
		t.Fatal("fixture profile lacks CPU samples")
	}
	var total int64
	for _, s := range p.Sample {
		total += s.Value[selected]
	}
	if summary.Total != total || total <= 0 {
		t.Fatal("summary total differs from authenticated native samples", summary.Total, total)
	}
	found := false
	for _, row := range summary.Top {
		if row.Function != nil && strings.Contains(*row.Function, "burn") && row.Cumulative > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("summary lacks the sampled fixture workload")
	}
	if verify(handle, operation) == nil {
		t.Fatal("profile query lacks exact joined worker/key readback")
	}
	t.Log("installed profile summary: ordinary read-only OAuth, native-download denial, exact CPU total, closed hotspots and original joined worker/key lifetime verified; no raw query or additional approval")
}
