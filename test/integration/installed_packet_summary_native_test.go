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
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type installedPacketSummarySource struct {
	CaseID, ArtifactID, Version, PodUID string
	Expires                             time.Time
}

// Read the same existing published source with ordinary read-only OAuth. No
// acquisition, raw grant or native-download authority is supplied by this view.
func queryInstalledPacketSummary(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, origin string, source installedPacketSummarySource, check installedProjectionCheck) query.PacketSummary {
	t.Helper()
	if check == nil {
		t.Fatal("packet summary requires independent SQL proof")
	}
	verify := check(source.ArtifactID)
	token := identity.approvedTokenSource(origin)
	if _, err := token.Token(ctx); err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-packet-summary", Version: "1"}, nil)
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
			t.Fatal("packet summary outcome unavailable; no replay", name, err)
		}
		raw, err := json.Marshal(result.StructuredContent)
		var out installedComparisonReply
		if err != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
			t.Fatal("canonical packet summary response", name)
		}
		t.Logf("installed packet summary %s status=%s elapsed=%s", name, out.Status, time.Since(started))
		return out
	}
	denied := call("prepare_artifact_download", map[string]string{"artifact_id": source.ArtifactID, "idempotency_key": "packet-read-only-denied"})
	if denied.Status != "error" {
		t.Fatal("read-only packet session obtained native download")
	}
	verify("", "")
	return queryInstalledPacketSummaryWithCall(t, ctx, source, call, verify)
}

func queryInstalledPacketSummaryWithCall(t *testing.T, ctx context.Context, source installedPacketSummarySource, call func(string, any) installedComparisonReply, verify func(string, string) func()) query.PacketSummary {
	t.Helper()
	result := call("get_pcap_summary", map[string]string{"case_id": source.CaseID, "artifact_id": source.ArtifactID})
	operation, handle := result.RequestID, ""
	var observed, until time.Time
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
		t.Fatal("packet summary unavailable", result.Status)
	}
	var finalObserved time.Time
	if handle != "" {
		var nested struct {
			Handle   string                   `json:"query_handle"`
			Tool     string                   `json:"tool_name"`
			Result   installedComparisonReply `json:"result"`
			Observed time.Time                `json:"query_observed_at"`
			Expires  time.Time                `json:"query_expires_at"`
		}
		if json.Unmarshal(result.Data, &nested) != nil || nested.Handle != handle || nested.Tool != "get_pcap_summary" || nested.Result.RequestID != result.RequestID || !nested.Expires.Equal(until) {
			t.Fatal("packet poll changed original association")
		}
		finalObserved = nested.Observed
		result = nested.Result
	}
	if result.Status != "ok" || result.DataClass != "extract" || len(result.Provenance) != 1 || result.Provenance[0].ArtifactID != source.ArtifactID || result.Provenance[0].Digest != source.Version {
		t.Fatal("packet summary changed exact source/version/result class")
	}
	var times struct {
		Observed time.Time `json:"query_observed_at"`
		Expires  time.Time `json:"query_expires_at"`
	}
	var summary query.PacketSummary
	if json.Unmarshal(result.Data, &times) != nil || times.Observed.IsZero() || !times.Expires.After(times.Observed) || times.Expires.After(source.Expires) || !until.IsZero() && (!times.Expires.Equal(until) || !times.Observed.Equal(finalObserved)) || json.Unmarshal(result.Data, &summary) != nil || !summary.Valid() {
		t.Fatal("packet summary lost canonical fields/original times")
	}
	if verify(handle, operation) == nil {
		t.Fatal("packet summary lacks exact SQL joined proof")
	}
	return summary
}
