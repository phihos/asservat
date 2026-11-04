package integration

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/google/pprof/profile"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const installedProfileComparisonQueries = 2

func installedProfileFocus() bool {
	return installedJourneyFocus() == "manual-profile" || installedJourneyFocus() == "profile-comparison"
}

type installedProfileComparisonSource struct {
	CaseID, ArtifactID, Version string
	Native                      []byte
	Expires                     time.Time
	Retirement                  func()
}
type installedProfileCaptureContinuation struct {
	InitializeProcessing bool
	Captured             func(http.RoundTripper, installedProfileComparisonSource)
	Refused              func(captureID, grantID, reason string) time.Time
}
type installedProfileComparisonCheck func([2]installedProfileComparisonSource) func(queryID, operationID string) func()

type installedComparisonReply struct{ installedJourneyEnvelope }

// Two actual captures have independent case/version/grant histories. The
// comparison caller has ordinary read scope only; SQL readback supplies no
// source, grant or runtime authority. Every unknown call ends without replay.
func qualifyInstalledProfileComparison(t *testing.T, ctx context.Context, identity *installedIdentity, transport http.RoundTripper, publicRoot []byte, address, origin string, sources [2]installedProfileComparisonSource, check installedProfileComparisonCheck) {
	t.Helper()
	if check == nil || sources[0].CaseID == sources[1].CaseID || sources[0].ArtifactID == sources[1].ArtifactID || sources[0].Retirement == nil || sources[1].Retirement == nil {
		t.Fatal("comparison requires two independently captured cross-case profiles and original download proofs")
	}
	tokens := identity.approvedTokenSource(origin)
	if _, err := tokens.Token(ctx); err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-profile-comparison", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, tokens.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	mcpCall := func(name string, args any) installedComparisonReply {
		t.Helper()
		started := time.Now()
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal("comparison operation outcome unknown; no replay", name, err)
		}
		raw, err := json.Marshal(result.StructuredContent)
		var out installedComparisonReply
		if err != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
			t.Fatal("comparison public/browser contract", name)
		}
		t.Logf("installed comparison %s status=%s elapsed=%s", name, out.Status, time.Since(started))
		return out
	}
	cert, err := x509.ParseCertificate(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	browser := identity.consoleSession(t, ctx, cert, address, origin)
	// Existing two-worker cohort bookkeeping only defers independent terminal
	// reads; each RPC/result is joined before the next query. Charges stay spent.
	proofs := &installedSyscallProofCohort{}
	defer proofs.flush(t)
	for index, pair := range [2][2]installedProfileComparisonSource{sources, {sources[1], sources[1]}} {
		verify := check(pair)
		call := mcpCall
		if index == 0 {
			denied := call("prepare_artifact_download", map[string]string{"artifact_id": pair[1].ArtifactID, "idempotency_key": "comparison-read-only-denied-" + pair[1].ArtifactID})
			if denied.Status != "error" {
				t.Fatal("read-only comparison caller obtained native download")
			}
			verify("", "")
		}
		operation, handle := "", ""
		// Retain early locators before browser response/render validation, so
		// failures still attempt independent known query/key/worker inspection.
		proofs.add(t, func() func() { return verify(handle, operation) })
		var finishBrowser func()
		if index == 1 {
			call, finishBrowser = installedProfileComparisonBrowser(t, ctx, browser, address, pair[1], func(reply installedComparisonReply) {
				if operation == "" {
					operation = reply.RequestID
				}
				if handle == "" && reply.Status == "pending" {
					var pending struct {
						Handle string `json:"query_handle"`
					}
					if json.Unmarshal(reply.Data, &pending) == nil {
						handle = pending.Handle
					}
				}
			})
			defer finishBrowser()
		}
		selection := query.ProfileComparisonSelection{SampleType: "cpu", Normalization: query.ProfileComparisonRate, TopN: 20}
		result := call("compare_profiles", map[string]any{"case_id": pair[1].CaseID, "artifact_id": pair[1].ArtifactID, "baseline_case_id": pair[0].CaseID, "baseline_artifact_id": pair[0].ArtifactID, "sample_type": "cpu", "normalization": "perSecond", "top_n": 20})
		operation = result.RequestID
		if index == 0 {
			for _, source := range sources {
				source.Retirement()
			}
		}
		var firstObserved, until time.Time
		for poll := 0; result.Status == "pending"; poll++ {
			var pending struct {
				Handle   string    `json:"query_handle"`
				Retry    int       `json:"retry_after_seconds"`
				Observed time.Time `json:"query_observed_at"`
				Expires  time.Time `json:"query_expires_at"`
			}
			if json.Unmarshal(result.Data, &pending) != nil || pending.Handle == "" || pending.Retry < 1 || pending.Observed.IsZero() || !pending.Expires.After(pending.Observed) || pending.Expires.After(pair[0].Expires) || pending.Expires.After(pair[1].Expires) {
				t.Fatal("invalid comparison pending identity/deadline")
			}
			if poll == 0 {
				handle, firstObserved, until = pending.Handle, pending.Observed, pending.Expires
			}
			if pending.Handle != handle || !pending.Expires.Equal(until) || poll >= 4 {
				t.Fatal("comparison changed query identity or exhausted original polls")
			}
			next, err := installedProjectionPollTime(firstObserved, until, time.Now(), time.Duration(pending.Retry)*time.Second, poll)
			if err != nil {
				t.Fatal(err)
			}
			if installedJourneyPause(ctx, time.Until(next)) != nil {
				t.Fatal(ctx.Err())
			}
			result = call("get_query_result", map[string]string{"query_handle": handle})
		}
		if result.Status != "ok" {
			t.Fatal("actual comparison did not succeed", string(result.Data))
		}
		if handle != "" {
			var nested struct {
				Handle   string                   `json:"query_handle"`
				Tool     string                   `json:"tool_name"`
				Result   installedComparisonReply `json:"result"`
				Observed time.Time                `json:"query_observed_at"`
				Expires  time.Time                `json:"query_expires_at"`
			}
			if json.Unmarshal(result.Data, &nested) != nil || nested.Handle != handle || nested.Tool != "compare_profiles" || nested.Result.RequestID != result.RequestID || !nested.Expires.Equal(until) {
				t.Fatal("comparison result changed paid-query association")
			}
			var innerTimes struct {
				Observed time.Time `json:"query_observed_at"`
				Expires  time.Time `json:"query_expires_at"`
			}
			if json.Unmarshal(nested.Result.Data, &innerTimes) != nil || !innerTimes.Observed.Equal(nested.Observed) || !innerTimes.Expires.Equal(nested.Expires) {
				t.Fatal("comparison inner/outer timing changed")
			}
			result = nested.Result
		}
		var content struct {
			query.ProfileComparison
			CaseID             string    `json:"case_id"`
			ArtifactID         string    `json:"artifact_id"`
			BaselineCaseID     string    `json:"baseline_case_id"`
			BaselineArtifactID string    `json:"baseline_artifact_id"`
			Version            string    `json:"source_version"`
			BaselineVersion    string    `json:"baseline_source_version"`
			Observed           time.Time `json:"query_observed_at"`
			Expires            time.Time `json:"query_expires_at"`
		}
		if result.DataClass != "extract" || json.Unmarshal(result.Data, &content) != nil || !content.Valid(selection) || content.CaseID != pair[1].CaseID || content.ArtifactID != pair[1].ArtifactID || content.Version != pair[1].Version || content.BaselineCaseID != pair[0].CaseID || content.BaselineArtifactID != pair[0].ArtifactID || content.BaselineVersion != pair[0].Version || content.Observed.IsZero() || !content.Expires.After(content.Observed) || content.Expires.After(pair[0].Expires) || content.Expires.After(pair[1].Expires) {
			t.Fatal("comparison changed source roles, versions, selection or original time")
		}
		for side, facts := range [2]query.ProfileComparisonFacts{content.Baseline, content.Incident} {
			p, parseErr := profile.ParseData(pair[side].Native)
			if parseErr != nil || facts.ProfileType != "cpu" || facts.Mode != "interval" || facts.ForceGC {
				t.Fatal("comparison changed accepted CPU acquisition facts", parseErr)
			}
			if p.PeriodType == nil || p.Period <= 0 {
				if facts.Period != nil {
					t.Fatal("unknown native sampling period became known")
				}
			} else if facts.Period == nil || facts.Period.Type != p.PeriodType.Type || facts.Period.Unit != p.PeriodType.Unit || facts.Period.Value != p.Period {
				t.Fatal("comparison changed native sampling period")
			}
		}
		wantRefs := map[string]string{pair[0].ArtifactID: pair[0].Version, pair[1].ArtifactID: pair[1].Version}
		if len(result.Provenance) != len(wantRefs) {
			t.Fatal("comparison provenance cardinality")
		}
		for _, ref := range result.Provenance {
			if wantRefs[ref.ArtifactID] != ref.Digest {
				t.Fatal("comparison provenance substituted")
			}
			delete(wantRefs, ref.ArtifactID)
		}
		want, totals, durations, err := independentInstalledProfileComparison(pair[0].Native, pair[1].Native, selection.TopN)
		if err != nil || !reflect.DeepEqual(content.Rows, want) || content.Baseline.Total != totals[0] || content.Incident.Total != totals[1] || content.Baseline.DurationSeconds == nil || content.Incident.DurationSeconds == nil || *content.Baseline.DurationSeconds != durations[0] || *content.Incident.DurationSeconds != durations[1] {
			t.Fatal("comparison differs from independent complete native CPU aggregation", err)
		}
		if index == 1 {
			for _, row := range content.Rows {
				if row.Delta != 0 || row.Baseline != row.Incident {
					t.Fatal("same-artifact comparison changed values")
				}
			}
			finishBrowser()
		}
	}
	proofs.flush(t)
	if proofs.queries != installedProfileComparisonQueries || proofs.joined != installedProfileComparisonQueries {
		t.Fatal("comparison terminal proof count", proofs.queries, proofs.joined)
	}
	t.Log("installed profile comparison: two independent cross-case native captures, distinct comparison through ordinary read-only MCP OAuth and same-artifact comparison through actual installed React with the original HttpOnly session/Origin/CSRF, rendered function rows, exact role/version provenance, independent full native cumulative aggregation, two joined one-worker/six-key batches and original download positive retirement; final terminal workers remain fully charged pending normal later cleanup demand")
}

// A separate fixture calculation: parse the downloaded originals, accumulate
// each function once per sample (including inline/recursive stack members),
// compute exact rational rates/deltas, sort all names and truncate only last.
// It calls no production comparison/aggregation implementation.
func independentInstalledProfileComparison(baseline, incident []byte, limit int) ([]query.ProfileComparisonRow, [2]int64, [2]float64, error) {
	var totals [2]int64
	var durations [2]float64
	var profiles [2]*profile.Profile
	counts := [2]map[string]int64{{}, {}}
	for side, native := range [2][]byte{baseline, incident} {
		p, err := profile.ParseData(native)
		if err != nil || p.CheckValid() != nil || p.DurationNanos <= 0 {
			return nil, totals, durations, errors.New("invalid fixture CPU profile")
		}
		profiles[side] = p
		durations[side] = float64(p.DurationNanos) / 1e9
		cpu := -1
		for i, typ := range p.SampleType {
			if typ.Type == "cpu" && typ.Unit == "nanoseconds" {
				cpu = i
			}
		}
		if cpu < 0 {
			return nil, totals, durations, errors.New("fixture lacks CPU nanoseconds")
		}
		for _, sample := range p.Sample {
			if cpu >= len(sample.Value) {
				return nil, totals, durations, errors.New("missing CPU value")
			}
			value := sample.Value[cpu]
			totals[side] += value
			names := map[string]bool{}
			if len(sample.Location) == 0 {
				names[""] = true
			}
			for _, location := range sample.Location {
				if location == nil || len(location.Line) == 0 {
					names[""] = true
					continue
				}
				for _, line := range location.Line {
					name := ""
					if line.Function != nil {
						name = line.Function.Name
					}
					names[name] = true
				}
			}
			for name := range names {
				counts[side][name] += value
			}
		}
	}
	names := map[string]bool{}
	for _, side := range counts {
		for name := range side {
			names[name] = true
		}
	}
	rows := make([]query.ProfileComparisonRow, 0, len(names))
	rate := func(value, duration int64) *big.Rat {
		return new(big.Rat).SetFrac(new(big.Int).Mul(big.NewInt(value), big.NewInt(1e9)), big.NewInt(duration))
	}
	for name := range names {
		b, i := rate(counts[0][name], profiles[0].DurationNanos), rate(counts[1][name], profiles[1].DurationNanos)
		bf, _ := b.Float64()
		inf, _ := i.Float64()
		delta, _ := new(big.Rat).Sub(i, b).Float64()
		row := query.ProfileComparisonRow{Baseline: bf, Incident: inf, Delta: delta}
		if name != "" {
			n := name
			row.Function = &n
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if math.Abs(rows[i].Delta) != math.Abs(rows[j].Delta) {
			return math.Abs(rows[i].Delta) > math.Abs(rows[j].Delta)
		}
		a, b := "", ""
		if rows[i].Function != nil {
			a = *rows[i].Function
		}
		if rows[j].Function != nil {
			b = *rows[j].Function
		}
		return a < b
	})
	if limit < 1 {
		return nil, totals, durations, fmt.Errorf("invalid fixture row limit %d", limit)
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, totals, durations, nil
}
