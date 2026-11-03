package presentation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/analysis"
)

func oversizedPublicComparison(t *testing.T, f *pairedBridge) []byte {
	t.Helper()
	f.a.Scope.Profile.TopN, f.a.Baseline.Scope.Profile.TopN = 100, 100
	result := f.result.Comparison
	result.Rows = []value.ProfileComparisonRow{}
	for n := 0; n < 100; n++ {
		name := fmt.Sprintf("%03d%s", n, strings.Repeat("x", 509))
		result.Rows = append(result.Rows, value.ProfileComparisonRow{Function: &name, Baseline: 10, Incident: 10, Delta: 0})
		b, e := json.Marshal(result)
		if e != nil {
			t.Fatal(e)
		}
		if len(b) > value.ProfileComparisonBytes {
			result.Rows = result.Rows[:len(result.Rows)-1]
			break
		}
	}
	if !result.Valid(f.a.Scope.Comparison.Selection(f.a.Scope.Profile)) {
		t.Fatal("invalid bounded comparison")
	}
	var in ProfileComparisonOperationInput
	if json.Unmarshal(comparisonInput(f), &in) != nil {
		t.Fatal("fixture input")
	}
	in.TopN = 100
	b, _ := json.Marshal(in)
	return b
}

func TestProfileComparisonSizeRefusalRetainsAuditedReadOwner(t *testing.T) {
	for _, size := range []string{"worker", "public-envelope"} {
		for _, mode := range []string{"direct", "poll", "failed-audit", "unknown-close"} {
			t.Run(size+"/"+mode, func(t *testing.T) {
				s, f, g, p := comparisonBridge(t, false)
				input := comparisonInput(f)
				if size == "worker" {
					f.result = &value.ProjectionResult{TooLarge: true}
				} else {
					input = oversizedPublicComparison(t, f)
				}
				tool := "compare_profiles"
				if mode != "direct" {
					f.ready = false
					pending, e := s.Call(t.Context(), f, tool, input)
					if e != nil {
						t.Fatal("pending", e)
					}
					if e = pending.Close(context.Background()); e != nil {
						t.Fatal(e)
					}
					f.ready = true
					tool, input = "get_query_result", bridgePoll(f.q.ID)
				}
				if mode == "failed-audit" {
					g.finishFail = true
				}
				if mode == "unknown-close" {
					f.closeErr = value.ErrUnavailable
				}
				out, e := s.Call(t.Context(), f, tool, input)
				if mode == "failed-audit" {
					if e == nil || len(out.Body) != 0 || !f.active || f.completions != 0 || !f.lastRead.closed {
						t.Fatal("failed acknowledgement lost conservative charged cleanup", e)
					}
					return
				}
				if e != nil {
					t.Fatal("authenticated size refusal lost its response owner", e)
				}
				if !f.active || f.completions != 0 || p.last.delivery == nil || out.CheckDisclosure(t.Context()) != nil {
					t.Fatal("read closed before outcome and transport join")
				}
				var body struct {
					Status    string                         `json:"status"`
					DataClass string                         `json:"data_class"`
					Data      struct{ Code, Message string } `json:"data"`
				}
				if json.Unmarshal(out.Body, &body) != nil || body.Status != "error" || body.DataClass != "metadata" || body.Data.Code != "AnalysisUnavailable" || !strings.Contains(body.Data.Message, "Select fewer functions") || strings.Contains(string(out.Body), `"rows"`) {
					t.Fatalf("size refusal leaked result or lost recovery guidance: %s", out.Body)
				}
				outcome := g.outcomes[len(g.outcomes)-1]
				if outcome.Status != "denied" || outcome.Reason != "not_available" || outcome.Effect != "accepted" {
					t.Fatal("wrong charged refusal outcome")
				}
				e = out.Close(context.Background())
				if mode == "unknown-close" {
					if e == nil || out.Close(context.Background()) == nil || !f.active || f.completions != 0 {
						t.Fatal("unknown join refunded size refusal")
					}
					return
				}
				if e != nil || f.active || f.completions != 1 {
					t.Fatal("acknowledged size refusal did not join", e)
				}
			})
		}
	}
}
