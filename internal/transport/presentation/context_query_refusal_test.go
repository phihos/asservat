package presentation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

// Component reproduction of the SQL outcome fence: private writer closure
// alone is insufficient. The exact invocation's acknowledged Finish must
// precede positive read-batch completion. Successful
// public replies additionally retain the local acknowledged body owner.
type refusalOutcomeGate struct {
	*presentationAuditGate
	acknowledged map[string]audit.OperationOutcome
}

func (g *refusalOutcomeGate) Finish(ctx context.Context, out audit.OperationOutcome) error {
	if err := g.presentationAuditGate.Finish(ctx, out); err != nil {
		return err
	}
	g.acknowledged[out.Intent.ID] = out
	return nil
}

type refusalOutcomeLedger struct {
	analysisapp.ContextQueryLedger
	gate            *refusalOutcomeGate
	attempts, early int
}

func (l *refusalOutcomeLedger) CompleteReadBatch(ctx context.Context, b value.ContextReadBatch, closed analysisapp.ContextProjectionClosed) error {
	l.attempts++
	out, ok := l.gate.acknowledged[b.OperationID]
	if !ok || out.Effect != "accepted" {
		l.early++
		return value.ErrUnavailable
	}
	return l.ContextQueryLedger.CompleteReadBatch(ctx, b, closed)
}

func oversizedRefusalSummary(t *testing.T, f *bridgeFixture) {
	t.Helper()
	f.a.Scope.Profile.TopN = 100
	summary := value.ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", Total: 100, Top: []value.ProfileHotspot{}, SymbolStatus: "complete"}
	for n := range 100 {
		name, fraction := fmt.Sprintf("%03d%s", n, strings.Repeat("x", 509)), .01
		summary.Top = append(summary.Top, value.ProfileHotspot{Function: &name, Flat: 1, Cumulative: 1, Fraction: &fraction})
		body, _ := json.Marshal(summary)
		if len(body) > value.ProfileSummaryBytes {
			summary.Top = summary.Top[:len(summary.Top)-1]
			break
		}
	}
	if !summary.Valid(f.a.Scope.Profile) {
		t.Fatal("invalid bounded summary fixture")
	}
	f.result = &value.ProjectionResult{Summary: &summary}
}

func TestQueryRefusalRetainsReadUntilExactOutcomeAndTransportClose(t *testing.T) {
	for _, kind := range []string{"http", "syscall-metadata", "syscall-arguments", "public-summary-size", "public-http-size"} {
		for _, poll := range []bool{false, true} {
			refusals := []string{"cursor", "size"}
			if strings.HasPrefix(kind, "public-") {
				refusals = []string{"size"}
			}
			for _, refusal := range refusals {
				t.Run(fmt.Sprintf("%s/poll-%t/%s", kind, poll, refusal), func(t *testing.T) {
					var s *AuditedOperations
					var f *bridgeFixture
					var g *presentationAuditGate
					var p *projectionAuditTarget
					tool := "get_http_headers"
					input := headerInput("", 5)
					switch kind {
					case "http", "public-http-size":
						s, f, g, p = httpBridge(t, value.HTTPHeaderWindow{Limit: 5})
						if kind == "public-http-size" {
							records := headerRecords(1, "bounded")
							for range 6 {
								records[0].Headers = append(records[0].Headers, value.HTTPHeaderField{Name: "content-type", Value: strings.Repeat("<", 1024)})
							}
							f.result = &value.ProjectionResult{Headers: value.HTTPHeaderPage{ProjectionDigest: headerDigest, Total: 1, Records: records, CoverageGaps: []string{}}}
						}
					case "syscall-metadata", "syscall-arguments":
						native := artifact.SyscallRecordsArtifact
						if kind == "syscall-arguments" {
							native = artifact.SyscallArgumentsArtifact
						}
						s, f, g, p = syscallBridge(t, native, value.SyscallEventsView)
						tool, input = "get_syscall_events", syscallInput("")
					case "public-summary-size":
						s, f, g, p = summaryBridge(t)
						oversizedRefusalSummary(t, f)
						tool, input = "get_profile_summary", summaryInput(100)
					}
					if !strings.HasPrefix(kind, "public-") {
						f.result = &value.ProjectionResult{InvalidCursor: refusal == "cursor", TooLarge: refusal == "size"}
					}
					gate := &refusalOutcomeGate{presentationAuditGate: g, acknowledged: map[string]audit.OperationOutcome{}}
					ledger := &refusalOutcomeLedger{ContextQueryLedger: f, gate: gate}
					s.audit["normal"], f.s.Results.Ledger = gate, ledger
					adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
					if err == nil {
						switch tool {
						case "get_http_headers":
							reads, _ := f.s.HTTPHeaders()
							adapter, err = adapter.WithHTTPHeaders(reads)
						case "get_syscall_events":
							reads, _ := f.s.SyscallQueries()
							adapter, err = adapter.WithSyscalls(reads)
						case "get_profile_summary":
							reads, _ := f.s.ProfileSummaries()
							adapter, err = adapter.WithProfileSummaries(reads)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					p.adapter = adapter
					premature := false
					g.onFinish = func() {
						if f.reads > 0 && (f.lastRead.closed || ledger.attempts != 0 || p.last.delivery == nil || p.last.acknowledged) {
							premature = true
						}
					}
					if poll {
						f.ready = false
						pending, err := s.Call(t.Context(), f, tool, input)
						if err != nil {
							t.Fatal(err)
						}
						if err := pending.Close(context.Background()); err != nil {
							t.Fatal(err)
						}
						tool, input = "get_query_result", bridgePoll(f.q.ID)
					}
					f.ready = true
					reply, err := s.Call(t.Context(), f, tool, input)
					if err != nil {
						t.Fatal(err)
					}
					defer reply.Close(context.Background())
					var body struct {
						Status string `json:"status"`
						Data   struct {
							Code string `json:"code"`
						} `json:"data"`
					}
					wantCode, wantStatus := "AnalysisUnavailable", "denied"
					if refusal == "cursor" {
						wantCode, wantStatus = "InvalidCursor", "invalid"
					}
					if premature || json.Unmarshal(reply.Body, &body) != nil || body.Status != "error" || body.Data.Code != wantCode || s.contracts.ValidateOutput(tool, reply.Body) != nil {
						t.Fatal("refusal closed the read before outcome acknowledgement or changed its wire result", premature, string(reply.Body))
					}
					out := g.outcomes[len(g.outcomes)-1]
					if out.Status != wantStatus || out.Effect != "accepted" || reply.owner == nil || f.lastRead.closed || ledger.attempts != 0 || !f.active || f.completions != 0 || len(s.lanes["normal"]) != 1 || reply.CheckDisclosure(t.Context()) != nil {
						t.Fatal("refusal lost exact charged live ownership", out.Status, out.Effect, reply.owner != nil, ledger.attempts, ledger.early, f.active, f.completions)
					}
					for _, field := range []string{`"records":`, `"top":`, `"events":`, `"rows":`} {
						if strings.Contains(string(reply.Body), field) {
							t.Fatal("refusal disclosed result content")
						}
					}
					if err := reply.Close(context.Background()); err != nil || ledger.attempts != 1 || ledger.early != 0 || f.completions != 1 || f.active || len(s.lanes["normal"]) != 0 {
						t.Fatal("acknowledged refusal failed joined fenced cleanup", err, ledger.attempts, ledger.early, f.completions, f.active)
					}
				})
			}
		}
	}
}

func TestQueryRefusalAuditFailureAndRevocationPreserveClosureFence(t *testing.T) {
	for _, mode := range []string{"finish-failed", "cancel-after-finish", "identity-after-finish", "uncertain-private-close"} {
		t.Run(mode, func(t *testing.T) {
			s, f, g, p := syscallBridge(t, artifact.SyscallArgumentsArtifact, value.SyscallEventsView)
			gate := &refusalOutcomeGate{presentationAuditGate: g, acknowledged: map[string]audit.OperationOutcome{}}
			ledger := &refusalOutcomeLedger{ContextQueryLedger: f, gate: gate}
			s.audit["normal"], f.s.Results.Ledger = gate, ledger
			adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
			if err != nil {
				t.Fatal(err)
			}
			reads, _ := f.s.SyscallQueries()
			p.adapter, err = adapter.WithSyscalls(reads)
			if err != nil {
				t.Fatal(err)
			}
			f.result = &value.ProjectionResult{InvalidCursor: true}
			f.ready = true
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "finish-failed":
				g.finishFail = true
			case "cancel-after-finish":
				g.onFinish = cancel
			case "identity-after-finish":
				g.onFinish = func() { f.i.Scopes = nil }
			case "uncertain-private-close":
				f.closeErr = value.ErrUnavailable
			}
			reply, err := s.Call(ctx, f, "get_syscall_events", syscallInput(""))
			if mode == "uncertain-private-close" {
				if err != nil || reply.owner == nil || f.completions != 0 {
					t.Fatal("refusal not prepared before uncertain close", err)
				}
				if reply.Close(context.Background()) == nil || reply.Close(context.Background()) == nil || !f.active || f.completions != 0 || ledger.attempts != 0 || len(s.lanes["normal"]) != 0 {
					t.Fatal("unknown private join became positive closure/refund")
				}
				return
			}
			if err == nil || len(reply.Body) != 0 || f.reads != 1 || f.admissions != 1 || f.batches != 1 || len(s.lanes["normal"]) != 0 || !f.lastRead.closed {
				t.Fatal("failed/refused response lost conservative cleanup", err)
			}
			if mode == "finish-failed" {
				if !f.active || f.completions != 0 || ledger.early != 1 {
					t.Fatal("missing audit acknowledgement bypassed completion fence")
				}
			} else if f.active || f.completions != 1 || ledger.early != 0 {
				t.Fatal("acknowledged outcome could not finish restrictive cleanup", f.active, f.completions, ledger.early)
			}
		})
	}
}
