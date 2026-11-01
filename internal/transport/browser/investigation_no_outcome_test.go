package browser

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

type noOutcomeStep struct {
	step     string
	rendered *bool
}

func (e noOutcomeStep) Error() string     { *e.rendered = true; return "private-provider-secret" }
func (e noOutcomeStep) FixedStep() string { return e.step }

type noOutcomeOpaque struct{ rendered *bool }

func (e noOutcomeOpaque) Error() string { *e.rendered = true; return "private-provider-secret" }

type noOutcomeOperations struct {
	presentation.Operations
	err error
}

func (o noOutcomeOperations) Call(context.Context, identities.CurrentIdentity, string, json.RawMessage) (presentation.OperationReply, error) {
	return presentation.OperationReply{}, o.err
}

func TestBrowserNoOutcomeReportsOnlyClosedTopLevelStage(t *testing.T) {
	for _, step := range []string{"identity", "busy", "audit-begin", "audit-result", "audit-finish", "result-acknowledgement", "request-expired", "final-identity", "reply-expired", "final-disclosure", "unknown-private-provider-secret", "audit-begin/private-provider-secret", "audit-finish/private-provider-secret", "no-fixed-step"} {
		t.Run(step, func(t *testing.T) {
			h, server, _, _, _, _ := auditedBrowserFixture(t)
			rendered := false
			var injected error = noOutcomeStep{step: step, rendered: &rendered}
			if step == "no-fixed-step" {
				injected = noOutcomeOpaque{rendered: &rendered}
			}
			// Explicit inner-operation failure at the actual strict handler boundary;
			// the separate real-auditor case below exercises genuine Begin failure.
			h.operations = noOutcomeOperations{Operations: h.operations, err: injected}
			reportedCh := make(chan string, 1)
			h.Report = func(v string) { reportedCh <- v }
			response, err := server.Client().Do(auditedBrowserRequest(t, server, "get_capture", `{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			reported := <-reportedCh
			want := step
			if at := strings.IndexByte(want, '/'); at >= 0 {
				want = want[:at]
			}
			if strings.HasPrefix(want, "unknown-") || want == "no-fixed-step" {
				want = "other"
			}
			if err != nil || response.StatusCode != 503 || reported != "call-no-outcome/"+want || rendered || strings.Contains(string(body), step) || strings.Contains(reported, "private-provider") {
				t.Fatal("closed no-outcome stage", response.StatusCode, reported, "rendered", rendered)
			}
		})
	}
}

func TestBrowserNoOutcomeRealAuditBeginFailure(t *testing.T) {
	h, server, calls, normal, _, _ := auditedBrowserFixture(t)
	normal.fail = true
	reportedCh := make(chan string, 1)
	h.Report = func(v string) { reportedCh <- v }
	response, err := server.Client().Do(auditedBrowserRequest(t, server, "get_capture", `{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	reported := <-reportedCh
	begin, finish := normal.count()
	if err != nil || response.StatusCode != 503 || reported != "call-no-outcome/audit-begin" || begin != 1 || finish != 0 || calls.requests != 0 || strings.Contains(string(body), "audit-begin") {
		t.Fatal("real audited no-outcome failure", response.StatusCode, reported, begin, finish, calls.requests)
	}
}
