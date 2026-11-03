package presentation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

func TestRawAccessUsesExistingAuditLaneBeforeDispatch(t *testing.T) {
	for _, mode := range []string{"accepted", "intent unavailable", "outcome unavailable", "uncertain service"} {
		t.Run(mode, func(t *testing.T) {
			audited, current, gate := auditedFixture(t)
			use := &rawGrantUseCase{grantUseCase: &grantUseCase{view: rawGrantView(current.i.VerifiedAt, 1), until: current.metadataUntil}}
			if mode == "uncertain service" {
				use.requestErr = authapp.ErrGrantUnavailable
			}
			gate.beginFail = mode == "intent unavailable"
			gate.finishFail = mode == "outcome unavailable"
			operations, err := NewGrantOperations(audited.inner.PublicOrigin(), audited.config.Now, audited.config.NewID, use)
			if err != nil {
				t.Fatal(err)
			}
			audited.inner, err = NewInvestigationGrantOperations(audited.inner.(*InvestigationOperations), operations)
			if err != nil {
				t.Fatal(err)
			}
			if audit.OperationLane("request_raw_access") != "normal" || !BrowserOperationSupported(audited, "request_raw_access") {
				t.Fatal("raw request has no existing authenticated audit route")
			}
			tool, ok := audited.Tool("request_raw_access")
			if !ok || !tool.MCP() {
				t.Fatal("MCP operation absent")
			}
			raw := []byte(fmt.Sprintf(`{"case_id":"%s","artifact_digests":["%s"],"operations":["download_artifact"],"reason":"PRIVATE REASON","max_bytes":512,"expires_in_seconds":3600,"idempotency_key":"original"}`, use.view.Grant.RawQuery.CaseID, hash(artifact.Digest{1})))
			normalized, err := audited.normalize("request_raw_access", raw)
			if err != nil {
				t.Fatal(err)
			}
			var in GrantOperationInput
			if json.Unmarshal(normalized, &in) != nil || in.CaseID == "" || len(in.ArtifactDigests) != 1 || in.MaxBytes != 512 || in.Reason != "PRIVATE REASON" {
				t.Fatal("audit omitted original selection", string(normalized))
			}
			reply, err := audited.Call(t.Context(), current, "request_raw_access", raw)
			if mode == "intent unavailable" {
				if err == nil || use.calls != 0 || len(gate.outcomes) != 0 || len(reply.Body) != 0 {
					t.Fatal("unaudited request ran", err)
				}
				return
			}
			if use.calls != 1 || len(gate.outcomes) != 1 || !gate.outcomes[0].Valid() {
				t.Fatal("missing bounded intent/outcome", err, gate.outcomes)
			}
			want := "accepted"
			if mode == "uncertain service" {
				want = "unknown"
			}
			if gate.outcomes[0].Effect != want {
				t.Fatal("effect misclassified", gate.outcomes[0].Effect)
			}
			encoded, _ := json.Marshal(gate.outcomes)
			if bytes.Contains(encoded, []byte("PRIVATE REASON")) {
				t.Fatal("audit leaked review text")
			}
			if mode == "outcome unavailable" {
				if err == nil || len(reply.Body) != 0 {
					t.Fatal("unaudited outcome escaped", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
