package presentation

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
)

type recordableLogsPreview struct{ *recorderFixture }

func (f recordableLogsPreview) PreviewComposition(ctx context.Context, current identities.CurrentIdentity, intent value.ContextIntent) (app.RecorderPreviewResult, error) {
	r, err := f.recorderFixture.PreviewComposition(ctx, current, intent)
	r.Recordable = true
	return r, err
}

func TestFiniteLogsActualCompiledPreviewFitsPublicContract(t *testing.T) {
	for _, protected := range []bool{false, true} {
		for _, maximum := range []string{"1048576", "67108864"} {
			s, base := recorderOperations(t, true)
			base.requireApproval = protected
			f := recordableLogsPreview{base}
			s, err := NewContextOperations(s.config, f, f)
			if err != nil {
				t.Fatal(err)
			}
			input := `{` + wireTarget + `,"requested_retention_seconds":600,"profile_composition":{"components":[{"id":"logs","profileRef":{"catalog":"builtin","name":"finite-logs","version":"v1"},"overrides":[{"actionID":"logs","field":"logBefore","value":"1h"},{"actionID":"logs","field":"logAfter","value":"2s"},{"actionID":"logs","field":"actionTimeout","value":"15s"},{"actionID":"logs","field":"actionMaxBytes","value":` + maximum + `}]}],"maxTotalBytes":` + maximum + `,"maxDuration":"15s"}}`
			var in ContextOperationInput
			if err := json.Unmarshal([]byte(input), &in); err != nil {
				t.Fatal(err)
			}
			data, _, err := s.recorderPreview(t.Context(), base, in)
			if err != nil {
				t.Fatal("actual logs plan projection", err)
			}
			if want, err := strconv.ParseInt(maximum, 10, 64); err != nil || data.MaxBytes != want {
				t.Fatalf("preview understates compiled logs ceiling: got%d want%s", data.MaxBytes, maximum)
			}
			body, _ := json.Marshal(OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: "00000000-0000-4000-8000-000000000001", Status: "ok", DataClass: "extract", Data: data, Warnings: []string{}, Provenance: []any{}})
			if err := s.contracts.ValidateOutput("preview_capture", body); err != nil {
				t.Fatalf("protected=%v compiled logs projection fails: %s", protected, s.contracts.OutputViolation("preview_capture", body))
			}
			if _, err := s.Call(t.Context(), base, "preview_capture", []byte(input)); err != nil {
				t.Fatal("public logs preview", protected, err)
			}
			var invalid map[string]any
			if err := json.Unmarshal(body, &invalid); err != nil {
				t.Fatal(err)
			}
			action := invalid["data"].(map[string]any)["lifecycle_plan"].(map[string]any)["actions"].([]any)[0].(map[string]any)
			for _, window := range [][2]string{{"0s", "2s"}, {"1h", "0s"}} {
				action["requestedBefore"], action["after"] = window[0], window[1]
				valid, _ := json.Marshal(invalid)
				if err := s.contracts.ValidateOutput("preview_capture", valid); err != nil {
					t.Fatal("finite future-only or historical-only logs rejected", window, err)
				}
			}
			action["requestedBefore"], action["after"] = "1h", "2s"
			for _, kind := range []string{"packetCapture", "syscallTrace"} {
				action["kind"] = kind
				bad, _ := json.Marshal(invalid)
				if s.contracts.ValidateOutput("preview_capture", bad) == nil {
					t.Fatal("on-trigger recorder acquired historical window", kind)
				}
			}
			action["kind"] = "logs"
			action["requestedBefore"], action["after"] = "0s", "0s"
			bad, _ := json.Marshal(invalid)
			if s.contracts.ValidateOutput("preview_capture", bad) == nil {
				t.Fatal("empty finite log window accepted")
			}
		}
	}
}
