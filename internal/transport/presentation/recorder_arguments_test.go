package presentation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
)

type argumentPreviewCompiler struct{ oneInstruction }

func (argumentPreviewCompiler) CompileArguments(names []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	defs, err := syscalls.ArgumentDefinitions(names, buffers, int(maximum))
	if err != nil {
		return artifact.RecordingArguments{}, err
	}
	program, err := hex.DecodeString(gadget.ArgumentObjectSHA256)
	if err != nil {
		return artifact.RecordingArguments{}, err
	}
	out := artifact.RecordingArguments{DefinitionDigest: artifact.Digest(syscalls.ArgumentDefinitionDigest(defs)), AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: int64(syscalls.ArgumentMaxProbeBytes(defs)), MaxBytesPerEvent: maximum, MaxBytesPerSecond: planning.SensitiveMaxBytesPerSecond, CaptureBuffers: buffers}
	copy(out.ProgramDigest[:], program)
	return out, nil
}

// Exercise the actual compiler, assessment, projection and output validator;
// synthetic catalog/target facts supply no collection authority.
func TestArgumentPreviewWire(t *testing.T) {
	s, f := recorderOperations(t, true)
	f.filters = argumentPreviewCompiler{}
	raw, err := os.ReadFile("../../application/planning/profiles/syscall-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"] = "argument-capture"
	a := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	a["impact"], a["executionMode"] = "sensitiveRead", "onTrigger"
	p := a["parameters"].(map[string]any)
	p["mode"], p["before"], p["after"] = "arguments", "0s", "3s"
	p["syscalls"] = map[string]any{"mode": "include", "names": []string{"read", "write", "openat"}}
	p["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	document, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f.resolved = []planning.CatalogProfile{{Ref: planning.ProfileRef{Catalog: "namespace", Name: "argument-capture", Version: "v1"}, SourceClusterID: "00000000-0000-4000-8000-000000000001", SourceNamespaceUID: "ns", SourceUID: "argument-uid", Document: document, Enabled: true}}
	in := `{` + wireTarget + `,"requested_retention_seconds":3600,"profile_composition":{"components":[{"id":"calls","profileRef":{"catalog":"namespace","name":"argument-capture","version":"v1"}}],"maxTotalBytes":16777216,"maxDuration":"20s"}}`
	var input ContextOperationInput
	if err := json.Unmarshal([]byte(in), &input); err != nil {
		t.Fatal(err)
	}
	data, _, err := s.recorderPreview(t.Context(), f, input)
	if err != nil {
		t.Fatal("argument plan projection", err)
	}
	for _, warning := range data.Warnings {
		if len(warning) > 256 {
			t.Errorf("preview warning exceeds 256 characters (%d): %s", len(warning), warning)
		}
	}
	reply, err := s.Call(t.Context(), f, "preview_capture", []byte(in))
	if err != nil {
		t.Fatal("compiled argument preview failed public output projection", err)
	}
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Approval bool     `json:"approval_required"`
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if json.Unmarshal(reply.Body, &out) != nil || out.Status != "ok" || !out.Data.Approval {
		t.Fatalf("argument preview: %s", reply.Body)
	}
	warnings := strings.Join(out.Data.Warnings, " ")
	for _, want := range []string{"disabling buffers does not disable path reads", "bytes in total", "bytes per second", "concurrent session", "eligible entry and exit probes", "Failed reads"} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("missing %q from warnings: %v", want, out.Data.Warnings)
		}
	}
}
