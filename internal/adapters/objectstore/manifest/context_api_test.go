package manifest

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestAPIContextManifestBindsExplicitProjectionClass(t *testing.T) {
	v, e, l, c, legacy := fixture(t)
	old, err := json.Marshal(e)
	if err != nil || bytes.Contains(old, []byte("ExecutionClass")) || bytes.Contains(legacy, []byte("executionClass")) {
		t.Fatal("node expectation or manifest serialization changed", err)
	}
	if _, err := v.ParseContext(mutate(t, legacy, func(m map[string]any) {
		delete(obj(m, "target"), "nodeUID")
		delete(obj(m, "target"), "nodeBootID")
	}), e, c); err == nil {
		t.Fatal("legacy node manifest silently became API context")
	}
	e.ExecutionClass, e.NodeUID, e.NodeBootID, e.ActionID = artifact.ContextAPIExecution, "", "", "pod-status"
	b, err := v.MarshalContext(e, l, c, e.TriggeredAt, e.TriggeredAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	m, err := v.ParseContext(b, e, c)
	if err != nil || !bytes.Contains(b, []byte(`"executionClass":"kubernetesAPI"`)) || bytes.Contains(b, []byte(`"nodeUID"`)) || bytes.Contains(b, []byte(`"nodeBootID"`)) {
		t.Fatal("API context manifest lost execution identity", err)
	}
	native, _ := json.Marshal(podDTO{Format: artifact.ContextFormat, NamespaceUID: e.NamespaceUID, PodUID: e.PodUID, ResourceVersion: "1", ObservedAt: m.StartedAt, Phase: "Pending", Ready: "Unknown", Initialized: "Unknown", Scheduled: "False"})
	if err := v.ValidateNative(native, e, m); err != nil {
		t.Fatal("unscheduled Pod projection rejected", err)
	}
	for name, edit := range map[string]func(map[string]any){
		"missing class":       func(m map[string]any) { delete(obj(m, "target"), "executionClass") },
		"unknown class":       func(m map[string]any) { obj(m, "target")["executionClass"] = "arbitrary" },
		"invented node":       func(m map[string]any) { obj(m, "target")["nodeUID"] = "node" },
		"invented boot":       func(m map[string]any) { obj(m, "target")["nodeBootID"] = testID(8) },
		"raw data":            func(m map[string]any) { m["dataClass"] = "raw" },
		"larger payload":      func(m map[string]any) { obj(m, "sizes")["plaintextBytes"] = 4097 },
		"different mechanism": func(m map[string]any) { m["kind"] = "coreDump" },
		"different action":    func(m map[string]any) { obj(m, "collectionProvenance")["actionID"] = "core" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := mutate(t, b, edit)
			if err := validate(v.manifest, bad, artifact.MaxRootBytes); err == nil {
				t.Fatal("schema admitted mixed/unqualified API class")
			}
			if _, err := v.ParseContext(bad, e, c); err == nil {
				t.Fatal("verifier admitted altered accepted class")
			}
		})
	}
	for name, edit := range map[string]func(*artifact.ContextExpectation){
		"node":           func(e *artifact.ContextExpectation) { e.NodeUID = "node" },
		"boot":           func(e *artifact.ContextExpectation) { e.NodeBootID = testID(8) },
		"raw":            func(e *artifact.ContextExpectation) { e.DataClass = "raw" },
		"action":         func(e *artifact.ContextExpectation) { e.ActionID = "context" },
		"larger ceiling": func(e *artifact.ContextExpectation) { e.Registration.NativeLimit++ },
	} {
		t.Run("expectation "+name, func(t *testing.T) {
			bad := e
			edit(&bad)
			if bad.Validate() == nil {
				t.Fatal("mixed accepted API expectation")
			}
		})
	}
}
