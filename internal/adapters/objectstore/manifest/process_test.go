package manifest

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProcessManifestCanonicalBranchAndMandatoryNativeCheck(t *testing.T) {
	v, e, l, c, _ := fixture(t)
	e.ExecutionClass = artifact.ContextAPIExecution
	e.NodeUID = ""
	e.NodeBootID = ""
	e.ActionID = "a0123456789abcdef01234567"
	e.NativeType = artifact.ProcessesArtifact
	e.DataClass = "metadata"
	e.Registration.NativeLimit = artifact.ProcessNativeLimit
	e.Processes = &artifact.ProcessCapture{ActionID: e.ActionID, Mode: artifact.ProcessAll, TimeoutMillis: 5000, MaxNativeBytes: artifact.ProcessNativeLimit, Composition: []byte(`{}`)}
	l.Binding = e.Binding()
	if e.Validate() != nil {
		t.Fatal("process expectation", e.Validate())
	}
	from, until := e.TriggeredAt, e.TriggeredAt.Add(time.Second)
	b, err := v.MarshalContext(e, l, c, from, until)
	if err != nil {
		d, de := contextDocument(e, l, c, from, until)
		raw, _ := json.Marshal(d)
		var val any
		_ = json.Unmarshal(raw, &val)
		t.Fatalf("canonical process manifest refused: %v document=%v layout=%v schema=%v", err, de, l.Validate(), v.manifest.Validate(val))
	}
	m, err := v.ParseContext(b, e, c)
	if err != nil {
		t.Fatal(err)
	}
	boot := testID(8)
	runtimeID := "containerd://" + strings.Repeat("a", 64)
	p := artifact.ProcessInventory{Format: artifact.ProcessFormat, PodUID: e.PodUID, NodeUID: testID(9), NodeBootID: boot, Mode: artifact.ProcessAll, StartedAt: from, CompletedAt: until, Origins: []artifact.ProcessOrigin{{RuntimeID: runtimeID, MainPID: 123, Outcome: "observed"}}, Processes: []artifact.ProcessRecord{{Identity: artifact.ProcessIdentity{PodUID: e.PodUID, NodeBootID: boot, RuntimeID: runtimeID, HostPID: 123, StartTimeTicks: 10, CgroupPath: "/pod/" + strings.Repeat("a", 64), CgroupID: 10}, NamespacePID: 1, ObservedAt: from, Main: true, State: "S", Threads: 1}}, Gaps: []string{"socketOwnersUnsupported"}}
	raw, _ := json.Marshal(p)
	check, err := v.NativeCheck(e, m)
	if err != nil || feed(check, raw, 127) != nil {
		t.Fatal("mandatory native checker refused original metadata", err)
	}
	for name, edit := range map[string]func(map[string]any){"class": func(m map[string]any) { m["dataClass"] = "raw" }, "format": func(m map[string]any) { m["format"] = "asservat-logs/v1" }, "cap": func(m map[string]any) { obj(m, "sizes")["plaintextBytes"] = artifact.ProcessNativeLimit + 1 }, "action": func(m map[string]any) { obj(m, "collectionProvenance")["actionID"] = "pod-status" }} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.ParseContext(mutate(t, b, edit), e, c); err == nil {
				t.Fatal("foreign manifest branch accepted")
			}
		})
	}
	p.PodUID = "other"
	raw, _ = json.Marshal(p)
	check, err = v.NativeCheck(e, m)
	if err != nil {
		t.Fatal(err)
	}
	if feed(check, raw, 127) == nil {
		t.Fatal("wrong-source native escaped mandatory checker")
	}
}
