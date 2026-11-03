package planning

import (
	"encoding/json"
	"testing"
)

// A saved approval's cumulative event ceiling must survive reconstruction;
// reusing a packet-only display type must not erase reviewed argument limits.
func TestRecorderScopeSummaryRetainsReviewedEventCeiling(t *testing.T) {
	in, now := recorderInput(t, network(text("sample", "packetFilter", "tcp[13] & 2 != 0")), "packetCapture")
	p, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil {
		t.Fatal(err)
	}
	var frozen map[string]any
	if err = json.Unmarshal(p.CanonicalScope, &frozen); err != nil {
		t.Fatal(err)
	}
	approval := frozen["approval"].(map[string]any)
	limits := approval["observationLimits"].(map[string]any)
	limits["maxObservedEvents"] = 1234
	raw, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	_, restored, err := RecorderScopeSummary(raw)
	if err != nil {
		t.Fatal("reviewed event ceiling refused during scope reconstruction", err)
	}
	encoded, err := json.Marshal(restored.ObservationLimits)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]int64
	if err = json.Unmarshal(encoded, &got); err != nil || got["MaxObservedEvents"] != 1234 {
		t.Fatal("reviewed event ceiling lost", string(encoded), err)
	}
	// Old packet scopes carry no event allowance and remain byte-for-byte stable.
	_, old, err := RecorderScopeSummary(p.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(old.ObservationLimits)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err = json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if _, present := got["MaxObservedEvents"]; present {
		t.Fatal("legacy event allowance was synthesized")
	}
}
