package conversion

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func argumentEditWire(t *testing.T, raw string) contracts.CaptureComposition {
	t.Helper()
	var wire contracts.CaptureComposition
	err := json.Unmarshal([]byte(`{"components":[{"id":"calls","profileRef":{"catalog":"namespace","name":"arguments","version":"v1"},"overrides":[{"actionID":"syscalls","field":"syscallArguments","value":`+raw+`}]}],"maxTotalBytes":16777216,"maxDuration":"30s"}`), &wire)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestSyscallArgumentsEditConversion(t *testing.T) {
	got, err := CompositionFromWire(argumentEditWire(t, `{"maxBytesPerEvent":128,"captureBuffers":false}`))
	if err != nil || !got.Valid() || got.Components[0].Edits[0].Unmodeled {
		t.Fatal("advertised argument edit remains unavailable", got, err)
	}
	a := got.Components[0].Edits[0].SyscallArguments
	if a == nil || a.MaxBytesPerEvent != 128 || a.CaptureBuffers {
		t.Fatal("explicit false lost", a)
	}
	for _, raw := range []string{`null`, `{}`, `{"maxBytesPerEvent":128}`, `{"captureBuffers":false}`, `{"maxBytesPerEvent":null,"captureBuffers":false}`, `{"maxBytesPerEvent":128,"captureBuffers":null}`, `{"maxBytesPerEvent":0,"captureBuffers":false}`, `{"maxBytesPerEvent":4097,"captureBuffers":false}`, `{"maxBytesPerEvent":1.5,"captureBuffers":false}`, `{"maxBytesPerEvent":128,"captureBuffers":"false"}`, `{"maxBytesPerEvent":128,"captureBuffers":false,"decoder":"caller"}`} {
		t.Run(raw, func(t *testing.T) {
			if _, err := CompositionFromWire(argumentEditWire(t, raw)); err == nil {
				t.Fatal("malformed argument edit accepted")
			}
		})
	}
	for _, raw := range []string{`{"maxBytesPerEvent":1,"captureBuffers":false}`, `{"maxBytesPerEvent":4096,"captureBuffers":true}`} {
		if got, err := CompositionFromWire(argumentEditWire(t, raw)); err != nil || !got.Valid() {
			t.Fatal("valid wire bound refused before mechanism qualification", err)
		}
	}
}
