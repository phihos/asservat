package planning

import (
	"fmt"
	"testing"
)

// Baselines were read from the original c70ae164 compiler before extracting
// shared policy normalization. Policy support must not reinterpret old scopes.
func TestRecorderManualScopeCompatibility(t *testing.T) {
	for name, c := range map[string]bool{"network": false, "syscalls": true} {
		composition := network()
		evidence := "packetCapture"
		if c {
			composition = syscalls()
			evidence = "syscallTrace"
		}
		in, now := recorderInput(t, composition, evidence)
		p, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"network": "b42d451360850807a6275cf0565160103f76ac53bc4e44306bb6f907e29d98e5", "syscalls": "2ac31a4cb066371c747192b952c45e70ee5498df20993239f424df46d350ac33"}[name]
		if got := fmt.Sprintf("%x", p.ScopeDigest); got != want {
			t.Fatalf("existing %s scope changed: got %s want %s", name, got, want)
		}
	}
}
