package planning

import (
	"fmt"
	"testing"
)

// Baselines pin the manual scope digests (ring {maxAge, maxBytes, segments});
// policy support must not reinterpret them.
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
		want := map[string]string{"network": "82e99d313bf0bb5d44b3bfd41418d51cbc075b0ee24b6fbc062d1c200a2ca60b", "syscalls": "5b9a6bbcf15963efdbe370f607605681e7e267927c9c6504ae948a294085e1c0"}[name]
		if got := fmt.Sprintf("%x", p.ScopeDigest); got != want {
			t.Fatalf("existing %s scope changed: got %s want %s", name, got, want)
		}
	}
}
