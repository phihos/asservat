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
		want := map[string]string{"network": "6814f11145ba9f9cfc4ee71b93d3398dc67a865f1bcc76dd8a4d82d8da3d967d", "syscalls": "5b9a6bbcf15963efdbe370f607605681e7e267927c9c6504ae948a294085e1c0"}[name]
		if got := fmt.Sprintf("%x", p.ScopeDigest); got != want {
			t.Fatalf("existing %s scope changed: got %s want %s", name, got, want)
		}
	}
}
