package mtls

import "testing"

type fixedTrace string

func (f fixedTrace) Error() string     { return "trace" }
func (f fixedTrace) FixedStep() string { return string(f) }

func TestSetupMarksKeepOnlyFixedMarks(t *testing.T) {
	for trace, want := range map[string]string{
		"settings-guard@3.1s after [source-open@20ms owned-process@1.2s]/inner": "source-open@20ms owned-process@1.2s",
		"fresh@4s after [source-open@20ms host.example:443]":                    "",
		"settings-guard@3.1s": "",
	} {
		if got := setupMarks(fixedTrace(trace)); got != want {
			t.Fatalf("%q: got %q want %q", trace, got, want)
		}
	}
}
