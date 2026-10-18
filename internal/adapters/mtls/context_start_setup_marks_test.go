package mtls

import (
	"context"
	"testing"
	"time"
)

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

type setupTraceError struct{ fixedTrace }

func (setupTraceError) ContextStartSetupStep() string     { return "settings-guard" }
func (setupTraceError) ContextStartSetupUntil() time.Time { return time.Time{} }

type outerStep struct{ err error }

func (o outerStep) Error() string     { return "outer" }
func (o outerStep) Unwrap() error     { return o.err }
func (o outerStep) FixedStep() string { return "outer-step" }

func TestSetupStepTraceIgnoresOuterWrapper(t *testing.T) {
	d := newContextStartOpeningDiagnostic(context.Background(), time.Now().Add(time.Second))
	d.setupStep(outerStep{setupTraceError{"settings-guard@3s after [source-open@20ms]"}})
	if d.stage != "setup-settings-guard" || d.trace != "source-open@20ms" {
		t.Fatalf("stage=%q trace=%q", d.stage, d.trace)
	}
}
