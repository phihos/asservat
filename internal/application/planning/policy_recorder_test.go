package planning

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/planning"
)

func TestPolicyRecorderUsesSameFrozenRecipeWithoutInventedCapture(t *testing.T) {
	c := network(text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s"), text("sample", "packetAfter", "2s"), text("sample", "actionTimeout", "10s"))
	// The builtin's local action name is stable, resolved from its definition.
	p, err := CompilePolicyRecorder(c, &fakeCompiler{program: fixtureProgram})
	if err != nil {
		t.Fatal(err)
	}
	in, now := recorderInput(t, c, "packetCapture")
	manual, err := CompileRecorder(in, &fakeCompiler{program: fixtureProgram}, now)
	if err != nil {
		t.Fatal(err)
	}
	var scope struct {
		Recipe json.RawMessage `json:"recipe"`
	}
	if err = json.Unmarshal(manual.CanonicalScope, &scope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Recipe, scope.Recipe) || p.RecipeDigest != manual.RecipeDigest || p.Action.ID != manual.Actions[0].ID || p.Action.FilterDigest != manual.Actions[0].FilterDigest {
		t.Fatal("manual and policy compilation diverged")
	}
	for _, field := range []string{`"captureUID"`, `"podUID"`, `"executor"`, `"deadline"`} {
		if bytes.Contains(p.Scope, []byte(field)) {
			t.Fatal("invented runtime identity in inert configuration", field)
		}
	}
	c.Components[0].Edits = append(c.Components[0].Edits, text("sample", "packetFilter", "tcp port 443"))
	changed, err := CompilePolicyRecorder(c, &fakeCompiler{program: fixtureProgram})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Digest == p.Digest {
		t.Fatal("filter edit did not change accepted configuration")
	}
}

func TestPolicyRecorderKeepsOngoingAndOtherMechanismsUnavailable(t *testing.T) {
	for name, c := range map[string]value.ProfileComposition{"ongoing": network(), "syscalls": syscalls()} {
		t.Run(name, func(t *testing.T) {
			_, err := CompilePolicyRecorder(c, &fakeCompiler{program: fixtureProgram})
			var e value.CompositionError
			if !errors.As(err, &e) || e.Code != value.CompositionRecorderUnavailable {
				t.Fatal("unsupported source armed", err)
			}
		})
	}
}
