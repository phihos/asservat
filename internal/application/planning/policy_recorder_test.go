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

// ADR-273: a syscall metadata composition compiles into an ongoing policy
// source with its include list sorted for the source filter digest; a finite
// onTrigger syscall policy stays unavailable.
func TestOngoingPolicyRecorderCompilesSyscallMetadata(t *testing.T) {
	include := value.ProfileEdit{ActionID: "syscalls", Field: "syscallFilter", Syscalls: &value.SyscallSelection{Mode: "include", Names: []string{"read", "openat"}}}
	p, err := CompileOngoingPolicyRecorder(syscalls(include), &fakeCompiler{program: fixtureProgram})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Valid() || p.Action.Kind != "syscallTrace" || p.Filter != nil || len(p.SyscallInclude) != 2 || p.SyscallInclude[0] != "openat" || p.SyscallInclude[1] != "read" {
		t.Fatalf("syscall policy recorder %+v", p.Action)
	}
	all, err := CompileOngoingPolicyRecorder(syscalls(), &fakeCompiler{program: fixtureProgram})
	if err != nil || !all.Valid() || len(all.SyscallInclude) != 0 || all.Digest == p.Digest {
		t.Fatal("all-syscalls policy recorder", err)
	}
	_, err = CompileOngoingPolicyRecorder(syscalls(text("syscalls", "actionExecutionMode", "onTrigger"), text("syscalls", "syscallBefore", "0s")), &fakeCompiler{program: fixtureProgram})
	var e value.CompositionError
	if !errors.As(err, &e) || e.Code != value.CompositionRecorderUnavailable {
		t.Fatal("finite syscall policy armed", err)
	}
}

// ADR-275: a packet + syscall composition compiles into one complete source
// configuration per recorder, each pinned to its own profile and action,
// while a one-component composition keeps its existing digest.
func TestOngoingPolicyRecordersOnePerAction(t *testing.T) {
	all, err := CompileOngoingPolicyRecorders(mixed(32<<20), &fakeCompiler{program: fixtureProgram})
	if err != nil || len(all) != 2 {
		t.Fatal("mixed policy recorders", err, len(all))
	}
	if !all[0].Valid() || !all[1].Valid() || all[0].Action.Kind != "packetCapture" || all[1].Action.Kind != "syscallTrace" || all[0].Profile.ComponentID != "net" || all[1].Profile.ComponentID != "calls" || all[0].Digest == all[1].Digest {
		t.Fatalf("recorders %+v %+v", all[0].Action, all[1].Action)
	}
	single, err := CompileOngoingPolicyRecorder(network(), &fakeCompiler{program: fixtureProgram})
	alone, err2 := CompileOngoingPolicyRecorders(network(), &fakeCompiler{program: fixtureProgram})
	if err != nil || err2 != nil || len(alone) != 1 || alone[0].Digest != single.Digest {
		t.Fatal("one-component digest changed", err, err2)
	}
}
