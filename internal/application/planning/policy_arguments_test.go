package planning

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"asservat.local/asservat/internal/adapters/gadget"
	syscalladapter "asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/planning"
)

// Use the release's real closed definitions and object pin, with no acquisition.
type policyArgumentCompiler struct{ fakeCompiler }

func (*policyArgumentCompiler) CompileArguments(names []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	defs, err := syscalladapter.ArgumentDefinitions(names, buffers, int(maximum))
	if err != nil {
		return artifact.RecordingArguments{}, err
	}
	a := artifact.RecordingArguments{DefinitionDigest: artifact.Digest(syscalladapter.ArgumentDefinitionDigest(defs)), AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: int64(syscalladapter.ArgumentMaxProbeBytes(defs)), MaxBytesPerEvent: maximum, MaxBytesPerSecond: value.SensitiveMaxBytesPerSecond, CaptureBuffers: buffers}
	program, err := hex.DecodeString(gadget.ArgumentObjectSHA256)
	if err != nil {
		return a, err
	}
	copy(a.ProgramDigest[:], program)
	return a, nil
}

func TestFiniteArgumentPolicyPinsSameReviewedMechanism(t *testing.T) {
	c := editableArgumentComposition(t)
	compiler := &policyArgumentCompiler{}
	p, err := CompilePolicyRecorder(c, compiler)
	if err != nil || !p.Valid() {
		t.Fatal("finite argument policy unavailable", err)
	}
	if !bytes.Contains(p.Scope, []byte(`"argumentProgram"`)) {
		t.Fatal("mechanism missing from policy digest")
	}
	if p.Filter != nil || p.Action.ExecutionMode != "onTrigger" || p.Action.SyscallMode != "arguments" || !slices.Contains(p.Action.Sensitive, value.ReasonSyscallArguments) {
		t.Fatal("arguments used packet or ongoing scope")
	}
	in, now := recorderInput(t, c, "syscallTrace")
	manual, err := CompileRecorder(in, compiler, now)
	if err != nil || manual.Approval == nil || manual.Approval.DataClass != "raw" {
		t.Fatal("same argument recipe lost raw approval", err)
	}
	r, _, err := RecordingFor(manual)
	if err != nil || r.Arguments == nil || *r.Arguments != *p.Arguments || manual.RecipeDigest != p.RecipeDigest {
		t.Fatal("policy and manual argument mechanisms diverged", err)
	}
	var scope struct {
		Argument argumentProgramRecord `json:"argumentProgram"`
	}
	if json.Unmarshal(p.Scope, &scope) != nil || scope.Argument.ActionID != p.Action.ID || !slices.Equal(scope.Argument.Names, p.SyscallInclude) {
		t.Fatal("missing exact action/name binding")
	}
	mechanism, err := scope.Argument.mechanism()
	if err != nil || mechanism != *p.Arguments {
		t.Fatal("scope did not preserve complete mechanism", err)
	}
	for _, buffers := range []bool{false, true} {
		edited := c.Clone()
		edited.Components[0].Edits = []value.ProfileEdit{{ActionID: "syscalls", Field: "syscallArguments", SyscallArguments: &value.SyscallArgumentsEdit{MaxBytesPerEvent: 256, CaptureBuffers: buffers}}}
		changed, err := CompilePolicyRecorder(*edited, compiler)
		if err != nil || !changed.Valid() || changed.Digest == p.Digest || changed.Arguments.CaptureBuffers != buffers || changed.Arguments.MaxBytesPerEvent != 256 || !slices.Contains(changed.Action.Sensitive, value.ReasonSyscallArguments) {
			t.Fatal("typed argument edits lost values, sensitivity or digest", err)
		}
		literal, _ := json.Marshal(buffers)
		if !bytes.Contains(changed.Scope, []byte(`"captureBuffers":`+string(literal))) {
			t.Fatal("explicit captureBuffers absent from scope")
		}
	}
}

func TestFiniteArgumentPolicyMechanismDigestAndRefusals(t *testing.T) {
	c := argumentCompositionFixture(t)
	base, err := CompilePolicyRecorder(c, &argumentCompilerFixture{})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*artifact.RecordingArguments){
		"program":     func(a *artifact.RecordingArguments) { a.ProgramDigest[0]++ },
		"definition":  func(a *artifact.RecordingArguments) { a.DefinitionDigest[0]++ },
		"fixed debit": func(a *artifact.RecordingArguments) { a.MaxProbeBytes = 256 },
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := CompilePolicyRecorder(c, &argumentCompilerFixture{mutate: mutate})
			if err != nil || changed.Digest == base.Digest {
				t.Fatal("mechanism change retained policy scope", err)
			}
		})
	}
	if _, err := CompilePolicyRecorder(c, &argumentCompilerFixture{mutate: func(a *artifact.RecordingArguments) { a.AccountingRule[0]++ }}); err == nil {
		t.Fatal("unknown accounting rule accepted")
	}
	if _, err := CompilePolicyRecorder(c, &fakeCompiler{}); err == nil {
		t.Fatal("packet compiler supplied arguments")
	}
	for name, edits := range map[string][]value.ProfileEdit{
		"ongoing":              {text("syscalls", "actionExecutionMode", "ongoing")},
		"history":              {text("syscalls", "syscallBefore", "1s")},
		"too long":             {text("syscalls", "syscallAfter", "61s")},
		"too short":            {text("syscalls", "syscallAfter", "500ms")},
		"unknown definition":   {{ActionID: "syscalls", Field: "syscallFilter", Syscalls: &value.SyscallSelection{Mode: "include", Names: []string{"execve"}}}},
		"read bound below ABI": {{ActionID: "syscalls", Field: "syscallArguments", SyscallArguments: &value.SyscallArgumentsEdit{MaxBytesPerEvent: 127, CaptureBuffers: true}}},
	} {
		t.Run(name, func(t *testing.T) {
			c := editableArgumentComposition(t)
			c.Components[0].Edits = edits
			if _, err := CompilePolicyRecorder(c, &policyArgumentCompiler{}); err == nil {
				t.Fatal("unqualified finite policy accepted")
			}
			if _, err := CompileOngoingPolicyRecorders(c, &policyArgumentCompiler{}); err == nil {
				t.Fatal("unqualified ongoing source accepted")
			}
		})
	}
}
