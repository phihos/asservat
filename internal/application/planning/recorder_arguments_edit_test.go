package planning

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

func editableArgumentComposition(t *testing.T) value.ProfileComposition {
	t.Helper()
	c := argumentCompositionFixture(t)
	var doc map[string]any
	if err := json.Unmarshal(c.Resolved[0].Document, &doc); err != nil {
		t.Fatal(err)
	}
	d := doc["definition"].(map[string]any)
	d["editableFields"] = append(d["editableFields"].([]any), map[string]any{"actionID": "syscalls", "field": "syscallArguments", "label": "Argument reads"})
	var err error
	c.Resolved[0].Document, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSyscallArgumentsEditReviewedAndFrozenRoundtrip(t *testing.T) {
	c := editableArgumentComposition(t)
	in, now := recorderInput(t, c, "syscallTrace")
	original, err := CompileRecorder(in, &argumentCompilerFixture{}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, buffers := range []bool{false, true} {
		c := c.Clone()
		c.Components[0].Edits = []value.ProfileEdit{{ActionID: "syscalls", Field: "syscallArguments", SyscallArguments: &value.SyscallArgumentsEdit{MaxBytesPerEvent: 256, CaptureBuffers: buffers}}}
		in.Composition = *c
		p, err := CompileRecorder(in, &argumentCompilerFixture{}, now)
		if err != nil {
			t.Fatal(err)
		}
		if p.ScopeDigest == original.ScopeDigest || p.Approval == nil || p.Approval.DataClass != "raw" || p.Approval.ObservationLimits == nil || !ManualObservationIssued(p.Actions, p.Approval) {
			t.Fatal("argument edit reused old approval scope or lost observation limits")
		}
		r, _, err := RecordingFor(p)
		if err != nil || r.Arguments == nil || r.Arguments.MaxBytesPerEvent != 256 || r.Arguments.CaptureBuffers != buffers || r.Arguments.ProgramDigest != (artifact.Digest{1}) || r.Arguments.DefinitionDigest != (artifact.Digest{2}) {
			t.Fatal("edited mechanism lost", r.Arguments, err)
		}
		provenance, err := CompositionProvenance(p)
		var wire wireProvenance
		if err != nil || json.Unmarshal(provenance, &wire) != nil {
			t.Fatal("invalid authored provenance", err)
		}
		got := wire.Authored.Components[0].Overrides[0].Value.(map[string]any)
		if len(got) != 2 || got["maxBytesPerEvent"] != float64(256) || got["captureBuffers"] != buffers {
			t.Fatal("literal argument provenance changed", got)
		}
		restored, err := RecorderContextFor(&r)
		if err != nil {
			t.Fatal(err)
		}
		restored.Composition.Resolved = c.Resolved
		in.Composition = restored.Composition
		replay, err := CompileRecorder(in, frozenRecorderCompiler{restored}, now)
		if err != nil || replay.ScopeDigest != p.ScopeDigest || replay.RecipeDigest != p.RecipeDigest {
			t.Fatal("frozen edit changed approved plan", err)
		}
		in.Composition = *in.Composition.Clone()
		in.Composition.Components[0].Edits[0].SyscallArguments.CaptureBuffers = !buffers
		if _, err := CompileRecorder(in, frozenRecorderCompiler{restored}, now); err == nil {
			t.Fatal("frozen mechanism accepted changed argument read")
		}
	}
}

type unsupportedArgumentEditCompiler struct{ fakeCompiler }

func (unsupportedArgumentEditCompiler) CompileArguments([]string, bool, int64) (artifact.RecordingArguments, error) {
	return artifact.RecordingArguments{}, value.ErrInvalid
}

func TestSyscallArgumentsEditRefusesUnexposedAndUnsupported(t *testing.T) {
	edit := value.ProfileEdit{ActionID: "syscalls", Field: "syscallArguments", SyscallArguments: &value.SyscallArgumentsEdit{MaxBytesPerEvent: 128, CaptureBuffers: false}}
	c := argumentCompositionFixture(t)
	c.Components[0].Edits = []value.ProfileEdit{edit}
	in, now := recorderInput(t, c, "syscallTrace")
	if _, err := CompileRecorder(in, &argumentCompilerFixture{}, now); err == nil {
		t.Fatal("unexposed argument field accepted")
	}
	c = editableArgumentComposition(t)
	c.Components[0].Edits = []value.ProfileEdit{edit}
	in.Composition = c
	if _, err := CompileRecorder(in, &unsupportedArgumentEditCompiler{}, now); err == nil {
		t.Fatal("typed argument edit bypassed unsupported decoder")
	}
	in.Composition.Components[0].Edits = []value.ProfileEdit{{ActionID: "syscalls", Field: "syscallArguments", Text: "caller expression"}}
	if _, err := CompileRecorder(in, &argumentCompilerFixture{}, now); err == nil {
		t.Fatal("argument edit accepted wrong value type")
	}
}
