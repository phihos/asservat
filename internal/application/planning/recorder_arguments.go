package planning

import (
	"encoding/hex"
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/planning"
)

// ArgumentCompiler resolves the release's fixed ABI table and program pins.
// It performs no acquisition and is distinct from a caller's authored recipe.
// The bootstrap composition supplies it alongside the packet filter compiler.
type ArgumentCompiler interface {
	CompileArguments(names []string, captureBuffers bool, maxBytesPerEvent int64) (artifact.RecordingArguments, error)
}

type syscallArgumentParameters struct {
	MaxBytesPerEvent int64 `json:"maxBytesPerEvent"`
	CaptureBuffers   *bool `json:"captureBuffers"`
}

type argumentProgramRecord struct {
	ActionID          string   `json:"actionID"`
	Names             []string `json:"names"`
	ProgramDigest     string   `json:"programDigest"`
	DefinitionDigest  string   `json:"definitionDigest"`
	AccountingRule    string   `json:"accountingRule"`
	MaxProbeBytes     int64    `json:"maxProbeBytes"`
	MaxBytesPerEvent  int64    `json:"maxBytesPerEvent"`
	MaxBytesPerSecond int64    `json:"maxBytesPerSecond"`
	CaptureBuffers    bool     `json:"captureBuffers"`
}

func argumentRecord(actionID string, names []string, a artifact.RecordingArguments) argumentProgramRecord {
	return argumentProgramRecord{ActionID: actionID, Names: slices.Clone(names), ProgramDigest: hexDigest(a.ProgramDigest), DefinitionDigest: hexDigest(a.DefinitionDigest), AccountingRule: hexDigest(a.AccountingRule), MaxProbeBytes: a.MaxProbeBytes, MaxBytesPerEvent: a.MaxBytesPerEvent, MaxBytesPerSecond: a.MaxBytesPerSecond, CaptureBuffers: a.CaptureBuffers}
}
func (a argumentProgramRecord) mechanism() (artifact.RecordingArguments, error) {
	out := artifact.RecordingArguments{MaxProbeBytes: a.MaxProbeBytes, MaxBytesPerEvent: a.MaxBytesPerEvent, MaxBytesPerSecond: a.MaxBytesPerSecond, CaptureBuffers: a.CaptureBuffers}
	for _, p := range []struct {
		text string
		dst  *artifact.Digest
	}{{a.ProgramDigest, &out.ProgramDigest}, {a.DefinitionDigest, &out.DefinitionDigest}, {a.AccountingRule, &out.AccountingRule}} {
		b, err := hex.DecodeString(p.text)
		if err != nil || len(b) != 32 || hex.EncodeToString(b) != p.text {
			return artifact.RecordingArguments{}, value.ErrInvalid
		}
		copy(p.dst[:], b)
	}
	if !out.Valid() || out.AccountingRule != artifact.Digest(collector.ArgumentObservationAccountingRule()) {
		return artifact.RecordingArguments{}, value.ErrInvalid
	}
	return out, nil
}

func resolveArgumentProgram(path string, s *syscallParameters, compiler FilterCompiler) (artifact.RecordingArguments, error) {
	var zero artifact.RecordingArguments
	var p syscallArgumentParameters
	if s == nil || s.Mode != "arguments" || strict(s.Arguments, &p) != nil || p.CaptureBuffers == nil || p.MaxBytesPerEvent < 1 || p.MaxBytesPerEvent > 4096 {
		return zero, refuse(value.CompositionInvalid, path+".parameters.arguments", "argument tracing requires explicit captureBuffers and maxBytesPerEvent from 1 to 4096")
	}
	if s.Syscalls.Mode != "include" || len(s.Syscalls.Names) < 1 || len(s.Syscalls.Names) > 128 {
		return zero, refuse(value.CompositionRecorderUnavailable, path+".parameters.syscalls", "argument tracing needs an explicitly selected, qualified syscall include list")
	}
	names := slices.Clone(s.Syscalls.Names)
	slices.Sort(names)
	for i, n := range names {
		if !syscallName(n) || i > 0 && n == names[i-1] {
			return zero, refuse(value.CompositionInvalid, path+".parameters.syscalls.names", "syscall names must be unique identifiers")
		}
	}
	c, ok := compiler.(ArgumentCompiler)
	if !ok {
		return zero, refuse(value.CompositionRecorderUnavailable, path+".parameters.mode", "the installed compiler has no qualified syscall argument engine")
	}
	resolved, err := c.CompileArguments(slices.Clone(names), *p.CaptureBuffers, p.MaxBytesPerEvent)
	if err != nil || !resolved.Valid() || resolved.AccountingRule != artifact.Digest(collector.ArgumentObservationAccountingRule()) || resolved.CaptureBuffers != *p.CaptureBuffers || resolved.MaxBytesPerEvent != p.MaxBytesPerEvent || resolved.MaxBytesPerSecond != value.SensitiveMaxBytesPerSecond {
		return zero, refuse(value.CompositionRecorderUnavailable, path+".parameters.syscalls", "the selected syscall names and argument bounds are unsupported by the qualified engine")
	}
	s.Syscalls.Names = names
	return resolved, nil
}

// frozenRecorderCompiler reconstructs only the originally reviewed mechanism.
// It cannot qualify a changed name set or expand argument reads during replay.
type frozenRecorderCompiler struct{ context *value.RecorderContext }

func (c frozenRecorderCompiler) CompileFilter(expression string) (value.CompiledFilter, error) {
	return frozenFilters(c.context.Filters).CompileFilter(expression)
}
func (c frozenRecorderCompiler) CompileArguments(names []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	for _, a := range c.context.Arguments {
		if slices.Equal(a.Names, names) && a.Mechanism.CaptureBuffers == buffers && a.Mechanism.MaxBytesPerEvent == maximum {
			return a.Mechanism, nil
		}
	}
	return artifact.RecordingArguments{}, value.ErrInvalid
}
func frozenArgumentFor(scope recorderScope, actionID string, params syscallParameters) (artifact.RecordingArguments, error) {
	if len(scope.ArgumentPrograms) != 1 || scope.ArgumentPrograms[0].ActionID != actionID {
		return artifact.RecordingArguments{}, value.ErrInvalid
	}
	a := scope.ArgumentPrograms[0]
	mechanism, err := a.mechanism()
	if err != nil {
		return artifact.RecordingArguments{}, err
	}
	context := value.RecorderContext{Arguments: []value.CompiledArguments{{Names: slices.Clone(a.Names), Mechanism: mechanism}}}
	return resolveArgumentProgram("action", &params, frozenRecorderCompiler{&context})
}
