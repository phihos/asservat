package artifact

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRecordingArgumentsKeepMechanismPinsAndLegacyEncoding(t *testing.T) {
	legacy := Recording{Kind: "syscallTrace", Profile: "metadata", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: 64 << 10, Snaplen: RecordingSyscallSnaplen, Syscalls: &RecordingSyscalls{Names: []string{"openat"}, MaxEvents: 1000, MaxEventsPerSecond: 100, MaxTrackedThreads: 64}}
	raw, _ := json.Marshal(legacy)
	if !legacy.Valid() || bytes.Contains(raw, []byte("Arguments")) {
		t.Fatal("legacy syscall encoding changed")
	}
	arguments := legacy
	arguments.Profile = "arguments"
	arguments.Snaplen = 0
	arguments.Arguments = &RecordingArguments{ProgramDigest: Digest{1}, DefinitionDigest: Digest{2}, AccountingRule: Digest{3}, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxBytesPerSecond: 51200}
	if !arguments.Valid() {
		t.Fatal("pinned argument recording refused")
	}
	for _, mode := range []string{"missing", "program", "definition", "rule", "probe", "width", "rate", "packet", "metadata", "snaplen", "all"} {
		t.Run(mode, func(t *testing.T) {
			r := arguments.Clone()
			switch mode {
			case "missing":
				r.Arguments = nil
			case "program":
				r.Arguments.ProgramDigest = Digest{}
			case "definition":
				r.Arguments.DefinitionDigest = Digest{}
			case "rule":
				r.Arguments.AccountingRule = Digest{}
			case "probe":
				r.Arguments.MaxProbeBytes = 1
			case "width":
				r.Arguments.MaxBytesPerEvent = 127
			case "rate":
				r.Arguments.MaxBytesPerSecond = 511
			case "packet":
				r.Kind = "packetCapture"
			case "metadata":
				r.Profile = "metadata"
			case "snaplen":
				r.Snaplen = 32
			case "all":
				r.Syscalls.Names = nil
			}
			if r.Valid() {
				t.Fatal("incoherent argument tuple accepted")
			}
		})
	}
	cloned := arguments.Clone()
	cloned.Arguments.DefinitionDigest[0]++
	if cloned.Arguments.DefinitionDigest == arguments.Arguments.DefinitionDigest {
		t.Fatal("clone shares argument pins")
	}
	typ, ok := LookupNativeType(SyscallArgumentsArtifact)
	if !ok || !typ.AllowsClass("raw") || typ.AllowsClass("metadata") || typ.Format == SyscallRecordsFormat {
		t.Fatal("raw arguments alias metadata format")
	}
}

func TestArgumentExpectationRequiresExactRawRecordingTuple(t *testing.T) {
	e := typedExpectation(t, SyscallArgumentsArtifact, RecordingNativeLimit)
	e.ExecutionClass, e.DataClass = ContextAPIExecution, "raw"
	e.NodeUID, e.NodeBootID = "", ""
	e.Recording = &Recording{Kind: "syscallTrace", Profile: "arguments", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: 64 << 10, Syscalls: &RecordingSyscalls{Names: []string{"close"}, MaxEvents: 1000, MaxEventsPerSecond: 100, MaxTrackedThreads: 64}, Arguments: &RecordingArguments{ProgramDigest: Digest{1}, DefinitionDigest: Digest{2}, AccountingRule: Digest{3}, MaxProbeBytes: 256, MaxBytesPerEvent: 1, MaxBytesPerSecond: 25600}}
	if err := e.Validate(); err != nil {
		t.Fatal("raw argument expectation", err)
	}
	for _, mode := range []string{"metadata class", "metadata type", "packet type", "no recording", "metadata profile", "missing pins"} {
		t.Run(mode, func(t *testing.T) {
			x := e
			x.Recording = e.Recording.Clone()
			switch mode {
			case "metadata class":
				x.DataClass = "metadata"
			case "metadata type":
				x.NativeType = SyscallRecordsArtifact
			case "packet type":
				x.NativeType = RawPCAPNGArtifact
			case "no recording":
				x.Recording = nil
			case "metadata profile":
				x.Recording.Profile = "metadata"
			case "missing pins":
				x.Recording.Arguments = nil
			}
			if x.Validate() == nil {
				t.Fatal("incoherent raw argument expectation accepted")
			}
		})
	}
}
