package planning

import (
	"encoding/json"
	"slices"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/planning"
)

type argumentCompilerFixture struct {
	fakeCompiler
	calls  int
	names  []string
	mutate func(*artifact.RecordingArguments)
}

func (c *argumentCompilerFixture) CompileArguments(names []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	c.calls++
	c.names = slices.Clone(names)
	out := artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: 512, MaxBytesPerEvent: maximum, MaxBytesPerSecond: value.SensitiveMaxBytesPerSecond, CaptureBuffers: buffers}
	if c.mutate != nil {
		c.mutate(&out)
	}
	return out, nil
}
func argumentParametersFixture() syscallParameters {
	return syscallParameters{Mode: "arguments", Syscalls: syscallSelection{Mode: "include", Names: []string{"write", "read"}}, Arguments: json.RawMessage(`{"maxBytesPerEvent":128,"captureBuffers":false}`)}
}
func TestArgumentCompilationUsesIndependentClosedMechanism(t *testing.T) {
	p := argumentParametersFixture()
	c := &argumentCompilerFixture{}
	got, err := resolveArgumentProgram("action", &p, c)
	if err != nil || !got.Valid() || got.CaptureBuffers || c.calls != 1 || !slices.Equal(c.names, []string{"read", "write"}) {
		t.Fatal(got, err, c.names)
	}
	if _, err = resolveArgumentProgram("action", &p, &fakeCompiler{}); err == nil {
		t.Fatal("packet-only compiler claimed argument support")
	}
	for name, mutate := range map[string]func(*syscallParameters){
		"implicit buffers": func(p *syscallParameters) { p.Arguments = json.RawMessage(`{"maxBytesPerEvent":128}`) },
		"null buffers": func(p *syscallParameters) {
			p.Arguments = json.RawMessage(`{"maxBytesPerEvent":128,"captureBuffers":null}`)
		},
		"zero bound": func(p *syscallParameters) {
			p.Arguments = json.RawMessage(`{"maxBytesPerEvent":0,"captureBuffers":false}`)
		},
		"unknown argument": func(p *syscallParameters) {
			p.Arguments = json.RawMessage(`{"maxBytesPerEvent":128,"captureBuffers":false,"pointer":"x"}`)
		},
		"all syscalls":   func(p *syscallParameters) { p.Syscalls.Mode = "all" },
		"duplicate name": func(p *syscallParameters) { p.Syscalls.Names = []string{"read", "read"} },
	} {
		t.Run(name, func(t *testing.T) {
			p := argumentParametersFixture()
			mutate(&p)
			c := &argumentCompilerFixture{}
			if _, err := resolveArgumentProgram("action", &p, c); err == nil || c.calls != 0 {
				t.Fatal("malformed authored input reached mechanism compiler", err, c.calls)
			}
		})
	}
	for name, mutate := range map[string]func(*artifact.RecordingArguments){
		"unbound program":     func(a *artifact.RecordingArguments) { a.ProgramDigest = artifact.Digest{} },
		"unbound definitions": func(a *artifact.RecordingArguments) { a.DefinitionDigest = artifact.Digest{} },
		"packet accounting": func(a *artifact.RecordingArguments) {
			a.AccountingRule = artifact.Digest(collector.ObservationAccountingRule())
		},
		"larger reads":     func(a *artifact.RecordingArguments) { a.MaxBytesPerEvent = 4096 },
		"buffers enabled":  func(a *artifact.RecordingArguments) { a.CaptureBuffers = true },
		"larger byte rate": func(a *artifact.RecordingArguments) { a.MaxBytesPerSecond++ },
	} {
		t.Run(name, func(t *testing.T) {
			p := argumentParametersFixture()
			c := &argumentCompilerFixture{mutate: mutate}
			if _, err := resolveArgumentProgram("action", &p, c); err == nil {
				t.Fatal("mismatched mechanism accepted")
			}
		})
	}
}

func argumentCompositionFixture(t *testing.T) value.ProfileComposition {
	t.Helper()
	raw, err := builtinFiles.ReadFile("profiles/syscall-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"] = "argument-capture"
	a := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	a["impact"], a["executionMode"] = "sensitiveRead", "onTrigger"
	p := a["parameters"].(map[string]any)
	p["mode"], p["before"], p["after"] = "arguments", "0s", "3s"
	p["syscalls"] = map[string]any{"mode": "include", "names": []string{"write", "read"}}
	p["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	c := syscalls()
	c.Components[0].Profile = value.ProfileRef{Catalog: "namespace", Name: "argument-capture", Version: "v1"}
	c.Resolved = []value.CatalogProfile{{Ref: c.Components[0].Profile, SourceClusterID: "00000000-0000-4000-8000-000000000001", SourceNamespaceUID: "ns-uid", SourceUID: "argument-profile-uid", Document: raw, Enabled: true}}
	return c
}
func TestArgumentRecorderPlanPinsReviewedMechanismAndEventPool(t *testing.T) {
	in, now := recorderInput(t, argumentCompositionFixture(t), "syscallTrace")
	compiler := &argumentCompilerFixture{}
	p, err := CompileRecorder(in, compiler, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Approval == nil || p.Approval.DataClass != "raw" || p.Approval.ObservationLimits == nil || p.Approval.ObservationLimits.MaxObservedEvents != 40000 || !ManualObservationIssued(p.Actions, p.Approval) {
		t.Fatal("missing cumulative reviewed event authority", p.Approval)
	}
	if !AcceptableRecorder(p).Acceptable() {
		t.Fatal(AcceptableRecorder(p))
	}
	r, _, err := RecordingFor(p)
	if err != nil || r.Arguments == nil || r.Profile != "arguments" || r.Snaplen != 0 || r.Arguments.MaxBytesPerEvent != 128 {
		t.Fatal("argument mechanism lost during acceptance", r, err)
	}
	if !slices.Equal(r.Syscalls.Names, []string{"read", "write"}) {
		t.Fatal(r.Syscalls.Names)
	}
	frozen, err := RecorderContextFromScope(in.Composition, p.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := CompileRecorder(in, frozenRecorderCompiler{frozen}, now)
	if err != nil || replay.ScopeDigest != p.ScopeDigest {
		t.Fatal("frozen argument scope changed", err)
	}
	restored, err := RecorderContextFor(&r)
	if err != nil {
		t.Fatal(err)
	}
	replay, err = CompileRecorder(in, frozenRecorderCompiler{restored}, now)
	if err != nil || replay.ScopeDigest != p.ScopeDigest {
		t.Fatal("accepted recording lost original argument pins", err)
	}
	copy := frozen.Clone()
	copy.Arguments[0].Names[0] = "close"
	if frozen.Arguments[0].Names[0] != "read" {
		t.Fatal("clone aliases original argument selection")
	}
	if _, err = CompileRecorder(in, frozenRecorderCompiler{copy}, now); err == nil {
		t.Fatal("changed selection reconstructed original mechanism")
	}
	changed := &argumentCompilerFixture{mutate: func(a *artifact.RecordingArguments) { a.ProgramDigest[0]++ }}
	other, err := CompileRecorder(in, changed, now)
	if err != nil || other.ScopeDigest == p.ScopeDigest {
		t.Fatal("review scope failed to pin exact engine", err)
	}
	if _, err = CompileRecorder(in, &fakeCompiler{}, now); err == nil {
		t.Fatal("unqualified compiler enabled arguments")
	}
}
