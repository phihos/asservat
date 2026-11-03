package planning

import (
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func finiteArgumentPolicyFixture() PolicyRecorderConfiguration {
	return PolicyRecorderConfiguration{
		Composition:    ProfileComposition{Components: []ProfileComponent{{ID: "calls", Profile: ProfileRef{Catalog: "namespace", Name: "arguments", Version: "v1"}}}, MaxTotalBytes: 8 << 20, MaxDuration: "10s"},
		Profile:        ResolvedProfile{DefinitionDigest: artifact.Digest{1}},
		Action:         RecorderAction{Kind: "syscallTrace", SyscallMode: "arguments", ExecutionMode: "onTrigger", Before: "0s", After: "3s", Sensitive: []string{ReasonSyscallArguments}},
		Arguments:      &artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest{3}, MaxProbeBytes: 512, MaxBytesPerEvent: 128, MaxBytesPerSecond: SensitiveMaxBytesPerSecond},
		SyscallInclude: []string{"read", "write"}, Recipe: []byte("{}"), Scope: []byte("{}"), RecipeDigest: artifact.Digest{4}, Digest: artifact.Digest{5},
	}
}

func TestFiniteArgumentPolicyConfigurationRequiresMechanismAndFiniteLifecycle(t *testing.T) {
	if !finiteArgumentPolicyFixture().Valid() {
		t.Fatal("finite argument configuration refused")
	}
	for name, mutate := range map[string]func(*PolicyRecorderConfiguration){
		"missing mechanism":        func(p *PolicyRecorderConfiguration) { p.Arguments = nil },
		"missing engine":           func(p *PolicyRecorderConfiguration) { p.Arguments.ProgramDigest = artifact.Digest{} },
		"missing definitions":      func(p *PolicyRecorderConfiguration) { p.Arguments.DefinitionDigest = artifact.Digest{} },
		"missing accounting":       func(p *PolicyRecorderConfiguration) { p.Arguments.AccountingRule = artifact.Digest{} },
		"missing sensitive reason": func(p *PolicyRecorderConfiguration) { p.Action.Sensitive = nil },
		"packet mechanism":         func(p *PolicyRecorderConfiguration) { p.Filter = &CompiledFilter{} },
		"metadata mechanism":       func(p *PolicyRecorderConfiguration) { p.Action.SyscallMode = "metadata" },
		"ongoing":                  func(p *PolicyRecorderConfiguration) { p.Action.ExecutionMode = "ongoing" },
		"history":                  func(p *PolicyRecorderConfiguration) { p.Action.Before = "1s" },
		"short interval":           func(p *PolicyRecorderConfiguration) { p.Action.After = "500ms" },
		"long interval":            func(p *PolicyRecorderConfiguration) { p.Action.After = "61s" },
		"all syscalls":             func(p *PolicyRecorderConfiguration) { p.SyscallInclude = nil },
		"unsorted names":           func(p *PolicyRecorderConfiguration) { p.SyscallInclude = []string{"write", "read"} },
	} {
		t.Run(name, func(t *testing.T) {
			p := finiteArgumentPolicyFixture()
			mutate(&p)
			if p.Valid() {
				t.Fatal("invalid argument configuration accepted")
			}
		})
	}
	for _, after := range []string{"1s", "60s"} {
		p := finiteArgumentPolicyFixture()
		p.Action.After = after
		if !p.Valid() {
			t.Fatal("finite boundary refused", after)
		}
	}
}
