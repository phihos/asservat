package bootstrap

import (
	"bytes"
	"encoding/json"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
)

// The shared public compiler is compared once with the accepted-source reader.
// It exercises inert canonical compilation only, not accepted authority or an
// installed recorder. Assembly ownership tests must retain these same bindings.
func TestOngoingPolicyCompilerParityAcrossPublicConsumers(t *testing.T) {
	for _, tc := range []struct{ name, mode, before string }{
		{"default-ongoing", "", ""},
		{"explicit-ongoing-zero-history", "ongoing", "0s"},
		{"explicit-ongoing-retained-history", "ongoing", "2s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := ongoingCompilerComposition(t, tc.mode, tc.before)
			current, err := recordingSavePolicyCompiler(ongoingCompilerFilters{})(raw)
			if err != nil || current.Action.ExecutionMode != "ongoing" {
				t.Fatal("private original-source compiler", err)
			}
			got, err := publicPolicyRecorderCompiler(ongoingCompilerFilters{})(raw)
			if err != nil {
				t.Fatal("public lifecycle compiler refused accepted ongoing definition", err)
			}
			if got.Action.ExecutionMode != "ongoing" || got.Digest != current.Digest || got.RecipeDigest != current.RecipeDigest || !bytes.Equal(got.Scope, current.Scope) || !bytes.Equal(got.Recipe, current.Recipe) {
				t.Fatal("compiler changed original ongoing collection intent")
			}

		})
	}
}

func TestExplicitFinitePolicyCompilerScopeRemainsUnchanged(t *testing.T) {
	raw := ongoingCompilerComposition(t, "onTrigger", "0s")
	finite, err := publicPolicyRecorderCompiler(ongoingCompilerFilters{})(raw)
	if err != nil || finite.Action.ExecutionMode != "onTrigger" {
		t.Fatal("explicit finite compilation", err)
	}
	var wire contracts.CaptureComposition
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	composition, err := conversion.CompositionFromWire(wire)
	if err != nil || composition == nil {
		t.Fatal(err)
	}
	original, err := planningapp.CompilePolicyRecorder(*composition, ongoingCompilerFilters{})
	if err != nil || original.Digest != finite.Digest || original.RecipeDigest != finite.RecipeDigest || !bytes.Equal(original.Scope, finite.Scope) || !bytes.Equal(original.Recipe, finite.Recipe) {
		t.Fatal("candidate changed original finite compiler bytes", err)
	}
	reader, err := recordingSavePolicyCompiler(ongoingCompilerFilters{})(raw)
	if err != nil || reader.Digest != finite.Digest || reader.RecipeDigest != finite.RecipeDigest || !bytes.Equal(reader.Scope, finite.Scope) || !bytes.Equal(reader.Recipe, finite.Recipe) {
		t.Fatal("source-capable compiler reinterpreted finite accepted scope", err)
	}
	ongoing, err := recordingSavePolicyCompiler(ongoingCompilerFilters{})(ongoingCompilerComposition(t, "ongoing", "0s"))
	if err != nil || ongoing.Digest == finite.Digest || bytes.Equal(ongoing.Scope, finite.Scope) {
		t.Fatal("lifecycle change reused original acceptance digest", err)
	}
}

func TestIncompleteOngoingCompositionCannotEnableSave(t *testing.T) {
	for _, collection := range []bool{false, true} {
		c, s := publicContextOperationFixture(t)
		c.CollectionEnabled = collection
		// Passive inventory alone and a conflicting nested value are not the trusted
		// packet-source service composition. Existing complete refusal tests remain.
		s.Recordings = &captureapp.RecordingSaves{Investigation: captureapp.ContextInvestigation{RecordingSaveEnabled: true}}
		got, err := composePublicContextUseCases(c, s)
		if err != nil || got.submission.RecordingSaveEnabled {
			t.Fatal("incomplete source composition enabled Save", collection, err)
		}
		if !s.Recordings.Investigation.RecordingSaveEnabled || s.Investigation.RecordingSaveEnabled {
			t.Fatal("composition mutated caller values")
		}
	}
}

func ongoingCompilerComposition(t *testing.T, mode, before string) json.RawMessage {
	t.Helper()
	edits := []any{
		map[string]any{"actionID": "sample", "field": "packetAfter", "value": "2s"},
		map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
		map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 80"},
	}
	if mode != "" {
		edits = append(edits, map[string]any{"actionID": "sample", "field": "actionExecutionMode", "value": mode})
	}
	if before != "" {
		edits = append(edits, map[string]any{"actionID": "sample", "field": "packetBefore", "value": before})
	}
	raw, err := json.Marshal(map[string]any{"components": []any{map[string]any{"id": "network", "profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"}, "overrides": edits}}, "maxTotalBytes": 16 << 20, "maxDuration": "20s"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Inert valid BPF fixture; it performs no device/network/provider operation.
type ongoingCompilerFilters struct{}

func (ongoingCompilerFilters) CompileFilter(string) (value.CompiledFilter, error) {
	return value.CompiledFilter{LinkType: value.FilterLinkType, Snaplen: value.FilterSnaplen, Program: []value.BPFInstruction{{Code: 0x28, K: 12}, {Code: 0x15, Jf: 1, K: 0x800}, {Code: 0x6, K: 65535}, {Code: 0x6}}}, nil
}

// These inert assembly handles panic if any constructor unexpectedly performs
// source observation, admission, dispatch or another authority/provider effect.
type ongoingCandidatePort interface{ captureapp.RecordingCandidates }

type ongoingCompositionPorts struct {
	*publicContextOperationPorts
	captureapp.PolicySourceLedger
	captureapp.PolicySourceDispatcher
	captureapp.OngoingRecorderObserver
	captureapp.RestartObserver
	captureapp.SourceSnapshotTargets
	captureapp.SourceSnapshotGroupTargets
	captureapp.ApprovalSettings
	captureapp.RecordingPolicies
	ongoingCandidatePort
	captureapp.RecordingSaveGroupAdmissions
	authapp.AcceptedPolicyReader
}

func TestTrustedOngoingCompositionBindsRuntimeAndSaveWithoutEffects(t *testing.T) {
	c, s := publicContextOperationFixture(t)
	ports := &ongoingCompositionPorts{publicContextOperationPorts: s.Investigation.Targets.(*publicContextOperationPorts)}
	s.Investigation.Targets = ports
	s.Investigation.RecordingPolicies, s.Investigation.PolicyAccepted = ports, ports
	s.Investigation.RecordingSources, s.Investigation.RecordingGroups, s.Investigation.Approvals = ports, ports, ports
	runtime := &captureapp.PolicySourceRuntime{Ledger: ports, Dispatcher: ports, Observer: ports, Recovery: s.Investigation.Recovery, Retention: s.Investigation.Retention, Settings: ports, Now: c.Now, NewID: c.NewID}
	s.ongoingSources = runtime
	got, err := composePublicContextUseCases(c, s)
	if err != nil || !got.submission.RecordingSaveEnabled || got.submission.Targets != ports || s.Investigation.RecordingSaveEnabled {
		t.Fatal("trusted source composition lost original ports or mutated input", err)
	}
	// Actual policy assembly must reuse this exact runtime, not create a second
	// reconciler. SQL/Kube handles below are inert constructor inputs only.
	pc := &publicContext{policies: &postgres.Policies{}, policyTriggers: &postgres.PolicyTriggers{}, automation: &postgres.AutomationAuthorities{}, hubPolicies: &kube.HubPolicySources{}, permissions: &postgres.Permissions{}, investigation: s.Investigation}
	pc.investigation.Filters = ongoingCompilerFilters{}
	operations, trigger, err := composePublicPolicies(c, s, pc)
	if err != nil || operations == nil || trigger.OngoingSources != runtime {
		t.Fatal("policy assembly replaced/missed shared source runtime", err)
	}
	snapshots, ok := trigger.SourceSnapshots.(captureapp.ContextSubmission)
	if !ok || !snapshots.RecordingSaveEnabled || snapshots.Targets != ports || snapshots.Admission != s.Investigation.Admission {
		t.Fatal("ongoing incident path omitted the original typed source snapshot submission")
	}
	regional, ok := snapshots.Start.(RegionalAPIContextStart)
	if !ok || regional.Router != s.Regional.Router || regional.Runner.Read != s.Regional.Runner.Read {
		t.Fatal("source incident replaced real admitted runner")
	}
	raw := ongoingCompilerComposition(t, "ongoing", "0s")
	actual, err := trigger.CompileRecorder(raw)
	expected, readerErr := recordingSavePolicyCompiler(ongoingCompilerFilters{})(raw)
	if err != nil || readerErr != nil || actual.Digest != expected.Digest || !bytes.Equal(actual.Scope, expected.Scope) {
		t.Fatal("actual trigger compiler diverged from source reader", err, readerErr)
	}
	disabled := c
	disabled.CollectionEnabled = false
	_, stopped, err := composePublicPolicies(disabled, s, pc)
	if err != nil || stopped.OngoingSources != nil || stopped.SourceSnapshots != nil {
		t.Fatal("disabled policy assembly acquired source runtime", err)
	}
	for _, item := range []struct {
		name   string
		mutate func(*PublicContextOperationsConfig, *PublicContextOperationServices)
	}{
		{"disabled", func(c *PublicContextOperationsConfig, s *PublicContextOperationServices) { c.CollectionEnabled = false }},
		{"no-runtime", func(c *PublicContextOperationsConfig, s *PublicContextOperationServices) { s.ongoingSources = nil }},
		{"no-source-reader", func(c *PublicContextOperationsConfig, s *PublicContextOperationServices) {
			s.Investigation.RecordingSources = nil
		}},
		{"no-admission", func(c *PublicContextOperationsConfig, s *PublicContextOperationServices) {
			s.Investigation.RecordingGroups = nil
		}},
		{"no-policy", func(c *PublicContextOperationsConfig, s *PublicContextOperationServices) {
			s.Investigation.PolicyAccepted = nil
		}},
		{"no-settings", func(c *PublicContextOperationsConfig, s *PublicContextOperationServices) {
			s.Investigation.Approvals = nil
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			copyC, copyS := c, s
			item.mutate(&copyC, &copyS)
			v, err := composePublicContextUseCases(copyC, copyS)
			if err != nil || v.submission.RecordingSaveEnabled {
				t.Fatal("incomplete acquisition composition enabled", err)
			}
		})
	}
	// A partial runtime is not readiness, even if all passive Save ports exist.
	partial := *runtime
	partial.Dispatcher = nil
	s.ongoingSources = &partial
	if packetSourceCompositionReady(c, s) {
		t.Fatal("missing source dispatch enabled acquisition")
	}
}
