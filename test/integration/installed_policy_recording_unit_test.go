package integration

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	captureapp "asservat.local/asservat/internal/application/capture"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
)

// The real installed hub uses libpcap. This exact program is solely the offline
// compiler input for preflighting the authored request; no capture can use it.
// The fixture was emitted by the maintained libpcap dead-handle compiler; the
// libpcap-tagged test compares every instruction against a fresh compilation.
type installedPolicyRecordingFilters struct{}

func (installedPolicyRecordingFilters) CompileFilter(expression string) (value.CompiledFilter, error) {
	if expression != installedPolicyRecordingFilter {
		return value.CompiledFilter{}, value.ErrInvalid
	}
	raw, err := os.ReadFile("../../internal/adapters/pcap/testdata/finite-policy-ack-filter.json")
	if err != nil {
		return value.CompiledFilter{}, err
	}
	var fixture struct {
		Expression, Compiler string
		Filter               value.CompiledFilter
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		return value.CompiledFilter{}, err
	}
	if fixture.Expression != expression || !strings.HasPrefix(fixture.Compiler, "libpcap version 1.11.0 ") {
		return value.CompiledFilter{}, value.ErrInvalid
	}
	return fixture.Filter, nil
}

func TestInstalledPolicyRecordingAuthoredInputs(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	const uid = "11111111-1111-4111-8111-111111111111"
	input := installedPolicyRecordingGrantArguments(uid, "installed-policy-grant")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.ValidateInput("request_policy_grant", raw); err != nil {
		t.Fatal("real native grant request schema", err)
	}
	for _, name := range []string{"capture_id", "pod_uid", "scope", "authority", "requester", "result_access"} {
		changed := installedPolicyRecordingGrantArguments(uid, "closed-input")
		changed[name] = "invented"
		raw, _ = json.Marshal(changed)
		if wire.ValidateInput("request_policy_grant", raw) == nil {
			t.Fatal("request accepted caller-selected authority", name)
		}
	}
	raw, _ = json.Marshal(installedPolicyRecordingSpec(uid, "payments", "api"))
	compile := func(raw json.RawMessage) (value.PolicyRecorderConfiguration, error) {
		var composition contracts.CaptureComposition
		if err := json.Unmarshal(raw, &composition); err != nil {
			return value.PolicyRecorderConfiguration{}, err
		}
		in, err := conversion.CompositionFromWire(composition)
		if err != nil || in == nil {
			return value.PolicyRecorderConfiguration{}, value.ErrInvalid
		}
		return compiler.CompilePolicyRecorder(*in, installedPolicyRecordingFilters{})
	}
	plan, err := captureapp.CompilePolicyWithRecorders(raw, compiler.ContextRecipeName, compiler.RecipeDigest(), compile)
	if err != nil || plan.Recorder == nil || plan.Recorder.Action.ExecutionMode != "onTrigger" || plan.Recorder.Action.Before != "0s" || plan.Recorder.Action.After != "2s" || plan.Recorder.Action.Filter != installedPolicyRecordingFilter || plan.Recorder.Filter == nil {
		t.Fatal("native authored finite policy plan", err)
	}
	if err = packets.CheckPrefixProgram(plan.Recorder.Filter.Program); err != nil {
		t.Fatal("native reviewed program exceeds actual prefix", err)
	}
	// The public policy grant review derives its session ceiling from this
	// exact authored action timeout. A schema-valid larger request would still
	// be refused by RequestPolicy; catch it before an installed runner starts.
	timeout, err := time.ParseDuration(plan.Recorder.Action.Timeout)
	observation := input["observation_limits"].(map[string]any)
	if err != nil || int64(observation["max_session_seconds"].(int))*int64(time.Second) > int64(timeout) {
		t.Fatal("native grant exceeds original action review", observation, plan.Recorder.Action.Timeout, err)
	}
}

func TestInstalledPolicyRecordingNativeFieldProof(t *testing.T) {
	for _, item := range []struct {
		input  string
		count  int
		refuse bool
	}{
		{"1\t1\t\n", 1, false}, {"1\t1\t\n2\t1\t\n", 2, false}, {"", 0, false},
		{"1\t1\t616263\n", 0, true}, {"1\t0\t\n", 0, true}, {"1\t1\n", 0, true},
	} {
		got, err := policyRecordingPacketFields([]byte(item.input))
		if (err != nil) != item.refuse || got != item.count {
			t.Fatalf("native fields count=%d err=%v want=%d/refuse%v", got, err, item.count, item.refuse)
		}
	}
}
