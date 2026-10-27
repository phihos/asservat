package planning

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"sigs.k8s.io/yaml"
)

// fakeCompiler stands in for the libpcap adapter (tested under the libpcap
// build tag). It returns a fixed program and records what it compiled.
type fakeCompiler struct {
	program  []value.BPFInstruction
	err      error
	linkType string
	compiled []string
}

func (c *fakeCompiler) CompileFilter(expression string) (value.CompiledFilter, error) {
	c.compiled = append(c.compiled, expression)
	if c.err != nil {
		return value.CompiledFilter{}, c.err
	}
	link := value.FilterLinkType
	if c.linkType != "" {
		link = c.linkType
	}
	return value.CompiledFilter{LinkType: link, Snaplen: value.FilterSnaplen, Program: c.program}, nil
}

var fixtureProgram = []value.BPFInstruction{{Code: 0x28, K: 12}, {Code: 0x15, Jf: 1, K: 0x800}, {Code: 0x6, K: 65535}, {Code: 0x6}}

func network(edits ...value.ProfileEdit) value.ProfileComposition {
	return value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: value.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: edits}}, MaxTotalBytes: 16 << 20, MaxDuration: "20s"}
}

func syscalls(edits ...value.ProfileEdit) value.ProfileComposition {
	return value.ProfileComposition{Components: []value.ProfileComponent{{ID: "calls", Profile: value.ProfileRef{Catalog: "builtin", Name: "syscall-activity", Version: "v1"}, Edits: edits}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
}

func text(action, field, v string) value.ProfileEdit {
	return value.ProfileEdit{ActionID: action, Field: field, Text: v}
}

func recorderInput(t *testing.T, c value.ProfileComposition, evidence string) (value.RecorderInput, time.Time) {
	t.Helper()
	in, now := contextInput(t)
	r, err := privacy.Resolve(privacy.PolicySet{Target: in.Target.Target(), Revision: identity.Revision{UID: "policy-set", Generation: 1, Digest: [32]byte{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "baseline", Generation: 1, Digest: [32]byte{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: in.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidence, AnchorAt: now}, now)
	if err != nil {
		t.Fatal(err)
	}
	return value.RecorderInput{CaptureID: in.CaptureID, Executor: in.Executor, Target: in.Target, Composition: c, Retention: r, Deadline: in.Deadline}, now
}

func refusal(t *testing.T, err error, code, path string) {
	t.Helper()
	var e value.CompositionError
	if !errors.As(err, &e) || e.Code != code || !strings.HasPrefix(e.Path, path) {
		t.Fatalf("got %v, want %s at %s", err, code, path)
	}
}

func TestBuiltinProfilesMatchExampleDefinitions(t *testing.T) {
	for _, name := range builtinNames {
		b, err := os.ReadFile("../../../examples/capture-profile-" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Metadata struct{ Namespace string }
			Spec     struct {
				Name, Version string
				Definition    json.RawMessage
			}
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(map[string]any{"name": doc.Spec.Name, "version": doc.Spec.Version, "definition": doc.Spec.Definition})
		_, digest, err := canonical(want)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := BuiltinProfileDigest(name)
		if !ok || got != digest {
			t.Fatalf("%s: embedded definition differs from examples/capture-profile-%s.yaml", name, name)
		}
	}
}

// The normalization matrix of plan row 1: execution-mode defaults, the
// onTrigger before:0s rule, exposure, duplicates and whole-plan bounds.
func TestCompositionNormalizationMatrix(t *testing.T) {
	c := &fakeCompiler{program: fixtureProgram}
	ringValue := func(maxAge string, maxBytes, segment int64, segments int, medium string) value.ProfileEdit {
		return value.ProfileEdit{ActionID: "sample", Field: "packetRing", Ring: &value.RingSettings{MaxAge: maxAge, MaxBytes: maxBytes, SegmentBytes: segment, MaxSegments: segments, Medium: medium}}
	}
	for name, tc := range map[string]struct {
		composition value.ProfileComposition
		code, path  string
	}{
		"onTrigger keeps history":        {network(text("sample", "actionExecutionMode", "onTrigger")), value.CompositionInvalid, "profile_composition.components[0] action sample.parameters.before"},
		"onTrigger without after":        {network(text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s"), text("sample", "packetAfter", "0s")), value.CompositionInvalid, "profile_composition.components[0] action sample.parameters.after"},
		"no window":                      {network(text("sample", "packetBefore", "0s"), text("sample", "packetAfter", "0s")), value.CompositionInvalid, "profile_composition.components[0] action sample.parameters"},
		"unknown mode":                   {network(text("sample", "actionExecutionMode", "periodic")), value.CompositionInvalid, "profile_composition.components[0] action sample.executionMode"},
		"history beyond ring":            {network(text("sample", "packetBefore", "31s")), value.CompositionInvalid, "profile_composition.components[0] action sample.parameters.ring.maxAge"},
		"segments exceed ring":           {network(ringValue("30s", 16<<20, 8<<20, 4, "memory")), value.CompositionInvalid, "profile_composition.components[0] action sample.parameters.ring.segmentBytes"},
		"ring over 256 MiB":              {network(ringValue("30s", 512<<20, 4<<20, 4, "memory")), value.CompositionInvalid, "profile_composition.components[0] action sample.parameters.ring.maxBytes"},
		"ring age over an hour":          {network(ringValue("2h", 16<<20, 4<<20, 4, "memory")), value.CompositionInvalid, "profile_composition.components[0] action sample.parameters.ring.maxAge"},
		"encrypted disk":                 {network(ringValue("30s", 16<<20, 4<<20, 4, "encryptedDisk")), value.CompositionInvalid, "profile_composition.components[0] action sample.parameters.ring.medium"},
		"timeout without margin":         {network(text("sample", "packetAfter", "12s")), value.CompositionInvalid, "profile_composition.components[0] action sample.limits.timeout"},
		"duration below timeout":         {network(text("sample", "actionTimeout", "25s")), value.CompositionInvalid, "profile_composition.maxDuration"},
		"unexposed field":                {network(value.ProfileEdit{ActionID: "sample", Field: "actionMaxBytes", Number: 1}), value.CompositionInvalid, "profile_composition.components[0].overrides[0].field"},
		"unknown action":                 {network(text("missing", "packetFilter", "tcp")), value.CompositionInvalid, "profile_composition.components[0].overrides[0].actionID"},
		"duplicate edit":                 {network(text("sample", "packetAfter", "5s"), text("sample", "packetAfter", "6s")), value.CompositionInvalid, "profile_composition.components[0].overrides[1]"},
		"peers not yet":                  {network(value.ProfileEdit{ActionID: "sample", Field: "packetPeers", Unmodeled: true}), value.CompositionInvalid, "profile_composition.components[0].overrides[0]"},
		"wrong value type":               {network(value.ProfileEdit{ActionID: "sample", Field: "packetBefore", Number: 3}), value.CompositionInvalid, "profile_composition.components[0].overrides[0]"},
		"syscall mode not exposed":       {syscalls(text("syscalls", "syscallMode", "arguments")), value.CompositionInvalid, "profile_composition.components[0].overrides[0].field"},
		"syscall after over 60s":         {syscalls(text("syscalls", "syscallAfter", "61s"), text("syscalls", "actionTimeout", "70s")), value.CompositionInvalid, "profile_composition.components[0] action syscalls.parameters.after"},
		"duplicate syscall names":        {syscalls(value.ProfileEdit{ActionID: "syscalls", Field: "syscallFilter", Syscalls: &value.SyscallSelection{Mode: "include", Names: []string{"write", "write"}}}), value.CompositionInvalid, "profile_composition.components[0] action syscalls.parameters.syscalls.names"},
		"syscall rate over bound":        {syscalls(value.ProfileEdit{ActionID: "syscalls", Field: "syscallRate", Number: 100001}), value.CompositionInvalid, "profile_composition.components[0] action syscalls.parameters.maxEventsPerSecond"},
		"http headers not yet":           {value.ProfileComposition{Components: []value.ProfileComponent{{ID: "http", Profile: value.ProfileRef{Catalog: "builtin", Name: "http-headers", Version: "v1"}}}, MaxTotalBytes: 1, MaxDuration: "1s"}, value.CompositionProfileMissing, "profile_composition.components[0].profileRef"},
		"organization catalog":           {value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: value.ProfileRef{Catalog: "organization", Name: "network-connections", Version: "v1"}}}, MaxTotalBytes: 1, MaxDuration: "1s"}, value.CompositionProfileMissing, "profile_composition.components[0].profileRef"},
		"unknown version":                {value.ProfileComposition{Components: []value.ProfileComponent{{ID: "net", Profile: value.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v2"}}}, MaxTotalBytes: 1, MaxDuration: "1s"}, value.CompositionProfileMissing, "profile_composition.components[0].profileRef"},
		"aggregate output never raised":  {func() value.ProfileComposition { x := network(); x.MaxTotalBytes = 1 << 20; return x }(), value.CompositionInvalid, "profile_composition.maxTotalBytes"},
		"two components":                 {value.ProfileComposition{Components: append(network().Components, syscalls().Components...), MaxTotalBytes: 32 << 20, MaxDuration: "30s"}, value.CompositionInvalid, "profile_composition.components"},
		"raw byte predicate":             {network(text("sample", "packetFilter", "tcp[13] & 2 != 0")), value.CompositionApproval, "profile_composition.components[0] action sample.parameters.filter"},
		"unresolved host name":           {network(text("sample", "packetFilter", "host db.payments.svc")), value.CompositionFilterRejected, "profile_composition.components[0] action sample.parameters.filter"},
		"service name port":              {network(text("sample", "packetFilter", "tcp port https")), value.CompositionFilterRejected, "profile_composition.components[0] action sample.parameters.filter"},
		"gateway resolves names":         {network(text("sample", "packetFilter", "gateway 10.0.0.1")), value.CompositionFilterRejected, "profile_composition.components[0] action sample.parameters.filter"},
		"uppercase keyword is not trust": {network(text("sample", "packetFilter", "HOST 10.0.0.1")), value.CompositionFilterRejected, "profile_composition.components[0] action sample.parameters.filter"},
		"edit text over 4096 bytes":      {network(text("sample", "packetFilter", strings.Repeat("tcp or ", 600)+"tcp")), value.CompositionInvalid, "profile_composition"},
		"filter over 256 tokens":         {network(text("sample", "packetFilter", strings.Repeat("tcp or ", 128)+"tcp")), value.CompositionFilterRejected, "profile_composition.components[0] action sample.parameters.filter"},
		"control characters":             {network(text("sample", "packetFilter", "tcp\x00")), value.CompositionFilterRejected, "profile_composition.components[0] action sample.parameters.filter"},
		"escaped protocol name":          {network(text("sample", "packetFilter", "ip proto \\tcp")), value.CompositionFilterRejected, "profile_composition.components[0] action sample.parameters.filter"},
	} {
		t.Run(name, func(t *testing.T) {
			c.compiled = nil
			refusal(t, ValidateComposition(tc.composition, c), tc.code, tc.path)
			if tc.code == value.CompositionApproval || tc.code == value.CompositionFilterRejected {
				if len(c.compiled) != 0 {
					t.Fatal("a refused expression reached libpcap")
				}
			}
		})
	}
	for name, composition := range map[string]value.ProfileComposition{
		"defaults":                 network(),
		"onTrigger next interval":  network(text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s")),
		"ongoing retrospective":    network(text("sample", "packetAfter", "0s")),
		"ongoing after only":       network(text("sample", "packetBefore", "0s")),
		"filter and longer window": network(text("sample", "packetFilter", "  tcp port 8080\n and host 10.0.0.12 "), text("sample", "packetAfter", "15s"), text("sample", "actionTimeout", "20s")),
		"recorded ipv6 case":       network(text("sample", "packetFilter", "ip6 and dst host 2001:db8::2")),
		"cidr and portrange":       network(text("sample", "packetFilter", "net 10.0.0.0/8 and udp dst portrange 50-60")),
		"protocol number":          network(text("sample", "packetFilter", "ip proto 6")),
		"syscall defaults":         syscalls(),
		"syscall include errors":   syscalls(value.ProfileEdit{ActionID: "syscalls", Field: "syscallFilter", Syscalls: &value.SyscallSelection{Mode: "include", Names: []string{"openat", "connect"}}}, text("syscalls", "actionExecutionMode", "onTrigger"), text("syscalls", "syscallBefore", "0s")),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateComposition(composition, c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFilterScreeningCorpus(t *testing.T) {
	// The feasibility corpus expressions (docs/research/feasibility-packet-downloads.md).
	for _, expression := range []string{"tcp dst port 443", "udp port 53", "tcp and host 192.0.2.2", "ip6 and dst host 2001:db8::2", "udp dst portrange 50-60", "tcp port 80 or udp port 53", "not udp", "tcp dst port 80", "ether host 00:11:22:33:44:55", "vlan and ip", "len <= 128", "icmp or icmp6"} {
		if err := ScreenFilter("f", expression); err != nil {
			t.Fatalf("%q: %v", expression, err)
		}
	}
	refusal(t, ScreenFilter("f", "tcp[tcpflags] & tcp-syn != 0"), value.CompositionApproval, "f")
	refusal(t, ScreenFilter("f", strings.Repeat("tcp or ", 600)+"tcp"), value.CompositionFilterRejected, "f")
	refusal(t, ScreenFilter("f", " \t "), value.CompositionFilterRejected, "f")
	refusal(t, ScreenFilter("f", "host 10.0.0.1 or host münchen"), value.CompositionFilterRejected, "f")
	refusal(t, ScreenFilter("f", "ether[0:4] = 0x47455420"), value.CompositionApproval, "f")
	// libpcap lexes these hyphenated tokens as names (getaddrinfo); only a
	// portrange operand is a range.
	for _, expression := range []string{"host 1-2", "net 1-2", "src host 1-2", "port 1-2", "tcp and dst host 10-20"} {
		refusal(t, ScreenFilter("f", expression), value.CompositionFilterRejected, "f")
	}
	if err := ScreenFilter("f", "tcp src portrange 1-2"); err != nil {
		t.Fatal("portrange operand", err)
	}
	if NormalizeFilter("  tcp \t port\n80  ") != "tcp port 80" {
		t.Fatal("normalization")
	}
}

func TestFilterCompilerFailures(t *testing.T) {
	path := "profile_composition.components[0] action sample.parameters.filter"
	edit := network(text("sample", "packetFilter", "tcp port 8080"))
	refusal(t, ValidateComposition(edit, nil), value.CompositionNoCompiler, path)
	refusal(t, ValidateComposition(edit, &fakeCompiler{err: value.ErrFilterCompilerUnavailable}), value.CompositionNoCompiler, path)
	refusal(t, ValidateComposition(edit, &fakeCompiler{err: errors.New("syntax error\x01")}), value.CompositionFilterRejected, path)
	refusal(t, ValidateComposition(edit, &fakeCompiler{program: fixtureProgram, linkType: "RAW"}), value.CompositionNoCompiler, path)
	refusal(t, ValidateComposition(edit, &fakeCompiler{program: make([]value.BPFInstruction, value.MaxFilterInstructions+1)}), value.CompositionFilterRejected, path)
	refusal(t, ValidateComposition(edit, &fakeCompiler{}), value.CompositionNoCompiler, path)
	// Without a filter no compiler is needed.
	if err := ValidateComposition(network(), nil); err != nil {
		t.Fatal(err)
	}
}

type scopeView struct {
	Version    string `json:"schemaVersion"`
	Acceptance string `json:"acceptance"`
	Recipe     struct {
		Actions []struct {
			ID            string          `json:"id"`
			ExecutionMode string          `json:"executionMode"`
			Parameters    json.RawMessage `json:"parameters"`
		} `json:"actions"`
	} `json:"recipe"`
	Lifecycle struct {
		Actions []map[string]string `json:"actions"`
		Scope   string              `json:"ongoingPodScope"`
	} `json:"lifecycle"`
	Filters []struct {
		ActionID      string      `json:"actionID"`
		Expression    string      `json:"expression"`
		Program       [][4]uint32 `json:"program"`
		ProgramDigest string      `json:"programDigest"`
	} `json:"filters"`
	Provenance struct {
		ResolvedProfiles []map[string]any `json:"resolvedProfiles"`
		ActionMap        []map[string]any `json:"actionMap"`
	} `json:"profileComposition"`
}

func TestRecorderPlanLifecycleAndFilterBinding(t *testing.T) {
	c := &fakeCompiler{program: fixtureProgram}
	in, now := recorderInput(t, network(text("sample", "packetFilter", "  tcp port 8080 "), text("sample", "actionExecutionMode", "onTrigger"), text("sample", "packetBefore", "0s")), "packetCapture")
	plan, err := CompileRecorder(in, c, now)
	if err != nil {
		t.Fatal(err)
	}
	var v scopeView
	if err := json.Unmarshal(plan.CanonicalScope, &v); err != nil {
		t.Fatal(err)
	}
	id := generatedID("a", "net", "sample")
	a := plan.Actions[0]
	if v.Version != "recorder-preview/v1" || v.Acceptance != "recorderUnavailable" || a.ID != id || a.ExecutionMode != "onTrigger" || a.Before != "0s" || a.After != "10s" || a.FilterInstructions != 4 || a.Filter != "tcp port 8080" {
		t.Fatalf("plan %+v", a)
	}
	if len(v.Lifecycle.Actions) != 1 || v.Lifecycle.Actions[0]["requestedBefore"] != "0s" || v.Lifecycle.Actions[0]["activation"] != "" || v.Lifecycle.Scope != "none" {
		t.Fatalf("onTrigger lifecycle: %+v", v.Lifecycle)
	}
	if len(v.Filters) != 1 || v.Filters[0].Expression != "tcp port 8080" || v.Filters[0].ProgramDigest != hexDigest(FilterProgramDigest(fixtureProgram)) || len(v.Filters[0].Program) != 4 {
		t.Fatalf("filter binding: %+v", v.Filters)
	}
	if len(v.Provenance.ResolvedProfiles) != 1 || v.Provenance.ResolvedProfiles[0]["sourceUID"] != nil || len(v.Provenance.ActionMap) != 1 {
		t.Fatalf("builtin provenance: %+v", v.Provenance)
	}
	if !VerifyRecorderPlan(plan, c, now) {
		t.Fatal("plan does not recompile")
	}
	// The digest binds the program the kernel runs: another program changes it.
	other := &fakeCompiler{program: append(append([]value.BPFInstruction(nil), fixtureProgram[:3]...), value.BPFInstruction{Code: 0x6, K: 1})}
	if VerifyRecorderPlan(plan, other, now) {
		t.Fatal("changed bytecode kept the execution digest")
	}
	// Ongoing default: a manual session.
	in, _ = recorderInput(t, network(), "packetCapture")
	plan, err = CompileRecorder(in, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	v = scopeView{}
	_ = json.Unmarshal(plan.CanonicalScope, &v)
	if v.Lifecycle.Actions[0]["activation"] != "manualSession" || v.Lifecycle.Actions[0]["requestedBefore"] != "30s" || v.Lifecycle.Scope != "acceptedCapturePods" || v.Recipe.Actions[0].ExecutionMode != "ongoing" || len(v.Filters) != 0 {
		t.Fatalf("ongoing lifecycle: %+v", v)
	}
	// Retention must be resolved for the plan's own evidence type.
	in, _ = recorderInput(t, network(), "syscallTrace")
	if _, err := CompileRecorder(in, nil, now); !errors.Is(err, value.ErrInvalid) {
		t.Fatal("evidence type mismatch accepted")
	}
	if kind, err := RecorderEvidenceType(syscalls()); err != nil || kind != "syscallTrace" {
		t.Fatal(kind, err)
	}
}

// examples/resolved-recorder-preview.json is the cross-language fixture; the
// specification checker independently recomputes its recipe, provenance,
// lifecycle and program digest. The program is libpcap 1.11.0's output for the
// fixture expression (pinned by the libpcap-tagged adapter test).
func TestRecorderScopeCrossLanguageFixture(t *testing.T) {
	b, err := os.ReadFile("../../../examples/resolved-recorder-preview.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture scopeView
	if err := json.Unmarshal(b, &fixture); err != nil || len(fixture.Filters) != 1 {
		t.Fatal("fixture", err)
	}
	program := []value.BPFInstruction{}
	for _, ins := range fixture.Filters[0].Program {
		program = append(program, value.BPFInstruction{Code: uint16(ins[0]), Jt: uint8(ins[1]), Jf: uint8(ins[2]), K: ins[3]})
	}
	in, now := RecorderFixtureInput(t)
	c := &fakeCompiler{program: program}
	plan, err := CompileRecorder(in, c, now)
	if err != nil {
		t.Fatal(err)
	}
	want, _, err := canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plan.CanonicalScope, want) {
		if os.Getenv("ASSERVAT_WRITE_RECORDER_FIXTURE") == "1" {
			var pretty bytes.Buffer
			_ = json.Indent(&pretty, plan.CanonicalScope, "", "  ")
			pretty.WriteByte('\n')
			_ = os.WriteFile("../../../examples/resolved-recorder-preview.json", pretty.Bytes(), 0o644)
		}
		t.Fatalf("compiled plan differs from the fixture:\n%s", plan.CanonicalScope)
	}
	if len(c.compiled) != 1 || c.compiled[0] != fixture.Filters[0].Expression {
		t.Fatal("fixture expression not compiled")
	}
}

// RecorderFixtureInput is the synthetic input of examples/resolved-recorder-preview.json.
func RecorderFixtureInput(t *testing.T) (value.RecorderInput, time.Time) {
	t.Helper()
	return recorderInput(t, network(text("sample", "packetFilter", "tcp port 8080 and host 10.0.0.12"), text("sample", "packetAfter", "15s"), text("sample", "actionTimeout", "20s")), "packetCapture")
}

func TestRecorderAssessmentRules(t *testing.T) {
	in, now := recorderInput(t, network(), "packetCapture")
	plan, err := CompileRecorder(in, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err := AssessRecorder(plan, "00000000-0000-4000-8000-000000000161", now)
	if err != nil {
		t.Fatal(err)
	}
	x := a.Actions[0]
	if a.Combined.Level != "unknown" || !a.Combined.HasUnknowns || x.Impact.Level != "unknown" || a.ObservationPods != 1 || a.IncidentPods != 1 || a.PlanDigest != plan.ScopeDigest || a.RulesDigest != RecorderAssessmentRulesDigest() {
		t.Fatalf("assessment %+v", a)
	}
	if x.Exposure.Classification != "potentialPersonalData" || strings.Join(x.Exposure.RetainedPossible, ",") != "networkAddresses,personalIdentifiers" || strings.Join(x.Exposure.TransientOnly, ",") != "userContent,credentials" {
		t.Fatalf("packet exposure %+v", x.Exposure)
	}
	// Arming cost (ring per observation pod) is separate from incident cost.
	for _, q := range x.Quantities {
		if q.Basis != "configuredLimit" {
			t.Fatal("a quantity claims a measurement")
		}
	}
	if x.Quantities[1].Phase != "whileArmed" || x.Quantities[1].Scope != "perObservationPod" || x.Quantities[1].Upper != 16<<20 || x.Quantities[0].Phase != "perIncident" || x.Quantities[0].Upper != 16<<20 {
		t.Fatalf("quantities %+v", x.Quantities)
	}
	if x.Retention.AccessAgeSeconds != 3600 || x.Retention.DeleteAgeSeconds != 3900 || x.Retention.MaximumAgeSeconds != 86400 {
		t.Fatalf("retention %+v", x.Retention)
	}
	changes := []string{}
	for _, alt := range a.Alternatives {
		changes = append(changes, alt.Change)
	}
	if strings.Join(changes, ",") != "narrowScope,futureOnly" {
		t.Fatal(changes)
	}
	for _, e := range a.Combined.Effects {
		if e == "applicationPause" {
			t.Fatal("invented an application pause")
		}
	}
	// onTrigger: no armed phase, nothing to say about history.
	in, _ = recorderInput(t, syscalls(text("syscalls", "actionExecutionMode", "onTrigger"), text("syscalls", "syscallBefore", "0s")), "syscallTrace")
	plan, err = CompileRecorder(in, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	a, err = AssessRecorder(plan, "00000000-0000-4000-8000-000000000161", now)
	if err != nil {
		t.Fatal(err)
	}
	x = a.Actions[0]
	if a.ObservationPods != 0 || x.Quantities[1].Phase != "perIncident" || len(x.Exposure.TransientOnly) != 0 || strings.Join(x.Exposure.RetainedPossible, ",") != "personalIdentifiers" || len(a.Alternatives) != 1 || a.Alternatives[0].Change != "narrowScope" {
		t.Fatalf("syscall onTrigger assessment %+v", a)
	}
	if _, err := AssessRecorder(plan, "not-a-uuid", now); err == nil {
		t.Fatal("invalid assessment id accepted")
	}
}

func TestEmptyTextEditGetsFieldRemedy(t *testing.T) {
	path := "profile_composition.components[0].overrides[0]"
	empty := value.ProfileEdit{ActionID: "sample", Field: "packetFilter", TextSet: true}
	err := ValidateComposition(network(empty), &fakeCompiler{})
	refusal(t, err, value.CompositionFilterRejected, path)
	if !strings.Contains(err.Error(), "omit the edit") {
		t.Fatal("empty filter lost its remedy", err)
	}
}
