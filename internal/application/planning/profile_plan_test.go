package planning

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func cpuComposition() value.ProfileComposition {
	return value.ProfileComposition{Components: []value.ProfileComponent{{ID: "cpu", Profile: value.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
}

func TestProfilePreviewFreezesEndpointAndRequiresApproval(t *testing.T) {
	in, now := recorderInput(t, cpuComposition(), "profile")
	_, err := CompileRecorder(in, nil, now)
	var need EndpointResolutionNeeded
	if !errors.As(err, &need) || !need.Request.Valid() {
		t.Fatalf("endpoint query: %+v %v", need, err)
	}
	if need.Request.SourceRef == "api-local-pprof" || len(need.Request.Bindings) != 1 || need.Request.Bindings[0].Name != need.Request.SourceRef {
		t.Fatal("component binding not expanded")
	}
	r := targets.ProfileEndpointResolution{Request: need.Request, SourceKind: targets.ProfileEndpointTemplateBinding, SourceName: "go-pprof-loopback", AddressMode: "targetLoopback", Port: 6060, DeclaredPortName: "diagnostics", PathPolicy: "go-pprof/v1", DefinitionDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}, ResolvedAt: now}
	in.Endpoints = []targets.ProfileEndpointResolution{r}
	p, err := CompileRecorder(in, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Actions) != 1 || p.Actions[0].Kind != "profile" || !slices.Contains(p.Actions[0].Sensitive, value.ReasonLiveProfile) || p.Approval == nil || p.Approval.DataClass != "raw" {
		t.Fatalf("profile summary: %+v", p)
	}
	if !bytes.Contains(p.CanonicalScope, []byte(`"profileEndpoints"`)) || !bytes.Contains(p.CanonicalScope, []byte(`"endpointBindings"`)) {
		t.Fatal("endpoint missing from reviewed plan")
	}
	actions, approval, err := RecorderScopeSummary(p.CanonicalScope)
	if err != nil || len(actions) != 1 || actions[0].EndpointDigest != p.Actions[0].EndpointDigest || approval == nil {
		t.Fatal("scope roundtrip", err)
	}
	a, err := AssessRecorder(p, "00000000-0000-4000-8000-000000000001", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Actions[0].Quantities) != 1 || !slices.Contains(a.Combined.Effects, "applicationCPU") || len(a.Alternatives) != 0 {
		t.Fatalf("assessment: %+v", a)
	}
	in.Endpoints[0].EndpointDigest = artifact.Digest{3}
	changed, err := CompileRecorder(in, nil, now)
	if err != nil || changed.ScopeDigest == p.ScopeDigest {
		t.Fatal("endpoint change did not alter approval scope", err)
	}
	in.Endpoints[0].Request.SourceRef = "wrong"
	if _, err = CompileRecorder(in, nil, now); err == nil {
		t.Fatal("mismatched endpoint accepted")
	}
	if _, err = CompilePolicyRecorder(cpuComposition(), nil); err == nil {
		t.Fatal("profile policy enabled before acquisition")
	}
}

func TestProfileNormalizationBoundsAndForcedGC(t *testing.T) {
	for _, tc := range []struct {
		name, kind, mode, duration, timeout string
		gc, valid                           bool
	}{
		{"cpu", "cpu", "interval", "10s", "15s", false, true},
		{"snapshot", "heap", "snapshot", "", "5s", true, true},
		{"gc-delta", "heap", "delta", "10s", "15s", true, false},
		{"cpu-snapshot", "cpu", "snapshot", "", "5s", false, false},
		{"trace", "runtimeTrace", "interval", "15s", "20s", false, true},
		{"trace-too-long", "runtimeTrace", "interval", "16s", "21s", false, false},
		{"fractional", "cpu", "interval", "1500ms", "7s", false, false},
		{"no-margin", "cpu", "interval", "10s", "10s", false, false},
		{"excess-margin", "cpu", "interval", "10s", "21s", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := expandedAction{action: recipeAction{Kind: "profile", Impact: "intrusive", Limits: actionLimits{MaxBytes: 1 << 20, Timeout: tc.timeout}}, profile: &profileParameters{Runtime: "go", Type: tc.kind, Mode: tc.mode, Duration: tc.duration, ForceGC: tc.gc, Source: profileSource{Kind: "httpEndpoint", ProfileRef: "pprof"}}}
			err := normalizeProfile("action", &x)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if err == nil && (x.action.ExecutionMode != "onTrigger" || !slices.Contains(x.sensitive, value.ReasonLiveProfile)) {
				t.Fatal("missing lifecycle or approval")
			}
		})
	}
}

func TestProfileRegionResolutionScopeAndAmbiguity(t *testing.T) {
	in, now := endpointInput()
	req := targets.ProfileEndpointRequest{Target: in.Network.Target.Request, SourceRef: in.SourceRef, Type: "cpu", Mode: "interval", DurationSeconds: 10, NativeLimit: 16 << 20, Bindings: []targets.ProfileEndpointBinding{{Name: in.SourceRef, TemplateRef: "go-pprof", AddressMode: "targetLoopback", PortName: "diagnostics"}}}
	entries := []ProfileEndpointEntry{{Definition: in.Catalog.Templates[0]}}
	r, err := ResolveProfileEndpointRequest(entries, in.Network, req, now)
	if err != nil || !r.Answers(req) || r.Port != 6060 || !r.ResolvedAt.IsZero() {
		t.Fatalf("region answer %+v %v", r, err)
	}
	entries[0].Namespaces = []string{"other"}
	if _, err = ResolveProfileEndpointRequest(entries, in.Network, req, now); !errors.Is(err, targets.ErrEndpointUnavailable) {
		t.Fatal("out-of-scope definition", err)
	}
	entries[0].Namespaces = nil
	in.Network.Ports = append(in.Network.Ports, in.Network.Ports[0])
	if _, err = ResolveProfileEndpointRequest(entries, in.Network, req, now); !errors.Is(err, targets.ErrEndpointAmbiguous) {
		t.Fatal("duplicate declared port", err)
	}
	in.Network.Ports = in.Network.Ports[:1]
	in.Network.Target.FreshUntil = now.Add(-time.Second)
	if _, err = ResolveProfileEndpointRequest(entries, in.Network, req, now); err == nil {
		t.Fatal("expired target accepted")
	}
}

func TestSamplerProfileNormalizationHasNoEndpointOrFrequencyOverride(t *testing.T) {
	makeAction := func() expandedAction {
		return expandedAction{action: recipeAction{Kind: "profile", Impact: "intrusive", Limits: actionLimits{MaxBytes: 16 << 20, Timeout: "15s"}}, profile: &profileParameters{Runtime: "any", Type: "cpu", Mode: "interval", Duration: "10s", Source: profileSource{Kind: "ebpfSampler"}}}
	}
	x := makeAction()
	if err := normalizeProfile("action", &x); err != nil || len(x.sensitive) != 1 {
		t.Fatal("sampler plan", err)
	}
	for _, change := range []func(*profileParameters){func(p *profileParameters) { p.Source.ProfileRef = "endpoint" }, func(p *profileParameters) { p.FrequencyHz = 99 }, func(p *profileParameters) { p.ForceGC = true }, func(p *profileParameters) { p.Runtime = "go" }, func(p *profileParameters) { p.Duration = "61s" }} {
		x := makeAction()
		change(x.profile)
		if normalizeProfile("action", &x) == nil {
			t.Fatal("unsupported sampler accepted", x.profile)
		}
	}
}
