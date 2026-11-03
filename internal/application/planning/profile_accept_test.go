package planning

import (
	"bytes"
	"errors"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func TestAcceptedProfileRoundTripPreservesEndpointAndApproval(t *testing.T) {
	in, now := recorderInput(t, cpuComposition(), "profile")
	in.NodeRecorder = true
	in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
	_, err := CompileRecorder(in, nil, now)
	var need EndpointResolutionNeeded
	if !errors.As(err, &need) {
		t.Fatal(err)
	}
	in.Endpoints = []targets.ProfileEndpointResolution{{Request: need.Request, SourceKind: targets.ProfileEndpointTemplateBinding, SourceName: "go-pprof-loopback", AddressMode: "targetLoopback", Port: 6060, DeclaredPortName: "diagnostics", PathPolicy: "go-pprof/v1", DefinitionDigest: artifact.Digest{1}, EndpointDigest: artifact.Digest{2}, ResolvedAt: now}}
	plan, err := CompileRecorder(in, nil, now)
	if err != nil || !AcceptableProfile(plan).Acceptable() {
		t.Fatal(err)
	}
	frozen, err := ProfileContextFromScope(in.Composition, in.Target.Request, plan.CanonicalScope)
	if err != nil {
		t.Fatal(err)
	}
	ctxIn, _ := contextInput(t)
	ctxIn.Retention, ctxIn.Profile, ctxIn.Target = in.Retention, frozen, in.Target
	ctxIn.Capability.ExecutionClass = artifact.ContextAPIExecution
	cp, err := CompileContext(ctxIn, now)
	if err != nil || cp.ScopeDigest != plan.ScopeDigest || !bytes.Equal(cp.CanonicalScope, plan.CanonicalScope) || !VerifyFrozenContextPlan(cp) {
		t.Fatalf("profile scope roundtrip: %v", err)
	}
	acquisition, id, err := ProfileForContext(cp)
	if err != nil || id != plan.Actions[0].ID || acquisition.TimeoutMillis != 15000 || acquisition.MaxBytes != 16<<20 {
		t.Fatalf("acquisition: %+v %v", acquisition, err)
	}
	restored, err := ProfileContextFor(&acquisition)
	if err != nil || !restored.Endpoints[0].Request.Equal(need.Request) || !restored.Endpoints[0].ResolvedAt.Equal(now) {
		t.Fatal("accepted binding roundtrip", err)
	}
	for name, change := range map[string]func(*artifact.GoProfileAcquisition){
		"endpoint": func(p *artifact.GoProfileAcquisition) { p.EndpointDigest = artifact.Digest{9} },
		"duration": func(p *artifact.GoProfileAcquisition) { p.DurationMillis++ },
		"timeout":  func(p *artifact.GoProfileAcquisition) { p.TimeoutMillis = 30000 },
		"cap":      func(p *artifact.GoProfileAcquisition) { p.MaxBytes++ },
	} {
		p := acquisition
		change(&p)
		if _, err := ProfileContextFor(&p); err == nil {
			t.Fatal("accepted mutated", name)
		}
	}
	mixed := ctxIn
	mixed.Recorder = &value.RecorderContext{Composition: in.Composition}
	if _, err := CompileContext(mixed, now); err == nil {
		t.Fatal("profile also recorded as packet")
	}
	frozen.Endpoints[0].Request.Bindings[0].TemplateRef = "mutated"
	if cp.Input.Profile.Endpoints[0].Request.Bindings[0].TemplateRef == "mutated" {
		t.Fatal("accepted input shares bindings")
	}
}
