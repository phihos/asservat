package planning

import (
	"asservat.local/asservat/internal/domain/execution"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func TestPolicyEndpointPreservesAdministratorRangeAndExactPort(t *testing.T) {
	in, now := endpointInput()
	d := in.Catalog.Templates[0]
	r := targets.ProfileEndpointDefinitionRequest{ClusterID: in.Network.Target.Request.ClusterID, Namespace: in.Network.Target.Request.Namespace, SourceRef: d.Source.Name}
	entries := []ProfileEndpointEntry{{Definition: d, Profile: true, AddressMode: "targetLoopback", Port: 6060}}
	a, err := ResolveProfileEndpointDefinition(entries, r)
	if err != nil || !a.Answers(r) || a.MinimumPort != 6000 || a.MaximumPort != 6999 {
		t.Fatal("fixed administrator port lost original definition range", err)
	}
	p, err := PolicyProfileEndpointFromResolution(a)
	if err != nil || !p.Valid() {
		t.Fatal("valid fixed administrator selection refused", err)
	}
	child := targets.ProfileEndpointRequest{Target: in.Network.Target.Request, SourceRef: d.Source.Name, Type: "cpu", Mode: "interval", DurationSeconds: 10, NativeLimit: 16 << 20}
	resolved, err := ResolveProfileEndpointRequest(entries, in.Network, child, now)
	if err != nil || !p.Matches(resolved) {
		t.Fatal("fixed port failed to match exact child", err)
	}
	resolved.Port = 6061
	if p.Matches(resolved) {
		t.Fatal("approved fixed port changed within definition range")
	}
}

func TestPolicyProfilesUseSameFiniteModesRecipesAndProvenanceAsManual(t *testing.T) {
	for _, tc := range []struct {
		typ, mode, duration, timeout string
		gc                           bool
	}{
		{"cpu", "interval", "60s", "70s", false}, {"runtimeTrace", "interval", "15s", "20s", false},
		{"heap", "snapshot", "", "5s", false}, {"heap", "snapshot", "", "5s", true}, {"heap", "delta", "60s", "70s", false},
		{"goroutine", "snapshot", "", "5s", false}, {"goroutine", "delta", "1s", "6s", false},
		{"allocs", "cumulative", "", "5s", false}, {"allocs", "delta", "1s", "6s", false},
		{"block", "cumulative", "", "5s", false}, {"block", "delta", "1s", "6s", false},
		{"mutex", "cumulative", "", "5s", false}, {"mutex", "delta", "1s", "6s", false},
		{"threadcreate", "cumulative", "", "5s", false}, {"threadcreate", "delta", "1s", "6s", false},
	} {
		for _, tlsEnabled := range []bool{false, true} {
			name := "http"
			if tlsEnabled {
				name = "tls"
			}
			t.Run(name+"/"+tc.typ+"/"+tc.mode+"/"+tc.timeout, func(t *testing.T) {
				raw, err := os.ReadFile("profiles/go-cpu-v1.json")
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if json.Unmarshal(raw, &doc) != nil {
					t.Fatal("profile fixture")
				}
				doc["name"] = "finite-profile"
				recipe := doc["definition"].(map[string]any)["recipe"].(map[string]any)
				a := recipe["actions"].([]any)[0].(map[string]any)
				p := a["parameters"].(map[string]any)
				p["type"], p["mode"], p["forceGC"] = tc.typ, tc.mode, tc.gc
				if tc.duration == "" {
					delete(p, "duration")
				} else {
					p["duration"] = tc.duration
				}
				a["limits"].(map[string]any)["timeout"] = tc.timeout
				recipe["maxDuration"] = "90s"
				raw, _ = json.Marshal(doc)
				c := cpuComposition()
				c.MaxDuration = "90s"
				ref := value.ProfileRef{Catalog: "namespace", Name: "finite-profile", Version: "v1"}
				c.Components[0].Profile = ref
				c.Resolved = []value.CatalogProfile{{Ref: ref, SourceClusterID: endpointID(1), SourceNamespaceUID: "namespace-payments-uid", SourceUID: "profile-uid", Document: raw, Enabled: true, Deprecated: true}}
				_, err = CompilePolicyRecorder(c, nil)
				var needed PolicyProfileEndpointNeeded
				if !errors.As(err, &needed) || len(needed.Bindings) != 1 {
					t.Fatal("no target-independent definition request", err)
				}
				in, now := recorderInput(t, c, "profile")
				in.NodeRecorder = true
				in.Deadline = now.Add(2 * time.Minute)
				in.Target.ExecutionClass, in.Target.NodeUID, in.Target.NodeBootID, in.Target.Pin.NodeName = artifact.ContextAPIExecution, "", "", ""
				base, _ := endpointInput()
				d := base.Catalog.Templates[0]
				d.Source.Name = needed.Bindings[0].TemplateRef
				entries := []ProfileEndpointEntry{{Definition: d}}
				if tlsEnabled {
					material := execution.GoProfileTLSMaterial{RootsPEM: "public certificate fixture", ServerName: "pprof.example.invalid"}
					material.RootsDigest = artifact.Digest(sha256.Sum256([]byte(material.RootsPEM)))
					trust := d.Source
					trust.Digest = material.RootsDigest
					entries[0].Definition.TLS = &value.GoEndpointTLS{Trust: trust, ServerName: material.ServerName}
					entries[0].TLSMaterial = material
				}
				query := targets.ProfileEndpointDefinitionRequest{ClusterID: in.Target.Request.ClusterID, Namespace: in.Target.Request.Namespace, SourceRef: needed.SourceRef, Bindings: needed.Bindings}
				answer, err := ResolveProfileEndpointDefinition(entries, query)
				if err != nil {
					t.Fatal(err)
				}
				pin, err := PolicyProfileEndpointFromResolution(answer)
				if err != nil {
					t.Fatal(err)
				}
				parent, err := CompilePolicyRecorder(c, nil, pin)
				if err != nil || !parent.Valid() {
					t.Fatal("finite parent invalid", err)
				}
				_, err = CompileRecorder(in, nil, now)
				var childNeed EndpointResolutionNeeded
				if !errors.As(err, &childNeed) {
					t.Fatal(err)
				}
				network := base.Network
				network.Target = in.Target
				childEndpoint, err := ResolveProfileEndpointRequest(entries, network, childNeed.Request, now)
				if err != nil {
					t.Fatal(err)
				}
				childEndpoint.ResolvedAt = now
				in.Endpoints = []targets.ProfileEndpointResolution{childEndpoint}
				child, err := CompileRecorder(in, nil, now)
				if err != nil || !AcceptableProfile(child).Acceptable() {
					t.Fatal("manual child invalid", err)
				}
				actual := child.Actions[0]
				actual.EndpointDigest = ""
				var scope recorderScope
				if json.Unmarshal(child.CanonicalScope, &scope) != nil {
					t.Fatal("child scope")
				}
				if !reflect.DeepEqual(actual, parent.Action) || parent.Profile != child.Profiles[0] || parent.RecipeDigest != child.RecipeDigest || !bytes.Equal(parent.Recipe, scope.Recipe) || !parent.ProfileEndpoint.Matches(childEndpoint) {
					t.Fatal("parent/child identity differs")
				}
				for _, forbidden := range [][]byte{[]byte(`"PodUID"`), []byte(`"EndpointDigest"`), []byte(`"ResolvedAt"`), []byte(`"NodeBootID"`)} {
					if bytes.Contains(parent.Scope, forbidden) {
						t.Fatal("runtime identity in parent scope")
					}
				}
				changed := pin.Clone()
				changed.Definition.Host = "changed.invalid"
				if _, err = CompilePolicyRecorder(c, nil, changed); err == nil {
					t.Fatal("modified definition retained old digest")
				}
			})
		}
	}
}

func TestPolicyEndpointDefinitionSharesDigestAndRefusesUnqualifiedDependencies(t *testing.T) {
	in, now := endpointInput()
	r := targets.ProfileEndpointDefinitionRequest{ClusterID: in.Network.Target.Request.ClusterID, Namespace: in.Network.Target.Request.Namespace, SourceRef: in.SourceRef, Bindings: []targets.ProfileEndpointBinding{{Name: in.SourceRef, TemplateRef: "go-pprof", AddressMode: "targetLoopback", PortName: "diagnostics"}}}
	entries := []ProfileEndpointEntry{{Definition: in.Catalog.Templates[0]}}
	a, err := ResolveProfileEndpointDefinition(entries, r)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PolicyProfileEndpointFromResolution(a)
	manual, manualErr := ResolveGoProfileEndpoint(in, now)
	if err != nil || manualErr != nil || p.DefinitionDigest != manual.DefinitionDigest {
		t.Fatal("definition digest format changed", err, manualErr)
	}
	clone := p.Clone()
	clone.Definition.AddressModes[0] = "changed"
	clone.Binding.PortName = "other"
	if !p.Valid() || p.Binding.PortName != "diagnostics" {
		t.Fatal("pin aliases mutable clone")
	}
	addEndpointCredential(&in)
	entries[0].Definition = in.Catalog.Templates[0]
	if credentialAnswer, credentialErr := ResolveProfileEndpointDefinition(entries, r); credentialErr != nil || credentialAnswer.Credential == nil {
		t.Fatal("public credential definition lost", credentialErr)
	}
	entries[0].Definition.Credential = nil
	a, err = ResolveProfileEndpointDefinition(entries, r)
	if err != nil || a.TLS.IsZero() {
		t.Fatal("public TLS definition lost", err)
	}
	pin, err := PolicyProfileEndpointFromResolution(a)
	if err != nil || !reflect.DeepEqual(pin.Definition.TLS, entries[0].Definition.TLS) {
		t.Fatal("TLS public identity changed", err)
	}
	a.TLS.ServerName = "changed.invalid"
	if _, err = PolicyProfileEndpointFromResolution(a); err == nil {
		t.Fatal("changed TLS identity retained old digest")
	}
}
