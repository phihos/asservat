package kubernetes

import (
	"asservat.local/asservat/internal/domain/identity"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestRegionalExecutorPinsEveryMountedInputWithCollector(t *testing.T) {
	for _, collector := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata-only", true: "collector-enabled"}[collector], func(t *testing.T) {
			p := RegionalInstallPlan{Namespace: "asservat-connector", Offer: contracts.RegionalOffer{Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64)}}
			out := RegionalInstallation{}
			if collector {
				p.Collector = &RegionalCollectorPlan{Namespace: "asservat-collector", Name: "asservat-node"}
				out.Nodes = &RegionalNodeEndpoint{serverInput: contracts.ConnectorAPIInput{Kind: "Secret", Name: RegionalNodes, UID: ownerID(83), ResourceVersion: "83", DedicatedToAPI: true}}
			}
			x := regionalExecutor{capacity: &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{UID: types.UID(ownerID(80))}}, evidence: contracts.WorkerObjectReference{Name: RegionalEvidence, UID: ownerID(81)}, evidenceVersion: "81"}
			inputs := &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: RegionalInputs, UID: types.UID(ownerID(82)), ResourceVersion: "82"}}
			settings, err := regionalExecutorSettings(p, out, x, artifact.Digest{1}, artifact.Digest{2}, value.ConnectorCredentialProfile{}, inputs)
			if err != nil {
				t.Fatal(err)
			}
			refs, err := connectorAPIInputNames(RegionalWorkload(p.Offer, true, collector).Spec.Template.Spec)
			if err != nil {
				t.Fatal(err)
			}
			if len(settings.Inputs) != len(refs) {
				t.Fatalf("executor pins %d inputs but its real workload projects %d: %v", len(settings.Inputs), len(refs), refs)
			}
			for _, in := range settings.Inputs {
				if !refs[in.Kind+"/"+in.Name] || in.UID == "" || in.ResourceVersion == "" {
					t.Fatal("unbound or unprojected input", in)
				}
			}
		})
	}
}

func TestRegionalCollectorInputPinCannotBeOmittedOrChanged(t *testing.T) {
	p := RegionalInstallPlan{Collector: &RegionalCollectorPlan{Namespace: "asservat-collector", Name: "asservat-node"}, Offer: contracts.RegionalOffer{Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64)}}
	x := regionalExecutor{capacity: &core.ServiceAccount{}}
	inputs := &core.ConfigMap{}
	for name, pin := range map[string]*RegionalNodeEndpoint{
		"missing acknowledgement": nil,
		"missing pin":             {},
		"missing version":         {serverInput: contracts.ConnectorAPIInput{Kind: "Secret", Name: RegionalNodes, UID: ownerID(83), DedicatedToAPI: true}},
		"another Secret":          {serverInput: contracts.ConnectorAPIInput{Kind: "Secret", Name: "another", UID: ownerID(83), ResourceVersion: "83", DedicatedToAPI: true}},
		"not dedicated":           {serverInput: contracts.ConnectorAPIInput{Kind: "Secret", Name: RegionalNodes, UID: ownerID(83), ResourceVersion: "83"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := regionalExecutorSettings(p, RegionalInstallation{Nodes: pin}, x, artifact.Digest{1}, artifact.Digest{2}, value.ConnectorCredentialProfile{}, inputs); err == nil {
				t.Fatal("collector-enabled settings lack exact acknowledged input")
			}
		})
	}
}

// Pin the disabled-collector settings/startup ABI to the pre-fix builder.
func TestRegionalExecutorDisabledCollectorCompatibility(t *testing.T) {
	p := RegionalInstallPlan{Namespace: "asservat-connector", Offer: contracts.RegionalOffer{PermissionRootID: ownerID(1), Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64)}}
	p.Bootstrap.Binding = value.PeerBinding{InstallationID: ownerID(1), ClusterID: ownerID(2), IssuerEpoch: ownerID(3)}
	out := RegionalInstallation{Namespace: contracts.WorkerObjectReference{Name: p.Namespace, UID: ownerID(4)}, Account: contracts.WorkerObjectReference{Name: RegionalAccount, UID: ownerID(5)}, Deployment: contracts.WorkerObjectReference{Name: RegionalDeployment, UID: ownerID(6)}}
	x := regionalExecutor{capacity: &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{UID: types.UID(ownerID(7))}}, evidence: contracts.WorkerObjectReference{Name: RegionalEvidence, UID: ownerID(8)}, evidenceVersion: "8", startGuard: contracts.OwnerDeploymentGuard{Name: "start-guard", PolicyUID: ownerID(9), PolicyGeneration: 1, BindingUID: ownerID(10), BindingResourceVersion: "10"}}
	revision := value.ConnectorCredentialProfile{Revision: identity.Revision{UID: ownerID(11), Generation: 1, Digest: artifact.Digest{3}}}
	inputs := &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: RegionalInputs, UID: types.UID(ownerID(12)), ResourceVersion: "12"}}
	installed, err := regionalExecutorSettings(p, out, x, artifact.Digest{1}, artifact.Digest{2}, revision, inputs)
	if err != nil {
		t.Fatal(err)
	}
	startup, canonical, err := ConnectorAPIStartupDigest(artifact.Digest{4}, ownerID(13), "13", installed)
	if err != nil {
		t.Fatal("valid disabled collector settings", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(canonical)); got != "8855506cebb07f95046d4975c9e0f6e311cb8d408c95b41e8ffa13b12cedd66f" {
		t.Fatal("disabled collector input bytes changed", got)
	}
	if got := fmt.Sprintf("%x", startup); got != "e16e283cb052baf7265274d94aa8a985dbb90cd8edb555bcfcd3cd144647457e" {
		t.Fatal("disabled collector startup digest changed", got)
	}
}
