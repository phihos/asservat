package kubernetes

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func initialRuntimeBridgeFixture() cfg.InitialRuntimeBridgeAdministration {
	ns := cfg.NamespaceRef{Name: "initial-target", UID: ownerID(100)}
	admins := []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}
	initial := cfg.InitialWorkloadAdministration{Handover: true, Name: "initial-guard", Configuration: "initial-inputs", Witness: "initial-witness", FleetSource: "fleet", ControlNamespace: ns, PodName: "initial-pod", PodUID: ownerID(101), WriterAccount: "initial-writer", WriterAccountUID: ownerID(102), ProbeAccount: "initial-probe", ProbeAccountUID: ownerID(103), PodSpecDigest: artifact.Digest{1}, Administrators: admins}
	owner := cfg.OwnerWorkloadAdministration{Name: "owner-guard", Deployment: "owner", DeploymentUID: ownerID(104), ControlNamespace: ns, Administrators: admins, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "fleet", ServiceAccount: "configuration-worker"}}, InitialHistoryProbe: &cfg.OwnerInitialHistoryProbe{Namespace: cfg.NamespaceRef{Name: "bootstrap", UID: ownerID(105)}, ServiceAccount: "original-history", ServiceAccountUID: ownerID(106), Configuration: initial.Configuration}}
	return cfg.InitialRuntimeBridgeAdministration{Initial: initial, Owner: owner, Credentials: "initial-providers", OwnerProbe: cfg.InitialRuntimeProbe{ServiceAccount: "owner-probe", ServiceAccountUID: ownerID(107)}, SourceProbes: []cfg.InitialRuntimeSourceProbe{{ConfigMap: "fleet", ServiceAccount: "configuration-worker", ServiceAccountUID: ownerID(108)}}}
}

// These are candidate-shape tests, not an admission-enforcement substitute.
// Actual independent-denial/controller/cleanup checks require the native API.
func TestInitialRuntimeBridgePreservesOriginalPodAndBindingRestrictions(t *testing.T) {
	p := initialRuntimeBridgeFixture()
	old, binding, err := InitialWorkloadAdmission(p.Initial)
	if err != nil {
		t.Fatal(err)
	}
	probe, probeBinding, err := InitialRuntimeProbeAdmission(p)
	if err != nil {
		t.Fatal(err)
	}
	retained, retainedBinding, err := InitialRuntimeRetainedAdmission(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(binding, probeBinding) || !reflect.DeepEqual(binding, retainedBinding) || !reflect.DeepEqual(old.Spec.Validations[1:], retained.Spec.Validations[1:]) || !reflect.DeepEqual(old.Spec.Validations[1:], probe.Spec.Validations[1:]) {
		t.Fatal("bridge changed original binding or Pod retirement restrictions")
	}
	if !strings.HasPrefix(probe.Spec.Validations[0].Expression, "("+old.Spec.Validations[0].Expression+") || (has(request.dryRun) && request.dryRun && request.operation == 'UPDATE' && variables.sub == ''") {
		t.Fatal("intermediate candidate changed original allow branches or persistence limit")
	}
	if !reflect.DeepEqual(old.Spec.MatchConditions, probe.Spec.MatchConditions) || len(retained.Spec.MatchConditions) != len(old.Spec.MatchConditions)+1 {
		t.Fatal("intermediate candidate released namespace protection")
	}
	match := retained.Spec.MatchConditions[len(retained.Spec.MatchConditions)-1].Expression
	if strings.Contains(match, "variables.") {
		t.Fatal("match condition uses unavailable variables")
	}
	for _, name := range []string{p.Initial.Configuration, p.Initial.Witness, p.Initial.FleetSource, p.Credentials, p.Credentials + "-probe", p.Initial.WriterAccount, p.Initial.ProbeAccount, p.Initial.PodName} {
		if !strings.Contains(match, ownerCELString(name)) {
			t.Fatal("original resource escaped retained guard", name)
		}
	}
}

func TestInitialRuntimeBridgeRejectsInconsistentOriginalScope(t *testing.T) {
	for name, change := range map[string]func(*cfg.InitialRuntimeBridgeAdministration){
		"legacy":                    func(p *cfg.InitialRuntimeBridgeAdministration) { p.Initial.Handover = false },
		"different namespace":       func(p *cfg.InitialRuntimeBridgeAdministration) { p.Owner.ControlNamespace.UID = ownerID(999) },
		"missing history":           func(p *cfg.InitialRuntimeBridgeAdministration) { p.Owner.InitialHistoryProbe = nil },
		"new history target":        func(p *cfg.InitialRuntimeBridgeAdministration) { p.Owner.InitialHistoryProbe.Configuration = "other" },
		"old writer as owner probe": func(p *cfg.InitialRuntimeBridgeAdministration) { p.OwnerProbe.ServiceAccount = p.Initial.WriterAccount },
		"history as source probe": func(p *cfg.InitialRuntimeBridgeAdministration) {
			p.SourceProbes[0].ServiceAccountUID = p.Owner.InitialHistoryProbe.ServiceAccountUID
		},
		"missing source proof": func(p *cfg.InitialRuntimeBridgeAdministration) { p.SourceProbes = nil },
		"extra source proof": func(p *cfg.InitialRuntimeBridgeAdministration) {
			p.SourceProbes = append(p.SourceProbes, p.SourceProbes[0])
		},
		"different administrators": func(p *cfg.InitialRuntimeBridgeAdministration) {
			p.Owner.Administrators = []cfg.KubernetesActor{{Kind: "User", Name: "new-admin"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := initialRuntimeBridgeFixture()
			change(&p)
			if _, _, err := InitialRuntimeProbeAdmission(p); err == nil {
				t.Fatal("accepted inconsistent bridge")
			}
		})
	}
}

func TestOwnerInitialHistoryOmissionPreservesLegacyBytes(t *testing.T) {
	p := initialRuntimeBridgeFixture().Owner
	p.InitialHistoryProbe = nil
	// Independent old declaration records the pre-extension field order and
	// omission behavior used by canonical policy/proof digests.
	old := struct {
		Name, Deployment, DeploymentUID string
		ControlNamespace                cfg.NamespaceRef
		Administrators                  []cfg.KubernetesActor
		ConfigurationProbes             []cfg.OwnerConfigurationProbe
		SchedulingLeases                []cfg.OwnerSchedulingLease
		APIContextStarts                *cfg.OwnerAPIContextStarts `json:",omitempty"`
	}{p.Name, p.Deployment, p.DeploymentUID, p.ControlNamespace, p.Administrators, p.ConfigurationProbes, p.SchedulingLeases, p.APIContextStarts}
	a, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("omitted history capability changed historical canonical bytes")
	}
}
