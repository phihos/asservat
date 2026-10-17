package kubernetes

import (
	"strings"

	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// InitialRuntimeProbeAdmission preserves the namespace-wide initial guard and
// its Pod retirement checks. Only exact nonpersistent enforcement probes gain
// passage. This builder does not install a policy or authorize the bridge CAS.
func InitialRuntimeProbeAdmission(p cfg.InitialRuntimeBridgeAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Credentials)) != 0 || len(validation.IsDNS1123Subdomain(p.Credentials+"-probe")) != 0 || len(validation.IsDNS1123Subdomain(p.OwnerProbe.ServiceAccount)) != 0 {
		return nil, nil, cfg.ErrInvalid
	}
	if _, _, err := OwnerWorkloadAdmission(p.Owner); err != nil {
		return nil, nil, err
	}
	policy, binding, err := InitialWorkloadAdmission(p.Initial)
	if err != nil {
		return nil, nil, err
	}
	account := func(name, uid string) string {
		return "request.userInfo.username == " + ownerCELString("system:serviceaccount:"+p.Initial.ControlNamespace.Name+":"+name) + " && request.userInfo.uid == " + ownerCELString(uid)
	}
	// An actual oldObject UID is required: a CREATE or replacement Deployment
	// is not the independently installed owner guard's original probe target.
	probes := []string{"(variables.group == 'apps' && request.resource.resource == 'deployments' && request.name == " + ownerCELString(p.Owner.Deployment) + " && oldObject.metadata.uid == " + ownerCELString(p.Owner.DeploymentUID) + " && " + account(p.OwnerProbe.ServiceAccount, p.OwnerProbe.ServiceAccountUID) + ")"}
	for _, probe := range p.SourceProbes {
		if len(validation.IsDNS1123Subdomain(probe.ConfigMap)) != 0 || len(validation.IsDNS1123Subdomain(probe.ServiceAccount)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
		probes = append(probes, "(variables.group == '' && request.resource.resource == 'configmaps' && request.name == "+ownerCELString(probe.ConfigMap)+" && "+account(probe.ServiceAccount, probe.ServiceAccountUID)+")")
	}
	policy.Spec.Validations[0].Expression = "(" + policy.Spec.Validations[0].Expression + ") || (has(request.dryRun) && request.dryRun && request.operation == 'UPDATE' && variables.sub == '' && (" + strings.Join(probes, " || ") + "))"
	return policy, binding, nil
}

// InitialRuntimeRetainedAdmission retains the original finite initial resource
// set. The owner policy must already be independently proven before installing
// this fixed second candidate; structural equality alone supplies no authority.
func InitialRuntimeRetainedAdmission(p cfg.InitialRuntimeBridgeAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	policy, binding, err := InitialRuntimeProbeAdmission(p)
	if err != nil {
		return nil, nil, err
	}
	// Match conditions cannot reference policy variables. Explicit names keep
	// the old source, credentials, accounts and initial Pod under their original
	// protections while ordinary runtime controllers remain owner-policy duties.
	core := "(!has(request.resource.group) || request.resource.group == '')"
	names := func(values ...string) string {
		out := make([]string, len(values))
		for i, value := range values {
			out[i] = ownerCELString(value)
		}
		return "request.name in [" + strings.Join(out, ",") + "]"
	}
	exact := "(" + core + " && ((request.resource.resource == 'configmaps' && " + names(p.Initial.Configuration, p.Initial.Witness, p.Initial.FleetSource) + ") || (request.resource.resource == 'secrets' && " + names(p.Credentials, p.Credentials+"-probe") + ") || (request.resource.resource == 'serviceaccounts' && " + names(p.Initial.WriterAccount, p.Initial.ProbeAccount) + ") || (request.resource.resource == 'pods' && " + names(p.Initial.PodName) + ")))"
	policy.Spec.MatchConditions = append(policy.Spec.MatchConditions, admission.MatchCondition{Name: "retained-initial-resources", Expression: exact})
	return policy, binding, nil
}
