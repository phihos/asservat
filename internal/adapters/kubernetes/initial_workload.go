package kubernetes

import (
	"crypto/sha256"
	"encoding/json"
	"strings"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const initialWorkloadDenial = "Asservat initial installation requires the pinned administrator or bounded installer operation."

// InstallationPodSpecDigest excludes only scheduler assignment and the
// removable launch gate. The server-defaulted remainder must match exactly.
func InstallationPodSpecDigest(spec core.PodSpec) artifact.Digest {
	s := spec.DeepCopy()
	s.NodeName, s.SchedulingGates = "", nil
	b, _ := json.Marshal(s)
	return artifact.Digest(sha256.Sum256(b))
}

func InitialWorkloadAdmission(p cfg.InitialWorkloadAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Label(p.ControlNamespace.Name)) != 0 {
		return nil, nil, cfg.ErrInvalid
	}
	for _, n := range []string{p.Name, p.Configuration, p.Witness, p.FleetSource, p.PodName, p.WriterAccount, p.ProbeAccount} {
		if len(validation.IsDNS1123Subdomain(n)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
	}
	user := func(n string) string {
		return ownerCELString("system:serviceaccount:" + p.ControlNamespace.Name + ":" + n)
	}
	var allowed []string
	for _, a := range p.Administrators {
		if a.Kind == "User" {
			allowed = append(allowed, "request.userInfo.username == "+ownerCELString(a.Name))
		} else {
			allowed = append(allowed, ownerCELString(a.Name)+" in request.userInfo.groups")
		}
	}
	allowed = append(allowed,
		"(request.operation == 'UPDATE' && variables.group == '' && request.resource.resource == 'configmaps' && variables.sub == '' && request.name == "+ownerCELString(p.Witness)+" && request.userInfo.username == "+user(p.WriterAccount)+" && request.userInfo.uid == "+ownerCELString(p.WriterAccountUID)+")",
		"(has(request.dryRun) && request.dryRun && request.operation == 'UPDATE' && variables.group == '' && request.resource.resource == 'configmaps' && variables.sub == '' && request.name in ["+ownerCELString(p.Witness)+","+ownerCELString(p.FleetSource)+"] && request.userInfo.username == "+user(p.ProbeAccount)+" && request.userInfo.uid == "+ownerCELString(p.ProbeAccountUID)+")",
		"(request.userInfo.username == 'system:kube-scheduler' && variables.group == '' && request.resource.resource == 'pods' && request.name == "+ownerCELString(p.PodName)+" && ((variables.sub == 'binding' && request.operation == 'CREATE') || (variables.sub == 'status' && request.operation == 'UPDATE')))",
		"('system:nodes' in request.userInfo.groups && variables.group == '' && request.resource.resource == 'pods' && request.name == "+ownerCELString(p.PodName)+" && has(oldObject.spec.nodeName) && oldObject.spec.nodeName != '' && request.userInfo.username == 'system:node:' + oldObject.spec.nodeName && oldObject.metadata.uid == "+ownerCELString(p.PodUID)+" && ((variables.sub == 'status' && request.operation == 'UPDATE') || (variables.sub == '' && request.operation == 'DELETE' && has(oldObject.metadata.deletionTimestamp) && has(oldObject.status.phase) && oldObject.status.phase in ['Succeeded','Failed'])))",
		"(request.userInfo.username.startsWith('system:node:') && 'system:nodes' in request.userInfo.groups && variables.group == '' && request.resource.resource == 'serviceaccounts' && variables.sub == 'token' && request.operation == 'CREATE' && request.name == "+ownerCELString(p.WriterAccount)+" && has(object.spec.boundObjectRef) && object.spec.boundObjectRef.kind == 'Pod' && object.spec.boundObjectRef.name == "+ownerCELString(p.PodName)+" && object.spec.boundObjectRef.uid == "+ownerCELString(p.PodUID)+")",
		"(variables.group in ['', 'events.k8s.io'] && request.resource.resource == 'events' && variables.sub == '' && request.operation in ['CREATE','UPDATE','DELETE'])",
	)
	fail, equivalent, scope := admission.Fail, admission.Equivalent, admission.NamespacedScope
	policy := &admission.ValidatingAdmissionPolicy{ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, Variables: []admission.Variable{{Name: "group", Expression: "has(request.resource.group) ? request.resource.group : ''"}, {Name: "sub", Expression: "has(request.subResource) ? request.subResource : ''"}}, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete, admission.Connect}, Rule: admission.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*/*"}, Scope: &scope}}}}}, MatchConditions: []admission.MatchCondition{{Name: "initial-installer-namespace", Expression: "request.namespace == " + ownerCELString(p.ControlNamespace.Name)}}, Validations: []admission.Validation{{Expression: strings.Join(allowed, " || "), Message: initialWorkloadDenial}}}}
	if p.Handover {
		// The final guard knows the actual Pod UID. The bootstrap continuity guard
		// alone intentionally cannot authorize replacement or infer cleanup state.
		k := ownerCELString(initialPreparationRetiredAnnotation)
		exact := "oldObject.metadata.uid == " + ownerCELString(p.PodUID) + " && has(oldObject.status.phase) && oldObject.status.phase == 'Succeeded'"
		marker := "has(oldObject.metadata.annotations) && " + k + " in oldObject.metadata.annotations && oldObject.metadata.annotations[" + k + "] == " + ownerCELString(p.PodUID)
		unchanged := "object.spec == oldObject.spec && object.metadata.uid == oldObject.metadata.uid && (!has(object.metadata.ownerReferences) || size(object.metadata.ownerReferences) == 0) && (!has(object.metadata.finalizers) || size(object.metadata.finalizers) == 0) && object.metadata.labels == oldObject.metadata.labels"
		metadata := "object.metadata.annotations == oldObject.metadata.annotations || (size(object.metadata.annotations) == size(oldObject.metadata.annotations)+1 && object.metadata.annotations.all(k, k == " + k + " || k in oldObject.metadata.annotations && object.metadata.annotations[k] == oldObject.metadata.annotations[k]) && object.metadata.annotations[" + k + "] == " + ownerCELString(p.PodUID) + ")"
		pod := "variables.group == '' && request.resource.resource == 'pods' && request.name == " + ownerCELString(p.PodName) + " && variables.sub == ''"
		update := "!(" + pod + " && request.operation == 'UPDATE' && ((has(object.metadata.annotations) && " + k + " in object.metadata.annotations) || (has(oldObject.metadata.annotations) && " + k + " in oldObject.metadata.annotations))) || (" + exact + " && has(object.metadata.annotations) && " + k + " in object.metadata.annotations && object.metadata.annotations[" + k + "] == " + ownerCELString(p.PodUID) + " && " + unchanged + " && (" + metadata + "))"
		deletion := "!(" + pod + " && request.operation == 'DELETE') || (" + exact + " && " + marker + ")"
		policy.Spec.Validations = append(policy.Spec.Validations, admission.Validation{Expression: update, Message: initialWorkloadDenial}, admission.Validation{Expression: deletion, Message: initialWorkloadDenial})
	}
	binding := &admission.ValidatingAdmissionPolicyBinding{ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

type InitialWorkloadProtection struct {
	guard *configMapProtection
	plan  cfg.InitialWorkloadAdministration
}

func NewInitialWorkloadProtection(writer, probe *PermissionClient, p cfg.InitialWorkloadAdministration, pin GuardPin) (*InitialWorkloadProtection, error) {
	p.Administrators = append([]cfg.KubernetesActor(nil), p.Administrators...)
	policy, binding, err := InitialWorkloadAdmission(p)
	if err != nil {
		return nil, err
	}
	g, err := newConfigMapProtection(writer, probe, cfg.ConfigMapAdministration{Name: p.Name, SourceName: p.Configuration, ControlNamespace: p.ControlNamespace, Administrators: p.Administrators}, pin, "initial-installer-namespace", initialWorkloadDenial)
	if err != nil {
		return nil, err
	}
	normalizePermissionPolicy(&policy.Spec)
	b, _ := json.Marshal(struct {
		Plan cfg.InitialWorkloadAdministration
		Pin  GuardPin
	}{p, pin})
	g.policy, g.binding, g.digest = policy.Spec, binding.Spec, artifact.Digest(sha256.Sum256(b))
	return &InitialWorkloadProtection{g, p}, nil
}
