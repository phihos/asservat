package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
)

const initialContinuityDenial = "Asservat preparation identities must remain occupied and may only lose setup authority."

func preparerWorkload(p contracts.InitialPreparationPlan) InitialInstallerWorkloadPlan {
	w := p.Workload
	audience := ""
	if p.Handover == contracts.InitialPreparationHandoverProtocol {
		audience = p.ProbeAudience
	}
	return InitialInstallerWorkloadPlan{RegistryAuthentication: w.RegistryAuthentication, WriterAudience: audience, Namespace: w.Namespace, Name: w.Name, WriterAccount: w.WriterAccount, ProbeAccount: w.ProbeAccount, Configuration: w.Configuration, Credentials: w.Credentials, Image: w.Image, Witness: w.Witness, FleetSource: w.FleetSource, WitnessGuard: w.WitnessGuard, FleetGuard: w.FleetGuard, WorkloadGuard: w.WorkloadGuard}
}
func preparerAdministration(p contracts.InitialPreparationPlan) cfg.InitialNamespaceAdministration {
	a := cfg.InitialNamespaceAdministration{Name: p.Workload.StagingGuard, Namespace: p.Workload.Namespace, ProbeSource: p.Workload.Journal, Inputs: p.Workload.Configuration}
	for _, v := range p.Administrators {
		a.Administrators = append(a.Administrators, cfg.KubernetesActor{Kind: v.Kind, Name: v.Name})
	}
	return a
}

func validPreparerPlan(p contracts.InitialPreparationPlan) bool {
	if p.Workload.RegistryAuthentication != "" && (p.Workload.RegistryAuthentication != contracts.InitialRegistryAuthentication || p.Handover != contracts.InitialPreparationHandoverProtocol) {
		return false
	}
	if p.SchemaInitialization != "" && (p.SchemaInitialization != contracts.InitialSchemaProtocol || p.Handover != contracts.InitialPreparationHandoverProtocol) {
		return false
	}

	if p.Handover == "" && (p.HistoryProbe != nil || p.HistoryManager != nil) {
		return false
	}
	if p.Handover != "" && (p.Handover != contracts.InitialPreparationHandoverProtocol || p.Continuation != contracts.InitialPreparationActivationProtocol || p.PrivateState == nil || !identity.Text(p.ProbeAudience, 256) || p.HistoryManager == nil || !identity.Text(p.HistoryManager.Name, 63) || p.HistoryManager.OID == 0 || p.HistoryManager.OID == 10 || p.HistoryProbe == nil || !authorization.UUID(p.HistoryProbe.UID) || len(validation.IsDNS1123Subdomain(p.HistoryProbe.Name)) != 0) {
		return false
	}
	if p.PrivateState == nil && p.ProbeAudience != "" || p.PrivateState != nil && (!identity.Text(p.ProbeAudience, 256) || len(validation.IsDNS1123Subdomain(p.Workload.Credentials+"-probe")) != 0) {
		return false
	}
	if p.PrivateState != nil && (p.Continuation != contracts.InitialPreparationActivationProtocol || !authorization.UUID(p.PrivateState.UID) || len(validation.IsDNS1123Subdomain(p.PrivateState.Name)) != 0) {
		return false
	}
	if p.Continuation != "" && p.Continuation != contracts.InitialPreparationActivationProtocol {
		return false
	}
	if !authorization.UUID(p.InstallationID) || !authorization.UUID(p.RequestID) || !authorization.UUID(p.ClusterID) || !authorization.UUID(p.BootstrapNamespace.UID) || p.BootstrapNamespace.Name == p.Workload.Namespace || p.RootName == p.ProbeName || p.ContinuityName == p.Workload.StagingGuard {
		return false
	}
	for _, n := range []string{p.RootName, p.ProbeName, p.ContinuityName, p.Workload.StagingGuard, p.Workload.Journal} {
		if len(validation.IsDNS1123Subdomain(n)) != 0 {
			return false
		}
	}
	if len(validation.IsDNS1123Label(p.BootstrapNamespace.Name)) != 0 {
		return false
	}
	if _, e := BuildInitialInstallerWorkload(preparerWorkload(p)); e != nil {
		return false
	}
	_, _, e := InitialNamespaceAdmission(preparerAdministration(p))
	return e == nil
}

func preparationPlanDigest(p contracts.InitialPreparationPlan) string {
	b, _ := json.Marshal(p)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// The compiled inventory is deliberately closed. No public arbitrary object,
// Secret, TokenRequest, Pod, provider effect or activation enters this set.
func preparerObjects(p contracts.InitialPreparationPlan) ([]initialPreparationResource, error) {
	if !validPreparerPlan(p) {
		return nil, cfg.ErrInvalid
	}
	out := []initialPreparationResource{}
	add := func(group, kind, resource, ns string, v runtime.Object) {
		version := "v1"
		path := "/api/v1"
		if group != "" {
			version = group + "/v1"
			path = "/apis/" + version
		}
		if ns != "" {
			path += "/namespaces/" + ns
		}
		v.GetObjectKind().SetGroupVersionKind(core.SchemeGroupVersion.WithKind(kind))
		if group != "" {
			gv := rbac.SchemeGroupVersion
			if group == admission.GroupName {
				gv = admission.SchemeGroupVersion
			}
			v.GetObjectKind().SetGroupVersionKind(gv.WithKind(kind))
		}
		b, _ := json.Marshal(v)
		d := sha256.Sum256(b)
		out = append(out, initialPreparationResource{object: v, path: path + "/" + resource, namespace: ns, digest: hex.EncodeToString(d[:])})
	}
	ns := &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: p.Workload.Namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}
	add("", "Namespace", "namespaces", "", ns)
	w, _ := BuildInitialInstallerWorkload(preparerWorkload(p))
	for _, a := range w.Accounts {
		add("", "ServiceAccount", "serviceaccounts", p.Workload.Namespace, a)
	}
	for _, a := range w.Roles {
		add(rbac.GroupName, "Role", "roles", p.Workload.Namespace, a)
	}
	for _, a := range w.Bindings {
		add(rbac.GroupName, "RoleBinding", "rolebindings", p.Workload.Namespace, a)
	}
	add(rbac.GroupName, "ClusterRole", "clusterroles", "", w.ClusterRole)
	add(rbac.GroupName, "ClusterRoleBinding", "clusterrolebindings", "", w.ClusterBinding)
	if p.Handover == contracts.InitialPreparationHandoverProtocol {
		// This account has no persistent mutation exception in either guard.
		// Named UPDATE RBAC permits the independent explicit dry-run admission
		// probe; only the separately pinned final guard supplies its denial.
		name := p.Workload.Name + "-history-probe"
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return nil, cfg.ErrInvalid
		}
		add(rbac.GroupName, "Role", "roles", p.Workload.Namespace, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: p.Workload.Namespace}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.Workload.Configuration}, Verbs: []string{"update"}}}})
		add(rbac.GroupName, "RoleBinding", "rolebindings", p.Workload.Namespace, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: p.Workload.Namespace}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: p.BootstrapNamespace.Name, Name: p.HistoryProbe.Name}}})
	}
	return out, nil
}

func preparerMetadata(v runtime.Object) *meta.ObjectMeta {
	if m := preparationMetadata(v); m != nil {
		return m
	}
	switch v := v.(type) {
	case *core.Namespace:
		return &v.ObjectMeta
	case *admission.ValidatingAdmissionPolicy:
		return &v.ObjectMeta
	case *admission.ValidatingAdmissionPolicyBinding:
		return &v.ObjectMeta
	case *core.ConfigMap:
		return &v.ObjectMeta
	}
	return nil
}

// InitialPreparationContinuityAdmission is trusted bootstrap, installed and
// pinned before the producer root or target namespace. The independent probe
// is a separate public anchor, so it can prove enforcement before root CREATE.
// Even a listed administrator cannot delete protected keys or refill retired
// rules/subjects. An administrator able to replace this policy remains trusted.
func InitialPreparationContinuityAdmission(p contracts.InitialPreparationPlan) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	objects, e := preparerObjects(p)
	if e != nil {
		return nil, nil, e
	}
	actors := []string{}
	for _, a := range p.Administrators {
		if a.Kind == "User" {
			actors = append(actors, "request.userInfo.username == "+ownerCELString(a.Name))
		} else {
			actors = append(actors, ownerCELString(a.Name)+" in request.userInfo.groups")
		}
	}
	key := func(group, resource, ns, name string) string {
		namespace := "(has(request.namespace) ? request.namespace : '') == " + ownerCELString(ns)
		if group == "" && resource == "namespaces" {
			// Native Namespace admission reports its object name as the request
			// namespace. This cluster-wide identity is already exact by name;
			// do not let an empty-namespace assumption exclude its deletion.
			namespace = "true"
		}
		return "((has(request.resource.group) ? request.resource.group : '') == " + ownerCELString(group) + " && request.resource.resource == " + ownerCELString(resource) + " && " + namespace + " && ((has(request.name) ? request.name : '') == " + ownerCELString(name) + " || request.operation == 'DELETE' && oldObject != null && oldObject.metadata.name == " + ownerCELString(name) + "))"
	}
	root := key("", "configmaps", p.BootstrapNamespace.Name, p.RootName)
	anchor := key("", "configmaps", p.BootstrapNamespace.Name, p.ProbeName)
	keys := []string{root, anchor}
	privateKey := "false"
	if p.PrivateState != nil {
		privateKey = key("", "secrets", p.BootstrapNamespace.Name, p.PrivateState.Name)
		keys = append(keys, privateKey)
	}
	if p.Continuation == contracts.InitialPreparationActivationProtocol {
		// The staging/final guard governs all other Pod operations. Continuous
		// occupancy prevents a delayed pre-receipt CREATE replacing a winner.
		keys = append(keys, "("+key("", "pods", p.Workload.Namespace, p.Workload.Name)+" && request.operation == 'DELETE')")
	}
	roleKeys, bindingKeys := []string{}, []string{}
	literal := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	for _, o := range objects {
		gvk := o.object.GetObjectKind().GroupVersionKind()
		resource := o.path[strings.LastIndex(o.path, "/")+1:]
		k := key(gvk.Group, resource, o.namespace, preparerMetadata(o.object).Name)
		if gvk.Kind == "Namespace" {
			k = "(" + k + " && request.operation == 'DELETE')"
		}
		keys = append(keys, k)
		switch v := o.object.(type) {
		case *rbac.Role:
			roleKeys = append(roleKeys, "("+k+" && (!has(oldObject.rules) || oldObject.rules == null || size(oldObject.rules) == 0 || oldObject.rules == "+literal(v.Rules)+"))")
		case *rbac.ClusterRole:
			roleKeys = append(roleKeys, "("+k+" && !has(object.aggregationRule) && !has(oldObject.aggregationRule) && (!has(oldObject.rules) || oldObject.rules == null || size(oldObject.rules) == 0 || oldObject.rules == "+literal(v.Rules)+"))")
		case *rbac.RoleBinding:
			bindingKeys = append(bindingKeys, "("+k+" && object.roleRef == "+literal(v.RoleRef)+" && oldObject.roleRef == "+literal(v.RoleRef)+" && (!has(oldObject.subjects) || oldObject.subjects == null || size(oldObject.subjects) == 0 || oldObject.subjects == "+literal(v.Subjects)+"))")
		case *rbac.ClusterRoleBinding:
			bindingKeys = append(bindingKeys, "("+k+" && object.roleRef == "+literal(v.RoleRef)+" && oldObject.roleRef == "+literal(v.RoleRef)+" && (!has(oldObject.subjects) || oldObject.subjects == null || size(oldObject.subjects) == 0 || oldObject.subjects == "+literal(v.Subjects)+"))")
		}
	}
	keys = append(keys, "("+key("", "namespaces", "", p.BootstrapNamespace.Name)+" && request.operation == 'DELETE')")
	// Only resourceVersion may change during retirement. The server supplies
	// managedFields; permitting its update cannot change resource authority.
	sameMeta := "object.metadata.name == oldObject.metadata.name && object.metadata.uid == oldObject.metadata.uid && (!has(object.metadata.labels) && !has(oldObject.metadata.labels) || has(object.metadata.labels) && has(oldObject.metadata.labels) && object.metadata.labels == oldObject.metadata.labels) && object.metadata.annotations == oldObject.metadata.annotations && (!has(object.metadata.ownerReferences) || size(object.metadata.ownerReferences) == 0) && (!has(object.metadata.finalizers) || size(object.metadata.finalizers) == 0) && (!has(oldObject.metadata.ownerReferences) || size(oldObject.metadata.ownerReferences) == 0) && (!has(oldObject.metadata.finalizers) || size(oldObject.metadata.finalizers) == 0) && !has(object.metadata.deletionTimestamp)"
	roles := "(" + strings.Join(roleKeys, " || ") + ") && (!has(object.rules) || object.rules == null || size(object.rules) == 0)"
	bindings := "(" + strings.Join(bindingKeys, " || ") + ") && (!has(object.subjects) || object.subjects == null || size(object.subjects) == 0) && object.roleRef == oldObject.roleRef"
	// Keep the exact historical compiled policy when this capability is absent.
	// Existing pinned guards cannot silently change on a binary upgrade.
	allowed := "(" + strings.Join(actors, " || ") + ") && variables.sub == '' && (request.operation == 'CREATE' && !(" + anchor + ") || request.operation == 'UPDATE' && (" + root + " || (" + sameMeta + ") && (" + roles + " || " + bindings + ")))"
	if p.PrivateState != nil {
		// The retired map is canonical and contains no credential. An immutable
		// retired Secret has no supported transition back to private progress.
		privateUpdate := "(" + privateKey + " && oldObject.metadata.uid == " + ownerCELString(p.PrivateState.UID) + " && " + sameMeta + " && oldObject.type == 'Opaque' && object.type == 'Opaque' && (!has(oldObject.immutable) || !oldObject.immutable) && (!has(oldObject.data) || oldObject.data != {'retired':'dHJ1ZQ=='}) && !has(object.stringData) && ((has(object.data) && size(object.data) == 1 && 'state.json' in object.data && (!has(object.immutable) || !object.immutable)) || (has(object.data) && object.data == {'retired':'dHJ1ZQ=='} && has(object.immutable) && object.immutable)))"
		allowed = "(" + strings.Join(actors, " || ") + ") && variables.sub == '' && (request.operation == 'CREATE' && !(" + anchor + " || " + privateKey + ") || request.operation == 'UPDATE' && (" + root + " || (" + sameMeta + ") && (" + roles + " || " + bindings + ") || " + privateUpdate + "))"
		// TokenRequest is a CREATE on the protected ServiceAccount's token
		// subresource. Permit only this explicit private continuation's fixed
		// finite administrator request. Actual original Secret UID and one-use
		// claim are checked separately by the producer, never inferred here.
		probeToken := "request.operation == 'CREATE' && variables.group == '' && request.resource.resource == 'serviceaccounts' && variables.sub == 'token' && request.namespace == " + ownerCELString(p.Workload.Namespace) + " && request.name == " + ownerCELString(p.Workload.ProbeAccount) + " && has(object.spec) && has(object.spec.audiences) && object.spec.audiences == [" + ownerCELString(p.ProbeAudience) + "] && has(object.spec.expirationSeconds) && object.spec.expirationSeconds == 600 && has(object.spec.boundObjectRef) && object.spec.boundObjectRef.apiVersion == 'v1' && object.spec.boundObjectRef.kind == 'Secret' && object.spec.boundObjectRef.name == " + ownerCELString(p.Workload.Credentials+"-probe") + " && has(object.spec.boundObjectRef.uid) && object.spec.boundObjectRef.uid.matches('^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')"
		allowed = "(" + allowed + ") || ((" + strings.Join(actors, " || ") + ") && (" + probeToken + "))"

	}
	if p.Handover == contracts.InitialPreparationHandoverProtocol {
		// This preinstalled guard cannot know the future Pod UID. Its finite
		// request shape intersects the separately accepted final workload policy,
		// which binds the actual original Pod UID. Neither guard stands alone.
		writerToken := "request.userInfo.username.startsWith('system:node:') && 'system:nodes' in request.userInfo.groups && request.operation == 'CREATE' && variables.group == '' && request.resource.resource == 'serviceaccounts' && variables.sub == 'token' && request.namespace == " + ownerCELString(p.Workload.Namespace) + " && request.name == " + ownerCELString(p.Workload.WriterAccount) + " && has(object.spec) && has(object.spec.audiences) && object.spec.audiences == [" + ownerCELString(p.ProbeAudience) + "] && has(object.spec.expirationSeconds) && object.spec.expirationSeconds == 600 && has(object.spec.boundObjectRef) && object.spec.boundObjectRef.apiVersion == 'v1' && object.spec.boundObjectRef.kind == 'Pod' && object.spec.boundObjectRef.name == " + ownerCELString(p.Workload.Name) + " && has(object.spec.boundObjectRef.uid) && object.spec.boundObjectRef.uid.matches('^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')"
		allowed = "(" + allowed + ") || (" + writerToken + ")"
		// Retirement is a narrow terminal branch. The independently pinned
		// final workload guard additionally binds the real original Pod UID.
		marker := ownerCELString(initialPreparationRetiredAnnotation)
		terminalDelete := key("", "pods", p.Workload.Namespace, p.Workload.Name) + " && request.operation == 'DELETE' && variables.sub == '' && oldObject != null && has(oldObject.metadata.annotations) && " + marker + " in oldObject.metadata.annotations && oldObject.metadata.annotations[" + marker + "] == oldObject.metadata.uid && oldObject.metadata.annotations[" + ownerCELString(initialNamespaceInstallationAnnotation) + "] == " + ownerCELString(p.InstallationID) + " && oldObject.metadata.annotations[" + ownerCELString(initialNamespaceRequestAnnotation) + "] == " + ownerCELString(p.RequestID) + " && has(oldObject.status.phase) && oldObject.status.phase == 'Succeeded' && (((" + strings.Join(actors, " || ") + ")) || ('system:nodes' in request.userInfo.groups && has(oldObject.spec.nodeName) && oldObject.spec.nodeName != '' && request.userInfo.username == 'system:node:' + oldObject.spec.nodeName && has(oldObject.metadata.deletionTimestamp)))"
		allowed = "(" + allowed + ") || (" + terminalDelete + ")"

	}
	fail, equivalent, scope := admission.Fail, admission.Equivalent, admission.AllScopes
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: admission.SchemeGroupVersion.String(), Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.ContinuityName}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, Variables: []admission.Variable{{Name: "group", Expression: "has(request.resource.group) ? request.resource.group : ''"}, {Name: "sub", Expression: "has(request.subResource) ? request.subResource : ''"}}, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete, admission.Connect}, Rule: admission.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*/*"}, Scope: &scope}}}}}, MatchConditions: []admission.MatchCondition{{Name: "initial-preparation-continuity", Expression: strings.Join(keys, " || ")}}, Validations: []admission.Validation{{Expression: allowed, Message: initialContinuityDenial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: admission.SchemeGroupVersion.String(), Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.ContinuityName}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.ContinuityName, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

// BuildInitialPreparationRoot creates public desired provenance only. Helm must
// not own this mutable ConfigMap: the supervisor uses this body once under the
// pinned continuity policy and thereafter only exact UID/resourceVersion CAS.
func BuildInitialPreparationRoot(p contracts.InitialPreparationPlan) (*core.ConfigMap, error) {
	if !validPreparerPlan(p) {
		return nil, cfg.ErrInvalid
	}
	state := contracts.InitialPreparationRoot{Format: contracts.InitialPreparationRootFormat, InstallationID: p.InstallationID, RequestID: p.RequestID, PlanDigest: preparationPlanDigest(p), Phase: "declaring", Creates: []contracts.InitialPreparationCreate{}}
	b, e := json.Marshal(state)
	if e != nil || len(b) > contracts.InitialPreparationMaxBytes {
		return nil, cfg.ErrInvalid
	}
	return &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: p.RootName, Namespace: p.BootstrapNamespace.Name, Annotations: map[string]string{initialNamespaceInstallationAnnotation: p.InstallationID, initialNamespaceRequestAnnotation: p.RequestID}}, Data: map[string]string{"root.json": string(b)}}, nil
}

func validPreparerReceipt(r *contracts.InitialPreparationReceipt) bool {
	return r == nil || authorization.UUID(r.UID) && identity.Text(r.ResourceVersion, 128)
}
