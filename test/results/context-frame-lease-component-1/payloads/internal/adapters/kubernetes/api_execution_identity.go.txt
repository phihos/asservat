package kubernetes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const apiExecutionDenial = "Asservat regional API execution namespace requires its exact administrator or bounded role operation."

// APIExecutionPodDigest excludes scheduler assignment only. All other fields,
// including credentials, containers, volumes and resource limits, stay pinned.
func APIExecutionPodDigest(spec core.PodSpec) artifact.Digest {
	s := spec.DeepCopy()
	s.NodeName = ""
	b, _ := json.Marshal(s)
	return artifact.Digest(sha256.Sum256(b))
}
func APIExecutionAdmission(p cfg.APIExecutionAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || len(validation.IsDNS1123Label(p.ControlNamespace.Name)) != 0 {
		return nil, nil, cfg.ErrInvalid
	}
	for _, name := range []string{p.PodName, p.Account, p.CapacityAccount, p.ProbeAccount} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
	}
	var allowed []string
	for _, a := range p.Administrators {
		if a.Kind == "User" {
			allowed = append(allowed, "request.userInfo.username == "+ownerCELString(a.Name))
		} else {
			allowed = append(allowed, ownerCELString(a.Name)+" in request.userInfo.groups")
		}
	}
	user := func(name string) string {
		return ownerCELString("system:serviceaccount:" + p.ControlNamespace.Name + ":" + name)
	}
	// After an administrator starts foreground deletion, GC must remove its
	// own finalizer. Permit only that removal on this exact deleting Pod; it
	// confers no workload mutation, new deletion, or other finalizer authority.
	gcFinalization := "object.spec == oldObject.spec && has(oldObject.metadata.finalizers) && 'foregroundDeletion' in oldObject.metadata.finalizers"
	gcFinalization += " && (has(object.metadata.finalizers) ? object.metadata.finalizers : []) == oldObject.metadata.finalizers.filter(f, f != 'foregroundDeletion')"
	for _, field := range []string{"labels", "annotations", "ownerReferences"} {
		gcFinalization += " && (has(object.metadata." + field + ") == has(oldObject.metadata." + field + ")) && (!has(object.metadata." + field + ") || object.metadata." + field + " == oldObject.metadata." + field + ")"
	}
	allowed = append(allowed,
		"(request.userInfo.username in ['system:kube-controller-manager', 'system:serviceaccount:kube-system:generic-garbage-collector'] && variables.group == '' && request.resource.resource == 'pods' && variables.sub == '' && request.operation == 'UPDATE' && request.name == "+ownerCELString(p.PodName)+" && oldObject.metadata.uid == "+ownerCELString(p.PodUID)+" && object.metadata.uid == oldObject.metadata.uid && has(oldObject.metadata.deletionTimestamp) && ("+gcFinalization+"))",
		"(variables.group == 'asservat.io' && request.resource.resource == 'capacityreservations' && request.operation in ['CREATE','UPDATE'] && ((request.userInfo.username == "+user(p.CapacityAccount)+" && request.userInfo.uid == "+ownerCELString(p.CapacityAccountUID)+") || (request.userInfo.username == "+user(p.Account)+" && request.userInfo.uid == "+ownerCELString(p.AccountUID)+")))",
		"(request.userInfo.username == 'system:kube-scheduler' && variables.group == '' && request.resource.resource == 'pods' && request.name == "+ownerCELString(p.PodName)+" && ((variables.sub == 'binding' && request.operation == 'CREATE') || (variables.sub == 'status' && request.operation == 'UPDATE')))",
		"('system:nodes' in request.userInfo.groups && variables.group == '' && request.resource.resource == 'pods' && request.name == "+ownerCELString(p.PodName)+" && has(oldObject.spec.nodeName) && oldObject.spec.nodeName != '' && request.userInfo.username == 'system:node:' + oldObject.spec.nodeName && oldObject.metadata.uid == "+ownerCELString(p.PodUID)+" && ((variables.sub == 'status' && request.operation == 'UPDATE') || (variables.sub == '' && request.operation == 'DELETE' && has(oldObject.metadata.deletionTimestamp) && has(oldObject.status.phase) && oldObject.status.phase in ['Succeeded','Failed'])))",
		"(request.userInfo.username.startsWith('system:node:') && 'system:nodes' in request.userInfo.groups && variables.group == '' && request.resource.resource == 'serviceaccounts' && variables.sub == 'token' && request.operation == 'CREATE' && request.name == "+ownerCELString(p.Account)+" && has(object.spec.boundObjectRef) && object.spec.boundObjectRef.kind == 'Pod' && object.spec.boundObjectRef.name == "+ownerCELString(p.PodName)+" && object.spec.boundObjectRef.uid == "+ownerCELString(p.PodUID)+")",
		"(variables.group in ['', 'events.k8s.io'] && request.resource.resource == 'events' && variables.sub == '' && request.operation in ['CREATE','UPDATE','DELETE'])")
	fail, equivalent, scope := admission.Fail, admission.Equivalent, admission.NamespacedScope
	policy := &admission.ValidatingAdmissionPolicy{ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, Variables: []admission.Variable{{Name: "group", Expression: "has(request.resource.group) ? request.resource.group : ''"}, {Name: "sub", Expression: "has(request.subResource) ? request.subResource : ''"}}, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete, admission.Connect}, Rule: admission.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*/*"}, Scope: &scope}}}}}, MatchConditions: []admission.MatchCondition{{Name: "regional-api-execution-namespace", Expression: "request.namespace == " + ownerCELString(p.ControlNamespace.Name)}}, Validations: []admission.Validation{{Expression: strings.Join(allowed, " || "), Message: apiExecutionDenial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

type APIExecutionProtection struct {
	observer, probe *PermissionClient
	plan            cfg.APIExecutionAdministration
	pin             GuardPin
	policy          admission.ValidatingAdmissionPolicySpec
	binding         admission.ValidatingAdmissionPolicyBindingSpec
	digest          artifact.Digest
}

func NewAPIExecutionProtection(observer, probe *PermissionClient, p cfg.APIExecutionAdministration, pin GuardPin) (*APIExecutionProtection, error) {
	if observer == nil || probe == nil || observer == probe || observer.clusterID != p.ClusterID || probe.clusterID != p.ClusterID || observer.control != p.ControlNamespace || probe.control != p.ControlNamespace || !identity.Text(pin.PolicyUID, 64) || !identity.Text(pin.BindingUID, 64) || !identity.Text(pin.BindingResourceVersion, 128) || pin.PolicyGeneration < 1 {
		return nil, cfg.ErrInvalid
	}
	policy, binding, err := APIExecutionAdmission(p)
	if err != nil {
		return nil, err
	}
	p.Administrators = append([]cfg.KubernetesActor(nil), p.Administrators...)
	normalizePermissionPolicy(&policy.Spec)
	raw, _ := json.Marshal(struct {
		Plan cfg.APIExecutionAdministration
		Pin  GuardPin
	}{p, pin})
	return &APIExecutionProtection{observer, probe, p, pin, policy.Spec, binding.Spec, artifact.Digest(sha256.Sum256(raw))}, nil
}
func (g *APIExecutionProtection) account(ctx context.Context, c *PermissionClient, name, uid string, bound bool) error {
	raw, err := c.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who auth.SelfSubjectReview
	if err != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+g.plan.ControlNamespace.Name+":"+name || who.Status.UserInfo.UID != uid {
		return cfg.ErrUnavailable
	}
	for _, a := range g.plan.Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return cfg.ErrInvalid
		}
	}
	if bound {
		for k, v := range map[string]string{"authentication.kubernetes.io/pod-name": g.plan.PodName, "authentication.kubernetes.io/pod-uid": g.plan.PodUID} {
			values := who.Status.UserInfo.Extra[k]
			if len(values) != 1 || values[0] != v {
				return cfg.ErrUnavailable
			}
		}
	}
	raw, err = g.observer.raw(ctx, "/api/v1/namespaces/"+g.plan.ControlNamespace.Name+"/serviceaccounts/"+name, nil)
	var account core.ServiceAccount
	if err != nil || json.Unmarshal(raw, &account) != nil || account.APIVersion != "v1" || account.Kind != "ServiceAccount" || !ownerMetadata(account.ObjectMeta, g.plan.ControlNamespace.Name, name, uid) {
		return cfg.ErrChanged
	}
	return nil
}
func (g *APIExecutionProtection) current(ctx context.Context) (time.Time, error) {
	if g == nil || ctx == nil {
		return time.Time{}, cfg.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := g.observer.now()
	until := start.Add(5 * time.Second)
	if err := g.account(ctx, g.probe, g.plan.ProbeAccount, g.plan.ProbeAccountUID, false); err != nil {
		return time.Time{}, err
	}
	ns, err := g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil || ns.Deleting {
		return time.Time{}, cfg.ErrChanged
	}
	first, err := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil {
		return time.Time{}, err
	}
	path := "/api/v1/namespaces/" + g.plan.ControlNamespace.Name + "/pods/" + g.plan.PodName
	denied := false
	for attempt := 0; attempt < 3; attempt++ {
		if g.observer.current(ctx, start, 5*time.Second) != nil {
			return time.Time{}, cfg.ErrUnavailable
		}
		raw, err := g.observer.raw(ctx, path, nil)
		var pod core.Pod
		if err != nil || json.Unmarshal(raw, &pod) != nil || pod.APIVersion != "v1" || pod.Kind != "Pod" || !ownerMetadata(pod.ObjectMeta, g.plan.ControlNamespace.Name, g.plan.PodName, g.plan.PodUID) || len(pod.OwnerReferences) != 0 || pod.Spec.ServiceAccountName != g.plan.Account || pod.Spec.HostPID || pod.Spec.HostIPC || pod.Spec.HostNetwork || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.Containers) != 1 || pod.Spec.NodeName == "" || (pod.Status.Phase != core.PodPending && pod.Status.Phase != core.PodRunning) || APIExecutionPodDigest(pod.Spec) != g.plan.PodSpecDigest {
			return time.Time{}, cfg.ErrChanged
		}
		if !restrictedAPIExecutionPod(pod.Spec) || !digestPinnedAPIImage(pod.Spec.Containers[0].Image) || !strings.HasSuffix(pod.Spec.Containers[0].Image, "@sha256:"+hex.EncodeToString(g.plan.ImageDigest[:])) {
			return time.Time{}, cfg.ErrInvalid
		}
		// Independent dry-run denial proves this exact policy, not a successful GET.
		response := g.probe.api.Put().AbsPath(path).Param("dryRun", "All").Param("fieldValidation", "Strict").Body(raw).MaxRetries(0).Do(ctx)
		body, _ := response.Raw()
		if exactAPIExecutionConflict(response.Error(), body, g.plan.PodName, g.plan.PodUID) {
			continue
		}
		if !exactAPIExecutionDenial(response.Error(), body, g.plan.Name) {
			return time.Time{}, cfg.ErrUnavailable
		}
		denied = true
		break
	}
	if !denied {
		return time.Time{}, cfg.ErrUnavailable
	}
	last, err := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil || first != last {
		return time.Time{}, cfg.ErrChanged
	}
	ns, err = g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil || ns.Deleting {
		return time.Time{}, cfg.ErrChanged
	}
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if ctx.Err() != nil || g.observer.now().Before(start) || !g.observer.now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	return until, nil
}
func restrictedAPIExecutionPod(p core.PodSpec) bool {
	if p.SecurityContext == nil || p.SecurityContext.RunAsNonRoot == nil || !*p.SecurityContext.RunAsNonRoot || p.SecurityContext.SeccompProfile == nil || p.SecurityContext.SeccompProfile.Type != core.SeccompProfileTypeRuntimeDefault {
		return false
	}
	for _, v := range p.Volumes {
		if v.HostPath != nil {
			return false
		}
	}
	for _, c := range p.Containers {
		s := c.SecurityContext
		if s == nil || s.Privileged != nil && *s.Privileged || s.AllowPrivilegeEscalation == nil || *s.AllowPrivilegeEscalation || s.ReadOnlyRootFilesystem == nil || !*s.ReadOnlyRootFilesystem || s.Capabilities == nil || len(s.Capabilities.Add) != 0 || len(s.Capabilities.Drop) != 1 || s.Capabilities.Drop[0] != "ALL" {
			return false
		}
	}
	return true
}

// APIExecutionProcess owns one fresh epoch and cannot outlive its startup context.
// A background consumer context never detaches it from that process lifetime.
type APIExecutionProcess struct {
	guard   *APIExecutionProtection
	parent  context.Context
	binding value.APIProcessBinding
}

func NewAPIExecutionProcess(parent context.Context, g *APIExecutionProtection) (*APIExecutionProcess, error) {
	if parent == nil || parent.Err() != nil || g == nil {
		return nil, value.ErrInvalid
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, value.ErrUnavailable
	}
	nonce[6] = (nonce[6] & 15) | 64
	nonce[8] = (nonce[8] & 63) | 128
	epoch := fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
	p := g.plan
	return &APIExecutionProcess{g, parent, value.APIProcessBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, NamespaceUID: p.ControlNamespace.UID, AccountUID: p.AccountUID, PodUID: p.PodUID, ProcessEpoch: epoch, StartupDigest: g.digest, ImageDigest: p.ImageDigest}}, nil
}
func (p *APIExecutionProcess) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	var zero value.APIProcessObservation
	if p == nil || p.parent.Err() != nil || ctx == nil {
		return zero, value.ErrUnavailable
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.parent, cancel)
	defer func() { stop(); cancel() }()
	start := p.guard.observer.now()
	until, err := p.guard.current(ctx)
	if err != nil {
		return zero, err
	}
	if err = p.guard.account(ctx, p.guard.observer, p.guard.plan.Account, p.guard.plan.AccountUID, true); err != nil {
		return zero, err
	}
	until = identity.Earlier(until, start.Add(5*time.Second))
	out := value.APIProcessObservation{Binding: p.binding, CheckedAt: start, ValidUntil: until}
	if p.parent.Err() != nil || ctx.Err() != nil || !out.Valid(p.guard.observer.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}

func digestPinnedAPIImage(image string) bool {
	parts := strings.Split(image, "@sha256:")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) != 64 || parts[1] != strings.ToLower(parts[1]) {
		return false
	}
	_, err := hex.DecodeString(parts[1])
	return err == nil
}
