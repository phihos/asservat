package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const ownerWorkloadDenial = "Asservat private hub namespace requires an installation administrator or a qualified Kubernetes controller operation."

// These are exact built-in controller identities, not prefixes or a general
// service-account group. Each entry additionally restricts resources/operations.
// The shared controller-manager identity supports clusters without per-controller
// credentials; it remains subject to this union and ordinary Kubernetes RBAC.
type ownerControllerRule struct {
	names      []string
	expression string
}

func ownerControllerRules() []ownerControllerRule {
	// GC updates finalizers/owner references, never workload specs or labels.
	// The wildcard policy cannot schema-type-check these object fields; keep
	// the branch kind-gated and qualify all supported native resource shapes.
	metadataOnly := "has(object.spec) && has(oldObject.spec) && object.spec == oldObject.spec"
	for _, field := range []string{"labels", "annotations"} {
		metadataOnly += " && (has(object.metadata." + field + ") == has(oldObject.metadata." + field + ")) && (!has(object.metadata." + field + ") || object.metadata." + field + " == oldObject.metadata." + field + ")"
	}
	return []ownerControllerRule{
		{[]string{"deployment-controller"}, "request.resource.group == 'apps' && ((request.resource.resource == 'deployments' && request.subResource == 'status') || (request.resource.resource == 'replicasets' && request.subResource == ''))"},
		{[]string{"replicaset-controller"}, "(request.resource.group == 'apps' && request.resource.resource == 'replicasets' && request.subResource == 'status') || (request.resource.group == '' && request.resource.resource == 'pods' && request.subResource == '')"},
		{[]string{"statefulset-controller"}, "(request.resource.group == 'apps' && ((request.resource.resource == 'statefulsets' && request.subResource == 'status') || request.resource.resource == 'controllerrevisions')) || (request.resource.group == '' && request.resource.resource in ['pods', 'persistentvolumeclaims'] && request.subResource == '')"},
		{[]string{"daemon-set-controller"}, "(request.resource.group == 'apps' && ((request.resource.resource == 'daemonsets' && request.subResource == 'status') || request.resource.resource == 'controllerrevisions')) || (request.resource.group == '' && request.resource.resource == 'pods' && request.subResource == '')"},
		{[]string{"job-controller"}, "(request.resource.group == 'batch' && request.resource.resource == 'jobs' && request.subResource in ['', 'status']) || (request.resource.group == '' && request.resource.resource == 'pods' && request.subResource in ['', 'status'])"},
		{[]string{"cronjob-controller"}, "request.resource.group == 'batch' && ((request.resource.resource == 'cronjobs' && request.subResource == 'status') || (request.resource.resource == 'jobs' && request.subResource == ''))"},
		{[]string{"replication-controller"}, "request.resource.group == '' && ((request.resource.resource == 'replicationcontrollers' && request.subResource == 'status') || (request.resource.resource == 'pods' && request.subResource == ''))"},
		{[]string{"horizontal-pod-autoscaler"}, "(request.subResource == 'scale' && request.resource.group in ['', 'apps'] && request.resource.resource in ['replicationcontrollers', 'deployments', 'replicasets', 'statefulsets']) || (request.resource.group == 'autoscaling' && request.resource.resource == 'horizontalpodautoscalers' && request.subResource == 'status')"},
		{[]string{"endpointslice-controller", "endpointslicemirroring-controller"}, "request.resource.group == 'discovery.k8s.io' && request.resource.resource == 'endpointslices' && request.subResource == ''"},
		{[]string{"endpoint-controller"}, "request.resource.group == '' && request.resource.resource == 'endpoints' && request.subResource == ''"},
		{[]string{"service-account-controller"}, "request.resource.group == '' && request.resource.resource == 'serviceaccounts' && request.subResource == ''"},
		{[]string{"resourcequota-controller"}, "request.resource.group == '' && request.resource.resource == 'resourcequotas' && request.subResource == 'status'"},
		{[]string{"generic-garbage-collector"}, "request.operation == 'UPDATE' && request.subResource == '' && ((request.resource.group == 'apps' && request.resource.resource in ['deployments', 'replicasets']) || (request.resource.group == '' && request.resource.resource == 'pods')) && (" + metadataOnly + ")"},
		{[]string{"generic-garbage-collector", "namespace-controller", "ttl-after-finished-controller"}, "request.operation == 'DELETE' && request.subResource == ''"},
	}
}

func ownerCELString(s string) string         { b, _ := json.Marshal(s); return string(b) }
func ownerControllerUser(name string) string { return "system:serviceaccount:kube-system:" + name }

// OwnerWorkloadAdmission narrows writes only in the private hub namespace.
// It does not grant RBAC, authorize Secret reads, or protect against cluster
// administrators, compromised nodes/controllers or preexisting compromise.
func OwnerWorkloadAdmission(p cfg.OwnerWorkloadAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || len(validation.IsDNS1123Subdomain(p.Deployment)) != 0 || len(validation.IsDNS1123Label(p.ControlNamespace.Name)) != 0 {
		return nil, nil, cfg.ErrInvalid
	}
	var allowed []string
	if probe := p.InitialHistoryProbe; probe != nil {
		if len(validation.IsDNS1123Label(probe.Namespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(probe.ServiceAccount)) != 0 || len(validation.IsDNS1123Subdomain(probe.Configuration)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
		// This is the one retained original history probe, not general
		// cross-namespace access. The independently checked initial guard must
		// deny it. The reader also verifies live bootstrap namespace/account UIDs.
		allowed = append(allowed, "(has(request.dryRun) && request.dryRun && request.operation == 'UPDATE' && request.resource.group == '' && request.resource.resource == 'configmaps' && request.subResource == '' && request.name == "+ownerCELString(probe.Configuration)+" && request.userInfo.username == "+ownerCELString("system:serviceaccount:"+probe.Namespace.Name+":"+probe.ServiceAccount)+" && request.userInfo.uid == "+ownerCELString(probe.ServiceAccountUID)+")")
	}
	if a := p.CapacityProbe; a != nil {
		if len(validation.IsDNS1123Subdomain(a.ServiceAccount)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
		allowed = append(allowed, "(has(request.dryRun) && request.dryRun && request.operation == 'CREATE' && request.resource.group == 'asservat.io' && request.resource.version == 'v1alpha1' && request.resource.resource in ['evidencestoragepools', 'evidencebudgetpolicies', 'accessbindings', 'evidenceretentionpolicies'] && request.subResource == '' && request.userInfo.username == "+ownerCELString("system:serviceaccount:"+p.ControlNamespace.Name+":"+a.ServiceAccount)+" && request.userInfo.uid == "+ownerCELString(a.ServiceAccountUID)+")")
	}
	if a := p.APIContextStarts; a != nil {
		if len(validation.IsDNS1123Subdomain(a.CapacityAccount)) != 0 || len(validation.IsDNS1123Subdomain(a.ExecutionAccount)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
		account := func(name, uid string) string {
			return "(request.userInfo.username == " + ownerCELString("system:serviceaccount:"+p.ControlNamespace.Name+":"+name) + " && request.userInfo.uid == " + ownerCELString(uid) + ")"
		}
		capacity := account(a.CapacityAccount, a.CapacityAccountUID)
		execution := account(a.ExecutionAccount, a.ExecutionAccountUID)
		// Only the main CREATE and exact status UPDATE exist in the first profile.
		// StartAdmission independently pins body, immutable binding and Ready/start.
		allowed = append(allowed, "(request.resource.group == 'asservat.io' && request.resource.resource == 'capacityreservations' && ((request.operation == 'CREATE' && request.subResource == '' && "+capacity+") || (request.operation == 'UPDATE' && request.subResource == 'status' && ("+capacity+" || "+execution+"))))")
		if a.CapacityAudience != "" {
			// ADR-175: only the execution Pod's own Pod-bound credential may mint
			// the capacity account's token: 600 seconds, one audience, unbound
			// (the API server refuses to bind it to a Pod of another account).
			extra := func(key string) string {
				return "request.userInfo.extra[" + ownerCELString(key) + "]"
			}
			pod := "has(request.userInfo.extra) && " + ownerCELString("authentication.kubernetes.io/pod-uid") + " in request.userInfo.extra && size(" + extra("authentication.kubernetes.io/pod-uid") + ") == 1"
			token := "has(object.spec) && has(object.spec.audiences) && object.spec.audiences == [" + ownerCELString(a.CapacityAudience) + "] && has(object.spec.expirationSeconds) && object.spec.expirationSeconds == 600 && " + capacityTokenUnbound
			allowed = append(allowed, "(request.operation == 'CREATE' && request.resource.group == '' && request.resource.resource == 'serviceaccounts' && request.subResource == 'token' && request.name == "+ownerCELString(a.CapacityAccount)+" && "+execution+" && "+pod+" && "+token+")")
		}
	}
	for _, lease := range p.SchedulingLeases {
		if len(validation.IsDNS1123Subdomain(lease.Lease)) != 0 || len(validation.IsDNS1123Subdomain(lease.ServiceAccount)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
		// Scheduling needs persistent updates, but no create/delete, other
		// resource or credential permission. RBAC and the runtime's original
		// namespace/Lease UID and CAS checks remain independent requirements.
		allowed = append(allowed, "(request.operation == 'UPDATE' && request.resource.group == 'coordination.k8s.io' && request.resource.resource == 'leases' && request.subResource == '' && request.name == "+ownerCELString(lease.Lease)+" && request.userInfo.username == "+ownerCELString("system:serviceaccount:"+p.ControlNamespace.Name+":"+lease.ServiceAccount)+")")
	}
	for _, secret := range p.CredentialSecrets {
		if len(validation.IsDNS1123Subdomain(secret.Secret)) != 0 || len(validation.IsDNS1123Subdomain(secret.ServiceAccount)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
		// The connector CAS-writes its own credential Secret; RBAC (get/update
		// on this name) and the runtime's pinned UID and CAS stay independent.
		allowed = append(allowed, "(request.operation == 'UPDATE' && request.resource.group == '' && request.resource.resource == 'secrets' && request.subResource == '' && request.name == "+ownerCELString(secret.Secret)+" && request.userInfo.username == "+ownerCELString("system:serviceaccount:"+p.ControlNamespace.Name+":"+secret.ServiceAccount)+")")
	}
	for _, probe := range p.ConfigurationProbes {
		if len(validation.IsDNS1123Subdomain(probe.ConfigMap)) != 0 || len(validation.IsDNS1123Subdomain(probe.ServiceAccount)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
		// Kubernetes does not promise which denial is reported when policies
		// overlap. Only a named, nonpersistent source probe can pass this
		// guard so its independent source policy remains observable. Missing
		// dryRun, real writes, subresources and every other actor remain denied.
		allowed = append(allowed, "(has(request.dryRun) && request.dryRun && request.operation == 'UPDATE' && request.resource.group == '' && request.resource.resource == 'configmaps' && request.subResource == '' && request.name == "+ownerCELString(probe.ConfigMap)+" && request.userInfo.username == "+ownerCELString("system:serviceaccount:"+p.ControlNamespace.Name+":"+probe.ServiceAccount)+")")
	}
	for _, a := range p.Administrators {
		if a.Kind == "User" {
			allowed = append(allowed, "request.userInfo.username == "+ownerCELString(a.Name))
		} else {
			allowed = append(allowed, ownerCELString(a.Name)+" in request.userInfo.groups")
		}
	}
	for _, rule := range ownerControllerRules() {
		names := []string{ownerCELString("system:kube-controller-manager")}
		for _, name := range rule.names {
			names = append(names, ownerCELString(ownerControllerUser(name)))
		}
		allowed = append(allowed, "(request.userInfo.username in ["+strings.Join(names, ",")+"] && request.operation in ['CREATE', 'UPDATE', 'DELETE'] && ("+rule.expression+"))")
	}
	allowed = append(allowed,
		// Kubelet final removal follows a prior authorized deletion and terminal
		// status. Retain exact assigned-node identity and ordinary NodeRestriction.
		"(request.operation == 'DELETE' && request.resource.group == '' && request.resource.resource == 'pods' && request.subResource == '' && 'system:nodes' in request.userInfo.groups && has(oldObject.spec.nodeName) && oldObject.spec.nodeName != '' && request.userInfo.username == 'system:node:' + oldObject.spec.nodeName && has(oldObject.metadata.deletionTimestamp) && has(oldObject.status.phase) && oldObject.status.phase in ['Succeeded', 'Failed'])",
		"(request.userInfo.username == 'system:kube-scheduler' && request.resource.group == '' && request.resource.resource == 'pods' && ((request.subResource == 'binding' && request.operation == 'CREATE') || (request.subResource == 'status' && request.operation == 'UPDATE')))",
		"(request.userInfo.username.startsWith('system:node:') && 'system:nodes' in request.userInfo.groups && request.resource.group == '' && ((request.resource.resource == 'pods' && request.subResource == 'status' && request.operation == 'UPDATE') || (request.resource.resource == 'serviceaccounts' && request.subResource == 'token' && request.operation == 'CREATE')))",
		// Events confer no credential, workload or permission authority. Existing
		// RBAC still determines who may write them. Leases have only the exact
		// installation-selected update exceptions above, never a blanket bypass.
		"(request.resource.group in ['', 'events.k8s.io'] && request.resource.resource == 'events' && request.subResource == '' && request.operation in ['CREATE', 'UPDATE', 'DELETE'])",
	)
	fail, equivalent, scope := admission.Fail, admission.Equivalent, admission.NamespacedScope
	// AdmissionRequest omits empty group/subResource fields in JSON. CEL must
	// not treat ordinary core/main-resource requests as missing-field errors.
	normalize := strings.NewReplacer("request.resource.group", "variables.resourceGroup", "request.subResource", "variables.subResource")
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, Variables: []admission.Variable{{Name: "resourceGroup", Expression: "has(request.resource.group) ? request.resource.group : ''"}, {Name: "subResource", Expression: "has(request.subResource) ? request.subResource : ''"}}, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete, admission.Connect}, Rule: admission.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*/*"}, Scope: &scope}}}}}, MatchConditions: []admission.MatchCondition{{Name: "private-hub-namespace", Expression: "request.namespace == " + ownerCELString(p.ControlNamespace.Name)}}, Validations: []admission.Validation{{Expression: normalize.Replace(strings.Join(allowed, " || ")), Message: ownerWorkloadDenial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

type OwnerWorkloadProtection struct {
	observer, probe *PermissionClient
	plan            cfg.OwnerWorkloadAdministration
	pin             GuardPin
	policy          admission.ValidatingAdmissionPolicySpec
	binding         admission.ValidatingAdmissionPolicyBindingSpec
	digest          artifact.Digest
	reuse           *ownerProtectionReuse
}

// OwnerProtectionReuse bounds how long one successful self-protection proof
// serves every caller in this process (2026-10-23 revision of ADR-208/173).
// The trust model trusts cluster administrators, so re-proving the hub's own
// installed guard per request added API load without an integrity guarantee.
const OwnerProtectionReuse = 30 * time.Second

// ownerProtectionRefresh is the remaining validity below which a stored proof
// is renewed instead of reused, so callers keep the usual five-second window.
const ownerProtectionRefresh = 5 * time.Second

// ownerProtectionReuse is the process-local last successful proof, shared by
// all copies of one guard. The one-slot channel serializes proofs, so
// concurrent callers share one in-flight proof while still honoring their own
// cancellation. Failures are never stored.
type ownerProtectionReuse struct {
	slot  chan struct{}
	until time.Time
}

func newOwnerProtectionReuse() *ownerProtectionReuse {
	return &ownerProtectionReuse{slot: make(chan struct{}, 1)}
}

// share lets a guard rebuilt from the same plan and pin (equal digest) reuse
// this guard's proof.
func (g *OwnerWorkloadProtection) share(out *OwnerWorkloadProtection) *OwnerWorkloadProtection {
	if out != nil && g != nil && out.digest == g.digest && out.observer.clusterID == g.observer.clusterID {
		out.reuse = g.reuse
	}
	return out
}

func NewOwnerWorkloadProtection(observer, probe *PermissionClient, plan cfg.OwnerWorkloadAdministration, pin GuardPin) (*OwnerWorkloadProtection, error) {
	if observer == nil || probe == nil || observer == probe || observer.clusterID != probe.clusterID || observer.control != plan.ControlNamespace || probe.control != plan.ControlNamespace || !identity.Text(pin.PolicyUID, 64) || !identity.Text(pin.BindingUID, 64) || !identity.Text(pin.BindingResourceVersion, 128) || pin.PolicyGeneration < 1 {
		return nil, cfg.ErrInvalid
	}
	if plan.CapacityProbe != nil {
		p := *plan.CapacityProbe
		plan.CapacityProbe = &p
	}
	if plan.APIContextStarts != nil {
		p := *plan.APIContextStarts
		plan.APIContextStarts = &p
	}
	if plan.InitialHistoryProbe != nil {
		p := *plan.InitialHistoryProbe
		plan.InitialHistoryProbe = &p
	}
	plan.Administrators = append([]cfg.KubernetesActor(nil), plan.Administrators...)
	plan.ConfigurationProbes = append([]cfg.OwnerConfigurationProbe(nil), plan.ConfigurationProbes...)
	plan.SchedulingLeases = append([]cfg.OwnerSchedulingLease(nil), plan.SchedulingLeases...)
	plan.CredentialSecrets = append([]cfg.OwnerCredentialSecret(nil), plan.CredentialSecrets...)
	p, b, err := OwnerWorkloadAdmission(plan)
	if err != nil {
		return nil, err
	}
	normalizePermissionPolicy(&p.Spec)
	raw, _ := json.Marshal(struct {
		Format, Cluster string
		Plan            cfg.OwnerWorkloadAdministration
		Pin             GuardPin
	}{"asservat-owner-workload-protection/v1", observer.clusterID, plan, pin})
	return &OwnerWorkloadProtection{observer, probe, plan, pin, p.Spec, b.Spec, artifact.Digest(sha256.Sum256(raw)), newOwnerProtectionReuse()}, nil
}

// proveObject returns only the actual Deployment used by the successful denied
// probe. ADR150's closed native boundary validates this same object against its
// independently installed template. It supplies no authority outside that proof.
func (g *OwnerWorkloadProtection) proveObject(ctx context.Context, start time.Time) (apps.Deployment, error) {
	object, _, err := g.proveObjectIdentity(ctx, start)
	return object, err
}

// Only the exact SelfSubjectReview response from this actual denied probe is
// returned. Purpose-specific same-operation callers still check its installed
// account/client pins and a live account object; it creates no new authority.
func (g *OwnerWorkloadProtection) proveObjectIdentity(ctx context.Context, start time.Time) (apps.Deployment, authentication.UserInfo, error) {
	var zero apps.Deployment
	raw, err := g.probe.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", authentication.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	if err != nil {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeIdentityRead, cfg.ErrUnavailable)
	}
	var who authentication.SelfSubjectReview
	if strictGuardJSON(raw, &who) != nil || !identity.Text(who.Status.UserInfo.Username, 256) || !identity.Strings(who.Status.UserInfo.Groups, 256, 256) {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeIdentityShape, cfg.ErrUnavailable)
	}
	for _, a := range g.plan.Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeAdministrator, cfg.ErrInvalid)
		}
	}
	// The probe is not allowed to be any trusted control-plane identity, even
	// one that lacks this particular Deployment permission today.
	if strings.HasPrefix(who.Status.UserInfo.Username, "system:node:") || who.Status.UserInfo.Username == "system:kube-controller-manager" || who.Status.UserInfo.Username == "system:kube-scheduler" {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeControlIdentity, cfg.ErrInvalid)
	}
	for _, rule := range ownerControllerRules() {
		for _, name := range rule.names {
			if who.Status.UserInfo.Username == ownerControllerUser(name) {
				return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeControllerIdentity, cfg.ErrInvalid)
			}
		}
	}
	review := authorization.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: authorization.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorization.ResourceAttributes{Namespace: g.plan.ControlNamespace.Name, Verb: "update", Group: "apps", Version: "v1", Resource: "deployments", Name: g.plan.Deployment}}}
	raw, err = g.probe.proofPost(ctx, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", review, nil)
	if err != nil {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeAccessRead, cfg.ErrUnavailable)
	}
	var access authorization.SelfSubjectAccessReview
	if strictGuardJSON(raw, &access) != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeAccessVerdict, cfg.ErrUnavailable)
	}
	path := "/apis/apps/v1/namespaces/" + g.plan.ControlNamespace.Name + "/deployments/" + g.plan.Deployment
	for attempt := 0; attempt < 3; attempt++ {
		if g.observer.current(ctx, start, 5*time.Second) != nil {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeOriginalInterval, cfg.ErrUnavailable)
		}
		raw, err = g.observer.raw(ctx, path, nil)
		if err != nil {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeObjectRead, cfg.ErrUnavailable)
		}
		var object apps.Deployment
		if json.Unmarshal(raw, &object) != nil || object.APIVersion != "apps/v1" || object.Kind != "Deployment" || !ownerMetadata(object.ObjectMeta, g.plan.ControlNamespace.Name, g.plan.Deployment, g.plan.DeploymentUID) {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeObjectShape, cfg.ErrChanged)
		}
		response := g.probe.api.Put().AbsPath(path).Param("dryRun", "All").Param("fieldValidation", "Strict").Body(raw).MaxRetries(0).Do(ctx)
		raw, _ = response.Raw()
		if permissionJSON(raw, permissionPageBytes, 131072) != nil {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeDenialBody, cfg.ErrUnavailable)
		}
		err = response.Error()
		var status apierrors.APIStatus
		if !errors.As(err, &status) {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeStatusDecode, cfg.ErrUnavailable)
		}
		d := status.Status()
		if apierrors.IsConflict(err) && d.Code == 409 && d.Reason == meta.StatusReasonConflict && d.Status == meta.StatusFailure && d.Details != nil && d.Details.Group == "apps" && d.Details.Kind == "deployments" && d.Details.Name == g.plan.Deployment && (d.Details.UID == "" || string(d.Details.UID) == g.plan.DeploymentUID) && len(d.Details.Causes) == 0 {
			// A controller can advance resourceVersion after the GET. Only
			// this exact conflict permits a fresh read within the original
			// observation interval. An unrelated denial is never retried.
			continue
		}
		if !apierrors.IsForbidden(err) && !apierrors.IsInvalid(err) {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeDenialStatus, cfg.ErrUnavailable)
		}
		if d.Details == nil || d.Details.Group != "apps" || d.Details.Kind != "deployments" || len(d.Details.Causes) > 8 {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeDenialDetails, cfg.ErrUnavailable)
		}
		expected := "ValidatingAdmissionPolicy '" + g.plan.Name + "' with binding '" + g.plan.Name + "' denied request: " + ownerWorkloadDenial
		for _, cause := range d.Details.Causes {
			if cause.Message == expected {
				return object, who.Status.UserInfo, nil
			}
		}
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeDenialCause, cfg.ErrUnavailable)
	}
	return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeConflictsExhausted, cfg.ErrUnavailable)
}

func (g *OwnerWorkloadProtection) prove(ctx context.Context, start time.Time) error {
	_, err := g.proveObject(ctx, start)
	return err
}

// Current proves current enforcement only. It does not attest Pod creation
// history, a process, a CSR, recovery or certificate activation. A successful
// proof is reused for OwnerProtectionReuse; the returned time is its end.
func (g *OwnerWorkloadProtection) Current(ctx context.Context) (artifact.Digest, time.Time, error) {
	digest, until, err := g.reused(ctx)
	if err != nil {
		return digest, until, err
	}
	return digest, callerBound(ctx, until), nil
}

// reused returns the stored proof's own end, not bound by the caller.
func (g *OwnerWorkloadProtection) reused(ctx context.Context) (artifact.Digest, time.Time, error) {
	var zero artifact.Digest
	if g == nil || ctx == nil || g.observer == nil || g.probe == nil || g.reuse == nil {
		return zero, time.Time{}, ownerProtectionError("entry", cfg.ErrInvalid, nil)
	}
	select {
	case g.reuse.slot <- struct{}{}:
	case <-ctx.Done():
		return zero, time.Time{}, ownerProtectionError("reuse-wait", cfg.ErrUnavailable, ctx.Err())
	}
	defer func() { <-g.reuse.slot }()
	if err := ctx.Err(); err != nil {
		return zero, time.Time{}, ownerProtectionError("reuse-wait", cfg.ErrUnavailable, err)
	}
	if !g.observer.now().Add(ownerProtectionRefresh).Before(g.reuse.until) {
		until, err := g.current(ctx)
		if err != nil {
			return zero, time.Time{}, err
		}
		g.reuse.until = until
	}
	return g.digest, g.reuse.until, nil
}

// callerBound never reports a reused proof past the caller's own deadline.
func callerBound(ctx context.Context, until time.Time) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return identity.Earlier(until, d)
	}
	return until
}

func (g *OwnerWorkloadProtection) current(ctx context.Context) (time.Time, error) {
	var zero time.Time
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := g.observer.now()
	ns, err := g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil {
		return zero, ownerProtectionError("namespace-first", cfg.ErrChanged, err)
	}
	if ns.Deleting {
		return zero, ownerProtectionError("namespace-first-deleting", cfg.ErrChanged, nil)
	}
	before, err := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil {
		return zero, ownerProtectionError("guard-first", err, err)
	}
	if err = g.prove(ctx, start); err != nil {
		return zero, ownerProtectionError("probe", err, err)
	}
	after, err := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil {
		return zero, ownerProtectionError("guard-last", cfg.ErrChanged, err)
	}
	if before != after {
		return zero, ownerProtectionError("guard-changed", cfg.ErrChanged, nil)
	}
	if err = g.observer.current(ctx, start, 5*time.Second); err != nil {
		return zero, ownerProtectionError("original-interval", cfg.ErrChanged, err)
	}
	// Namespace replacement/deletion during the proof cannot keep it current.
	ns, err = g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil {
		return zero, ownerProtectionError("namespace-last", cfg.ErrChanged, err)
	}
	if ns.Deleting {
		return zero, ownerProtectionError("namespace-last-deleting", cfg.ErrChanged, nil)
	}
	if err = g.observer.current(ctx, start, 5*time.Second); err != nil {
		return zero, ownerProtectionError("final-interval", cfg.ErrChanged, err)
	}
	return start.Add(OwnerProtectionReuse), nil
}

// capacityTokenUnbound accepts the absent or empty boundObjectRef the API
// server presents for an unbound TokenRequest (observed natively: has() is
// true without a binding), and rejects any reference naming an object.
const capacityTokenUnbound = "(!has(object.spec.boundObjectRef) || ((!has(object.spec.boundObjectRef.kind) || object.spec.boundObjectRef.kind == '') && (!has(object.spec.boundObjectRef.name) || object.spec.boundObjectRef.name == '') && (!has(object.spec.boundObjectRef.uid) || object.spec.boundObjectRef.uid == '')))"

// CapacityTokenUnboundCondition exposes the exact condition for native
// diagnostics only.
const CapacityTokenUnboundCondition = capacityTokenUnbound

// WithClients rebuilds this exact protection, from a fresh decoded copy of
// its plan and the same pin, over other client instances of the same
// identities. ADR-197: a purpose with its own API budget proves the same
// guard without sharing another purpose's limiter.
func (g *OwnerWorkloadProtection) WithClients(observer, probe *PermissionClient) (*OwnerWorkloadProtection, error) {
	if g == nil {
		return nil, cfg.ErrInvalid
	}
	var plan cfg.OwnerWorkloadAdministration
	raw, err := json.Marshal(g.plan)
	if err != nil || json.Unmarshal(raw, &plan) != nil {
		return nil, cfg.ErrInvalid
	}
	out, err := NewOwnerWorkloadProtection(observer, probe, plan, g.pin)
	if err != nil || out.digest != g.digest {
		return nil, cfg.ErrInvalid
	}
	return g.share(out), nil
}
