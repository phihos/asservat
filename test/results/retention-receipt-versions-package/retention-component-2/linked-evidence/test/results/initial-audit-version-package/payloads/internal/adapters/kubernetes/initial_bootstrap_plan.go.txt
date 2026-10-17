package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

const initialBootstrapDenial = "Asservat trusted bootstrap identities must remain occupied; observation probes cannot mutate them."
const initialBootstrapAnnotation = "asservat.io/bootstrap-desired"
const initialBootstrapPassiveAnnotation = "asservat.io/bootstrap-passive-history"
const initialBootstrapRetiredAnnotation = "asservat.io/bootstrap-manager-retired"

type initialBootstrapNames struct {
	seed, guard, account, marker, continuityMarker, anchor               string
	private, sqlMaterial, providerMaterial, projection, root, continuity string
	passiveHistory                                                       string
	copyMarker, copyGuard                                                string
}

func bootstrapNames(d contracts.InitialBootstrap) initialBootstrapNames {
	return initialBootstrapNames{
		seed: d.Name + "-bootstrap-state", guard: d.BootstrapNamespace + "-" + d.Name + "-bootstrap",
		account: d.Name + "-probe", marker: d.Name + "-bootstrap-probe", continuityMarker: d.Name + "-continuity-probe", anchor: d.Name + "-probe-lifetime",
		private: d.Name + "-private-progress", sqlMaterial: d.Name + "-sql-material", providerMaterial: d.Name + "-provider-material",
		projection: d.Name + "-preparer", root: d.Name + "-preparation", continuity: d.BootstrapNamespace + "-" + d.Name + "-continuity",
		passiveHistory: d.Name + "-passive-history",
		copyMarker:     d.Name + "-copy-closure-probe", copyGuard: d.BootstrapNamespace + "-" + d.Name + "-copy-tombstone",
	}
}

func validateBootstrap(d contracts.InitialBootstrap) error {
	if (d.Format != contracts.InitialBootstrapFormat && !contracts.InitialBootstrapHasPassiveHistory(d.Format)) || len(d.Name) > 30 || len(validation.IsDNS1123Label(d.Name)) != 0 || len(validation.IsDNS1123Label(d.BootstrapNamespace)) != 0 || len(validation.IsDNS1123Label(d.TargetNamespace)) != 0 || d.BootstrapNamespace == d.TargetNamespace || !identity.Text(d.ProbeAudience, 256) {
		return cfg.ErrInvalid
	}
	for _, name := range []string{d.BootstrapNamespace, d.TargetNamespace} {
		if name == "default" || strings.HasPrefix(name, "kube-") {
			return cfg.ErrInvalid
		}
	}
	n := bootstrapNames(d)
	a := cfg.InitialNamespaceAdministration{Name: d.TargetNamespace + "-" + d.Name + "-staging", Namespace: d.TargetNamespace, ProbeSource: d.Name + "-journal", Inputs: d.Name + "-inputs"}
	for _, actor := range d.Administrators {
		if actor.Kind == "User" && actor.Name == "system:serviceaccount:"+d.BootstrapNamespace+":"+n.account {
			return cfg.ErrInvalid
		}
		a.Administrators = append(a.Administrators, cfg.KubernetesActor{Kind: actor.Kind, Name: actor.Name})
	}
	if _, _, e := InitialNamespaceAdmission(a); e != nil {
		return cfg.ErrInvalid
	}
	if d.RegistryAuthentication != "" && !contracts.InitialBootstrapHasCopyClosure(d.Format) {
		return cfg.ErrInvalid
	}
	if _, e := BuildInitialInstallerWorkload(bootstrapWorkload(d)); e != nil {
		return cfg.ErrInvalid
	}
	if providerconfig.Validate(d.Kubernetes, d.Postgres, d.AuditStore, d.KeyService, time.Now()) != nil {
		return cfg.ErrInvalid
	}
	if !providerconfig.InitialProviderNames(d.Providers.IssuerPolicy, d.Providers.WrapRole, d.Providers.WrapPolicy, d.Providers.UnwrapRole, d.Providers.UnwrapPolicy) {
		return cfg.ErrInvalid
	}
	// Fleet's actual complete canonical schema is checked after generated IDs
	// are bound, before seed or provider effects. Here reject oversized input.
	b, e := json.Marshal(d)
	if e != nil || len(b) > contracts.InitialBootstrapMaxBytes {
		return cfg.ErrInvalid
	}
	validator, e := newPermissionValidator()
	if e != nil {
		return cfg.ErrUnavailable
	}
	// Only structural validation uses these proposed UUIDs. They are never
	// retained or returned as installation identity or authority.
	installation, e := prepUUID()
	if e != nil {
		return e
	}
	epoch, e := prepUUID()
	if e != nil {
		return e
	}
	compiled, e := json.Marshal(bootstrapFleet(d, installation, epoch))
	var fleet contracts.FleetSettings
	if e != nil {
		return cfg.ErrInvalid
	}
	if _, e = decodePermissionSpec(compiled, validator.fleetSchema, &fleet); e != nil {
		return cfg.ErrInvalid
	}
	return nil
}

func bootstrapFleet(d contracts.InitialBootstrap, installation, epoch string) contracts.FleetSettings {
	f := d.Fleet
	return contracts.FleetSettings{SchemaVersion: "fleet-settings/v1", Revision: 1, InstallationID: installation, IssuerEpoch: epoch, Issuer: f.Issuer, Clients: f.Clients, Subjects: f.Subjects, Groups: f.Groups, DeliveryProfiles: f.DeliveryProfiles, MaxActiveBootstraps: f.MaxActiveBootstraps, MaxBootstrapHistory: f.MaxBootstrapHistory, MaxClusters: f.MaxClusters}
}

func bootstrapWorkload(d contracts.InitialBootstrap) InitialInstallerWorkloadPlan {
	return InitialInstallerWorkloadPlan{RegistryAuthentication: d.RegistryAuthentication, WriterAudience: d.ProbeAudience, Namespace: d.TargetNamespace, Name: d.Name, WriterAccount: d.Name + "-writer", ProbeAccount: d.Name + "-probe", Configuration: d.Name + "-inputs", Credentials: d.Name + "-providers", Image: d.Image, Witness: d.Name + "-witness", FleetSource: d.Name + "-fleet", WitnessGuard: d.TargetNamespace + "-" + d.Name + "-witness", FleetGuard: d.TargetNamespace + "-" + d.Name + "-fleet", WorkloadGuard: d.TargetNamespace + "-" + d.Name + "-workload"}
}

func bootstrapDigest(d contracts.InitialBootstrap) string {
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func bootstrapMeta(d contracts.InitialBootstrap, name string) meta.ObjectMeta {
	return meta.ObjectMeta{Name: name, Namespace: d.BootstrapNamespace, Annotations: map[string]string{initialBootstrapAnnotation: bootstrapDigest(d)}}
}

// InitialBootstrapAdmission is a static-name trusted bootstrap prelude. The
// public probe prerequisites must already exist before independently proving
// its denial. It is never described as authorizing its own installation.
func InitialBootstrapAdmission(d contracts.InitialBootstrap) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if e := validateBootstrap(d); e != nil {
		return nil, nil, e
	}
	n := bootstrapNames(d)
	actors := []string{}
	for _, a := range d.Administrators {
		if a.Kind == "User" {
			actors = append(actors, "request.userInfo.username == "+ownerCELString(a.Name))
		} else {
			actors = append(actors, ownerCELString(a.Name)+" in request.userInfo.groups")
		}
	}
	// Match conditions cannot reference policy variables; use request fields
	// directly for the keys reused by both matching and validation.
	key := func(group, resource, name string) string {
		return "((has(request.resource.group) ? request.resource.group : '') == " + ownerCELString(group) + " && request.resource.resource == " + ownerCELString(resource) + " && (has(request.namespace) ? request.namespace : '') == " + ownerCELString(d.BootstrapNamespace) + " && ((has(request.name) ? request.name : '') == " + ownerCELString(name) + " || request.operation == 'DELETE' && oldObject != null && oldObject.metadata.name == " + ownerCELString(name) + "))"
	}
	seed := key("", "secrets", n.seed)
	private := key("", "secrets", n.private)
	continuity := key("", "configmaps", n.continuityMarker)
	keys := []string{seed, private, continuity, key("", "configmaps", n.marker), key("", "configmaps", n.projection), key("", "serviceaccounts", n.account), key("", "secrets", n.anchor), key("", "secrets", n.sqlMaterial), key("", "secrets", n.providerMaterial), key(rbac.GroupName, "roles", n.account), key(rbac.GroupName, "rolebindings", n.account)}
	// Namespace requests report either the object's name or empty namespace;
	// exact Namespace deletion is matched without relying on that difference.
	keys = append(keys, "((has(request.resource.group) ? request.resource.group : '') == '' && request.resource.resource == 'namespaces' && request.operation == 'DELETE' && ((has(request.name) ? request.name : '') == "+ownerCELString(d.BootstrapNamespace)+" || oldObject != null && oldObject.metadata.name == "+ownerCELString(d.BootstrapNamespace)+"))")
	admin := "(" + strings.Join(actors, " || ") + ")"
	allowed := admin + " && variables.sub == '' && (request.operation == 'CREATE' || request.operation == 'UPDATE' && (" + seed + " || " + private + "))"
	// The later continuity marker must reach its own exact native guard during
	// independent dry-run proof. This exception cannot persist a mutation.
	allowed = "(" + allowed + ") || (" + continuity + " && variables.sub == '' && request.operation == 'UPDATE' && has(request.dryRun) && request.dryRun == true && request.userInfo.username == " + ownerCELString("system:serviceaccount:"+d.BootstrapNamespace+":"+n.account) + ")"
	// Current observation-only login may be reacquired on passive reopen. It
	// has no installation-effect privileges and cannot extend any SQL/provider
	// interval. The API independently checks this occupied immutable anchor UID.
	probeToken := key("", "serviceaccounts", n.account) + " && variables.sub == 'token' && request.operation == 'CREATE' && has(object.spec) && has(object.spec.audiences) && object.spec.audiences == [" + ownerCELString(d.ProbeAudience) + "] && has(object.spec.expirationSeconds) && object.spec.expirationSeconds == 600 && has(object.spec.boundObjectRef) && object.spec.boundObjectRef.apiVersion == 'v1' && object.spec.boundObjectRef.kind == 'Secret' && object.spec.boundObjectRef.name == " + ownerCELString(n.anchor) + " && has(object.spec.boundObjectRef.uid) && object.spec.boundObjectRef.uid.matches('^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')"
	allowed = "(" + allowed + ") || (" + admin + " && " + probeToken + ")"
	if contracts.InitialBootstrapHasPassiveHistory(d.Format) {
		keys = append(keys, key("", "secrets", n.passiveHistory))
		// Both receipt annotations are absent at seed creation and immutable
		// once set. An unsupported/invalid value fails the bounded reader;
		// neither the annotation nor its presence is effect authority.
		for _, annotation := range []string{initialBootstrapPassiveAnnotation, initialBootstrapRetiredAnnotation} {
			k := ownerCELString(annotation)
			oldHas := "(oldObject != null && has(oldObject.metadata.annotations) && " + k + " in oldObject.metadata.annotations)"
			newHas := "(has(object.metadata.annotations) && " + k + " in object.metadata.annotations)"
			unchanged := "(!" + newHas + " || size(object.metadata.annotations[" + k + "]) <= 2048) && (request.operation != 'CREATE' || !" + newHas + ") && (!" + oldHas + " || " + newHas + " && object.metadata.annotations[" + k + "] == oldObject.metadata.annotations[" + k + "])"
			allowed = "(" + allowed + ") && (!(" + seed + ") || (" + unchanged + "))"
		}
	}
	if contracts.InitialBootstrapHasCopyClosure(d.Format) {
		keys, allowed = bootstrapCopyClosureAdmission(d, keys, allowed, admin, key)
	}
	fail, equivalent, scope := admission.Fail, admission.Equivalent, admission.AllScopes
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: admission.SchemeGroupVersion.String(), Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: n.guard, Annotations: map[string]string{initialBootstrapAnnotation: bootstrapDigest(d)}}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, Variables: []admission.Variable{{Name: "sub", Expression: "has(request.subResource) ? request.subResource : ''"}}, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete, admission.Connect}, Rule: admission.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*/*"}, Scope: &scope}}}}}, MatchConditions: []admission.MatchCondition{{Name: "initial-bootstrap-continuity", Expression: strings.Join(keys, " || ")}}, Validations: []admission.Validation{{Expression: allowed, Message: initialBootstrapDenial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: admission.SchemeGroupVersion.String(), Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: n.guard, Annotations: map[string]string{initialBootstrapAnnotation: bootstrapDigest(d)}}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: n.guard, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

func bootstrapProbeAccount(d contracts.InitialBootstrap) *core.ServiceAccount {
	return &core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: bootstrapMeta(d, bootstrapNames(d).account), AutomountServiceAccountToken: ptr.To(false)}
}
func bootstrapProbeRole(d contracts.InitialBootstrap) *rbac.Role {
	n := bootstrapNames(d)
	markers := []string{n.marker, n.continuityMarker}
	if contracts.InitialBootstrapHasCopyClosure(d.Format) {
		markers = append(markers, n.copyMarker)
	}
	return &rbac.Role{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: bootstrapMeta(d, n.account), Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: markers, Verbs: []string{"get", "update"}}}}
}
func bootstrapProbeBinding(d contracts.InitialBootstrap) *rbac.RoleBinding {
	n := bootstrapNames(d)
	return &rbac.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: bootstrapMeta(d, n.account), RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: n.account}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: d.BootstrapNamespace, Name: n.account}}}
}
