package kubernetes

import (
	"strings"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const bootstrapCopyClaimAnnotation = "asservat.io/bootstrap-copy-claim"
const bootstrapCopyPolicyStartedAnnotation = "asservat.io/bootstrap-copy-policy-started"
const bootstrapCopyBindingStartedAnnotation = "asservat.io/bootstrap-copy-binding-started"
const bootstrapCopySQLMarkedAnnotation = "asservat.io/bootstrap-copy-sql-marked"
const bootstrapCopyProviderMarkedAnnotation = "asservat.io/bootstrap-copy-provider-marked"
const bootstrapCopyPolicyAnnotation = "asservat.io/bootstrap-copy-policy"
const bootstrapCopyBindingAnnotation = "asservat.io/bootstrap-copy-binding"
const bootstrapCopySQLAnnotation = "asservat.io/bootstrap-copy-sql-removed"
const bootstrapCopyProviderAnnotation = "asservat.io/bootstrap-copy-provider-removed"
const bootstrapCopyCompleteAnnotation = "asservat.io/bootstrap-copy-complete"
const bootstrapCopyObjectAnnotation = "asservat.io/bootstrap-copy-close"
const bootstrapCopyDenial = "Asservat retired setup-copy names remain permanently occupied."

func bootstrapCopyAnnotations() []string {
	return []string{bootstrapCopyClaimAnnotation, bootstrapCopyPolicyStartedAnnotation, bootstrapCopyPolicyAnnotation, bootstrapCopyBindingStartedAnnotation, bootstrapCopyBindingAnnotation, bootstrapCopySQLMarkedAnnotation, bootstrapCopySQLAnnotation, bootstrapCopyProviderMarkedAnnotation, bootstrapCopyProviderAnnotation, bootstrapCopyCompleteAnnotation}
}

func bootstrapCopyMarked(which string) string {
	k := ownerCELString(bootstrapCopyObjectAnnotation)
	return which + " != null && has(" + which + ".metadata.annotations) && " + k + " in " + which + ".metadata.annotations && " + which + ".metadata.annotations[" + k + "].matches('^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')"
}

// Only a once-set annotation may change. The resourceVersion remains the
// original CAS input; all payload and ownership fields are preserved. The
// original v3 guard and retained tombstone both apply this same narrow rule.
func bootstrapCopyMetadataOnly() string {
	k := ownerCELString(bootstrapCopyObjectAnnotation)
	return "object != null && oldObject != null && " + bootstrapCopyMarked("object") +
		" && object.metadata.name == oldObject.metadata.name && object.metadata.namespace == oldObject.metadata.namespace && object.metadata.uid == oldObject.metadata.uid && object.metadata.resourceVersion == oldObject.metadata.resourceVersion" +
		" && has(object.immutable) && object.immutable == true && has(oldObject.immutable) && oldObject.immutable == true && object.type == oldObject.type && object.data == oldObject.data && !has(object.stringData)" +
		" && (!has(object.metadata.labels) || size(object.metadata.labels) == 0) && (!has(oldObject.metadata.labels) || size(oldObject.metadata.labels) == 0)" +
		" && (!has(object.metadata.ownerReferences) || size(object.metadata.ownerReferences) == 0) && (!has(oldObject.metadata.ownerReferences) || size(oldObject.metadata.ownerReferences) == 0)" +
		" && (!has(object.metadata.finalizers) || size(object.metadata.finalizers) == 0) && (!has(oldObject.metadata.finalizers) || size(oldObject.metadata.finalizers) == 0)" +
		" && has(oldObject.metadata.annotations) && object.metadata.annotations.all(k, k == " + k + " || k in oldObject.metadata.annotations && object.metadata.annotations[k] == oldObject.metadata.annotations[k])" +
		" && oldObject.metadata.annotations.all(k, k in object.metadata.annotations && object.metadata.annotations[k] == oldObject.metadata.annotations[k])"
}

// The fresh-v3 original guard is never replaced. These clauses are compiled
// before any private input exists and do not alter legacy v1/v2 expressions.
func bootstrapCopyClosureAdmission(d contracts.InitialBootstrap, keys []string, allowed, admin string, key func(string, string, string) string) ([]string, string) {
	n := bootstrapNames(d)
	marker := key("", "configmaps", n.copyMarker)
	copies := "(" + key("", "secrets", n.sqlMaterial) + " || " + key("", "secrets", n.providerMaterial) + ")"
	keys = append(keys, marker)
	// Kubernetes does not evaluate VAP on admission-policy/binding objects.
	// Their retention is owned by the trusted installation administrator/RBAC;
	// each consumer independently checks original exact identities and content.
	allowed = "(" + allowed + ") || (" + admin + " && variables.sub == '' && " + copies + " && (request.operation == 'UPDATE' && (" + bootstrapCopyMetadataOnly() + ") || request.operation == 'DELETE' && (" + bootstrapCopyMarked("oldObject") + ")))"
	allowed = "(" + allowed + ") || (" + marker + " && variables.sub == '' && request.operation == 'UPDATE' && has(request.dryRun) && request.dryRun == true && request.userInfo.username == " + ownerCELString("system:serviceaccount:"+d.BootstrapNamespace+":"+n.account) + ")"
	// Existing allowed includes only administrator CREATE for protected public names.
	// Protect one-time claim/receipt annotations for all seed update paths.
	seed := key("", "secrets", n.seed)
	for _, annotation := range bootstrapCopyAnnotations() {
		k := ownerCELString(annotation)
		oldHas := "(oldObject != null && has(oldObject.metadata.annotations) && " + k + " in oldObject.metadata.annotations)"
		newHas := "(has(object.metadata.annotations) && " + k + " in object.metadata.annotations)"
		limit := "512"
		if annotation == bootstrapCopyClaimAnnotation {
			limit = "4096"
		}
		condition := "(!" + newHas + " || size(object.metadata.annotations[" + k + "]) <= " + limit + ") && (request.operation != 'CREATE' || !" + newHas + ") && (!" + oldHas + " || " + newHas + " && object.metadata.annotations[" + k + "] == oldObject.metadata.annotations[" + k + "])"
		allowed = "(" + allowed + ") && (!(" + seed + ") || (" + condition + "))"
	}
	complete := ownerCELString(bootstrapCopyCompleteAnnotation)
	required := []string{}
	for _, annotation := range []string{bootstrapCopyClaimAnnotation, bootstrapCopyPolicyStartedAnnotation, bootstrapCopyPolicyAnnotation, bootstrapCopyBindingStartedAnnotation, bootstrapCopyBindingAnnotation, bootstrapCopySQLMarkedAnnotation, bootstrapCopySQLAnnotation, bootstrapCopyProviderMarkedAnnotation, bootstrapCopyProviderAnnotation, initialBootstrapPassiveAnnotation, initialBootstrapRetiredAnnotation} {
		required = append(required, ownerCELString(annotation)+" in object.metadata.annotations")
	}
	// Secret data values are base64 JSON strings in the admission object. Native
	// qualification must validate this exact form before the capability ships.
	final := "!has(object.metadata.annotations) || !(" + complete + " in object.metadata.annotations) || (" + strings.Join(required, " && ") + " && has(object.immutable) && object.immutable == true && has(object.data) && object.data == {'retired':'dHJ1ZQ=='} && !has(object.stringData))"
	allowed = "(" + allowed + ") && (!(" + seed + ") || (" + final + "))"
	return keys, allowed
}

// InitialBootstrapCopyAdmission fences the two original names while its exact
// protection remains installed under trusted administrator/RBAC ownership. It
// is additive to the original v3 guard and grants no SQL or recovery authority.
func InitialBootstrapCopyAdmission(d contracts.InitialBootstrap, claim contracts.InitialBootstrapCopyClaim) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if validateBootstrap(d) != nil || !bootstrapCopyClaimValid(d, claim) {
		return nil, nil, cfg.ErrInvalid
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
	admin := "(" + strings.Join(actors, " || ") + ")"
	group := "(has(request.resource.group) ? request.resource.group : '')"
	namespace := "(has(request.namespace) ? request.namespace : '')"
	name := "(has(request.name) ? request.name : '')"
	copies := "(" + group + " == '' && request.resource.resource == 'secrets' && " + namespace + " == " + ownerCELString(d.BootstrapNamespace) + " && (" + name + " in [" + ownerCELString(n.sqlMaterial) + "," + ownerCELString(n.providerMaterial) + "] || request.operation == 'DELETE' && oldObject != null && oldObject.metadata.name in [" + ownerCELString(n.sqlMaterial) + "," + ownerCELString(n.providerMaterial) + "]))"
	marker := "(" + group + " == '' && request.resource.resource == 'configmaps' && " + namespace + " == " + ownerCELString(d.BootstrapNamespace) + " && " + name + " == " + ownerCELString(n.copyMarker) + ")"
	exact := "oldObject != null && ((oldObject.metadata.name == " + ownerCELString(claim.SQL.Name) + " && oldObject.metadata.uid == " + ownerCELString(claim.SQL.UID) + ") || (oldObject.metadata.name == " + ownerCELString(claim.Provider.Name) + " && oldObject.metadata.uid == " + ownerCELString(claim.Provider.UID) + "))"
	operation := ownerCELString(claim.OperationID)
	annotation := ownerCELString(bootstrapCopyObjectAnnotation)
	allowed := copies + " && " + admin + " && (!has(request.subResource) || request.subResource == '') && (" + exact + ") && ((request.operation == 'UPDATE' && (" + bootstrapCopyMetadataOnly() + ") && object.metadata.annotations[" + annotation + "] == " + operation + ") || (request.operation == 'DELETE' && (" + bootstrapCopyMarked("oldObject") + ") && oldObject.metadata.annotations[" + annotation + "] == " + operation + "))"
	fail, equivalent, scope := admission.Fail, admission.Equivalent, admission.AllScopes
	m := meta.ObjectMeta{Name: n.copyGuard, Annotations: map[string]string{initialBootstrapAnnotation: bootstrapDigest(d), bootstrapCopyClaimAnnotation: claim.OperationID}}
	p := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: admission.SchemeGroupVersion.String(), Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: m, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete, admission.Connect}, Rule: admission.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*/*"}, Scope: &scope}}}}}, MatchConditions: []admission.MatchCondition{{Name: "initial-bootstrap-copy-tombstone", Expression: copies + " || " + marker}}, Validations: []admission.Validation{{Expression: allowed, Message: bootstrapCopyDenial}}}}
	b := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: admission.SchemeGroupVersion.String(), Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: m, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: n.copyGuard, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return p, b, nil
}
