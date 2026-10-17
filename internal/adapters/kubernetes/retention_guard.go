package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	port "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RetentionGuard struct {
	observer, probe *PermissionClient
	plan            value.RetentionAdministration
	pin             GuardPin
	policy          admission.ValidatingAdmissionPolicySpec
	binding         admission.ValidatingAdmissionPolicyBindingSpec
	digest          artifact.Digest
}

var _ port.PolicyProtectionReader = (*RetentionGuard)(nil)

func NewRetentionGuard(observer, probe *PermissionClient, plan value.RetentionAdministration, pin GuardPin) (*RetentionGuard, error) {
	if observer == nil || probe == nil || observer == probe || observer.clusterID != probe.clusterID || observer.control != plan.ControlNamespace || probe.control != plan.ControlNamespace || !identity.Text(pin.PolicyUID, 64) || !identity.Text(pin.BindingUID, 64) || !identity.Text(pin.BindingResourceVersion, 128) || pin.PolicyGeneration < 1 {
		return nil, value.ErrInvalid
	}
	own, digest, err := retentionGuardDigest(observer.clusterID, plan, pin)
	if err != nil {
		return nil, err
	}
	p, b, err := RetentionAdmission(own)
	if err != nil {
		return nil, err
	}
	normalizePermissionPolicy(&p.Spec)
	return &RetentionGuard{observer: observer, probe: probe, plan: own, pin: pin, policy: p.Spec, binding: b.Spec, digest: digest}, nil
}

// RetentionGuardDigest is the protection digest of the hub retention source
// for this cluster, plan and pin: what a retention topology names. The join
// command computes it from the exact reopened guard (ADR-196 decision 7).
func RetentionGuardDigest(cluster string, plan value.RetentionAdministration, pin GuardPin) (artifact.Digest, error) {
	_, d, err := retentionGuardDigest(cluster, plan, pin)
	return d, err
}

func retentionGuardDigest(cluster string, plan value.RetentionAdministration, pin GuardPin) (value.RetentionAdministration, artifact.Digest, error) {
	var own value.RetentionAdministration
	encoded, err := json.Marshal(plan)
	if err != nil || json.Unmarshal(encoded, &own) != nil {
		return own, artifact.Digest{}, value.ErrInvalid
	}
	bound, err := json.Marshal(struct {
		Cluster string
		Plan    value.RetentionAdministration
		Pin     GuardPin
	}{cluster, own, pin})
	if err != nil {
		return own, artifact.Digest{}, value.ErrInvalid
	}
	return own, sha256.Sum256(bound), nil
}

// Digest is the guard's protection digest: the cluster, the plan and the pin.
// A retention source reference carries it (ADR-195).
func (g *RetentionGuard) Digest() artifact.Digest { return g.digest }

func (g *RetentionGuard) proveDenial(ctx context.Context) error {
	raw, err := g.probe.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", authentication.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	if err != nil {
		return retentionGuardFailure("review-request", value.ErrUnavailable)
	}
	var who authentication.SelfSubjectReview
	if strictGuardJSON(raw, &who) != nil || !identity.Text(who.Status.UserInfo.Username, 256) || !identity.Strings(who.Status.UserInfo.Groups, 256, 256) {
		return retentionGuardFailure("review-decode", value.ErrUnavailable)
	}
	for _, a := range g.plan.Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return retentionGuardFailure("probe-administrator", value.ErrInvalid)
		}
	}
	for _, d := range g.plan.Delegations {
		for _, a := range d.Writers {
			if actorMatches(a, who.Status.UserInfo) {
				return retentionGuardFailure("probe-delegate", value.ErrInvalid)
			}
		}
	}
	for _, user := range g.plan.StatusUsers {
		if user == who.Status.UserInfo.Username {
			return retentionGuardFailure("probe-status-user", value.ErrInvalid)
		}
	}
	const resource = "evidenceretentionpolicies"
	review := authorization.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: authorization.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorization.ResourceAttributes{Namespace: g.plan.ControlNamespace.Name, Verb: "create", Group: "asservat.io", Version: "v1alpha1", Resource: resource}}}
	raw, err = g.probe.proofPost(ctx, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", review, nil)
	if err != nil {
		return retentionGuardFailure("access-request", value.ErrUnavailable)
	}
	var access authorization.SelfSubjectAccessReview
	if strictGuardJSON(raw, &access) != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return retentionGuardFailure("access-denied", value.ErrUnavailable)
	}
	// Always a schema-valid synthetic policy and dryRun=All. No policy, capture
	// or evidence is persisted even if the expected admission guard is missing.
	durations := map[string]int64{"evidenceSeconds": 600, "caseMetadataSeconds": 600, "auditMetadataSeconds": 600}
	probe := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceRetentionPolicy", "metadata": map[string]any{"generateName": "asservat-retention-probe-", "namespace": g.plan.ControlNamespace.Name}, "spec": map[string]any{"scope": map[string]any{}, "purposeRef": "synthetic-admission-probe", "defaults": durations, "maxima": durations, "rules": []any{}, "deletionBudgetSeconds": 30, "legalExceptions": "disabled"}}
	_, err = g.probe.proofPost(ctx, "/apis/asservat.io/v1alpha1/namespaces/"+g.plan.ControlNamespace.Name+"/"+resource, probe, map[string]string{"dryRun": "All", "fieldValidation": "Strict"})
	var status apierrors.APIStatus
	if (!apierrors.IsForbidden(err) && !apierrors.IsInvalid(err)) || !errors.As(err, &status) {
		return retentionGuardFailure("dry-run-not-denied", value.ErrUnavailable)
	}
	denial := status.Status()
	if denial.Details == nil || denial.Details.Group != "asservat.io" || denial.Details.Kind != resource || len(denial.Details.Causes) > 8 {
		return retentionGuardFailure("denial-shape", value.ErrUnavailable)
	}
	expected := "ValidatingAdmissionPolicy '" + g.plan.Name + "' with binding '" + g.plan.Name + "' denied request: Asservat retention administrator or matching retention delegation is required."
	for _, cause := range denial.Details.Causes {
		if cause.Message == expected {
			return nil
		}
	}
	return retentionGuardFailure("denial-message", value.ErrUnavailable)
}
func (g *RetentionGuard) RetentionProtection(ctx context.Context) (port.SourceProtection, error) {
	var out port.SourceProtection
	if g == nil || g.observer == nil || g.probe == nil {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := g.observer.now()
	ns, err := g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil || ns.Deleting {
		return out, retentionGuardFailure("namespace", value.ErrChanged)
	}
	before, err := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil {
		return out, retentionGuardFailure("guard", err)
	}
	if err = g.proveDenial(ctx); err != nil {
		return out, err
	}
	after, err := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil || after != before {
		return out, value.ErrChanged
	}
	ns, err = g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil || ns.Deleting {
		return out, value.ErrChanged
	}
	if err = g.observer.current(ctx, start, 5*time.Second); err != nil {
		return out, err
	}
	return port.SourceProtection{SourceClusterID: g.observer.clusterID, ControlNamespaceUID: g.plan.ControlNamespace.UID, Digest: g.digest, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, nil
}

// retentionGuardFailure names the failed retention guard check with fixed
// text only; errors.Is keeps the original class.
type retentionGuardError struct {
	check string
	cause error
}

func retentionGuardFailure(check string, cause error) error {
	return &retentionGuardError{check, cause}
}
func (e *retentionGuardError) Error() string     { return "retention guard " + e.check }
func (e *retentionGuardError) Unwrap() error     { return e.cause }
func (e *retentionGuardError) FixedStep() string { return "guard." + e.check }
