package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/targets"
	authorizationv1 "k8s.io/api/authorization/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MaxIdentityMappings bounds one cluster's identity mapping records.
const MaxIdentityMappings = 16

// IdentityMappingsValid checks a cluster's identity mapping records (ADR-245):
// unique DNS-label names, an https issuer, bounded printable prefixes.
func IdentityMappingsValid(m []contracts.RegionalIdentityMapping) bool {
	if len(m) > MaxIdentityMappings {
		return false
	}
	names := map[string]bool{}
	for _, x := range m {
		u, err := url.Parse(x.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || !identity.Text(x.Issuer, 2048) || !dnsLabel(x.Name) || names[x.Name] || len(x.UsernamePrefix) > 256 || !printable(x.UsernamePrefix) {
			return false
		}
		if x.GroupsPrefix != nil && (len(*x.GroupsPrefix) > 256 || !printable(*x.GroupsPrefix)) {
			return false
		}
		names[x.Name] = true
	}
	return true
}

func dnsLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func printable(s string) bool {
	for _, c := range s {
		if c < 0x21 || c == 0x7f {
			return false
		}
	}
	return true
}

// WithIdentityMappings returns c reviewing decision-time sources through the
// cluster's identity mappings; without them every review answers
// MappingUnsupported.
func (c *PodTargets) WithIdentityMappings(m []contracts.RegionalIdentityMapping) (*PodTargets, error) {
	if !IdentityMappingsValid(m) {
		return nil, value.ErrInvalid
	}
	out := *c
	out.mappings = slices.Clone(m)
	return &out, nil
}

// ReviewAccess answers one decision-time review (REQ-PER-004, ADR-245): it
// maps the hub's authenticated principal through this cluster's own identity
// mapping, checks the namespace (exact UID, the source's selector and
// exclusions) and the reviewed object's identity, and submits one
// authorization.k8s.io/v1 SubjectAccessReview whose subject is the mapped
// user and groups, never this connector. Only allowed=true, denied!=true and
// no evaluation error allow. A deleted Pod or workload is reviewed by its
// recorded name (the RBAC authorizer decides by name); a same-name
// replacement with another UID is TargetChanged. Nothing of the review leaves
// the cluster except the closed outcome.
func (c *PodTargets) ReviewAccess(ctx context.Context, r value.AccessReviewRequest) (value.AccessReviewAnswer, error) {
	if c == nil || !r.Valid() || r.Target.ClusterID != c.client.clusterID {
		return value.AccessReviewAnswer{}, value.ErrInvalid
	}
	answer := func(outcome string) (value.AccessReviewAnswer, error) {
		return value.AccessReviewAnswer{SourceUID: r.Source.UID, Outcome: outcome}, nil
	}
	var mapping *contracts.RegionalIdentityMapping
	for i := range c.mappings {
		if c.mappings[i].Name == r.Source.IdentityMapping {
			mapping = &c.mappings[i]
		}
	}
	if mapping == nil || mapping.Issuer != r.Principal.Issuer {
		return answer(value.AccessMappingUnsupported)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	t := r.Target
	raw, err := c.client.raw(ctx, "/api/v1/namespaces/"+t.Namespace.Name, nil)
	if errors.Is(err, cfg.ErrChanged) {
		return answer(value.AccessTargetChanged)
	}
	if err != nil {
		return value.AccessReviewAnswer{}, targetReadError(err)
	}
	o, err := objectEnvelope(raw)
	if err != nil || o.APIVersion != "v1" || o.Kind != "Namespace" {
		return value.AccessReviewAnswer{}, value.ErrUnavailable
	}
	ns, err := decodeMetadata(o.Metadata, true)
	if err != nil {
		return value.AccessReviewAnswer{}, value.ErrUnavailable
	}
	if ns.Name != t.Namespace.Name || ns.UID != t.Namespace.UID {
		return answer(value.AccessTargetChanged)
	}
	if ns.Deleting || slices.Contains(r.Source.ExcludedNamespaces, ns.Name) {
		return answer(value.AccessOutsideSource)
	}
	for k, v := range r.Source.NamespaceSelector {
		if got, ok := ns.Labels[k]; !ok || got != v {
			return answer(value.AccessOutsideSource)
		}
	}
	attributes := authorizationv1.ResourceAttributes{Namespace: t.Namespace.Name, Version: "v1"}
	object, objectUID := "", ""
	switch r.Source.Check {
	case cfg.ReviewPodExec:
		attributes.Resource, attributes.Subresource, attributes.Verb, attributes.Name = "pods", "exec", "create", t.PodName
		object, objectUID = "/api/v1/namespaces/"+t.Namespace.Name+"/pods/"+t.PodName, t.PodUID
	case cfg.ReviewNamespaceCaptureCreate:
		attributes.Group, attributes.Version, attributes.Resource, attributes.Verb = "asservat.io", "v1alpha1", "debugcaptures", "create"
	default:
		if t.Workload.Kind != "Deployment" && t.Workload.Kind != "StatefulSet" {
			return answer(value.AccessOutsideSource)
		}
		plural := strings.ToLower(t.Workload.Kind) + "s"
		attributes.Group, attributes.Resource, attributes.Name = "apps", plural, t.Workload.Name
		attributes.Verb = map[string]string{cfg.ReviewWorkloadGet: "get", cfg.ReviewWorkloadPatch: "patch", cfg.ReviewWorkloadUpdate: "update"}[r.Source.Check]
		object, objectUID = "/apis/apps/v1/namespaces/"+t.Namespace.Name+"/"+plural+"/"+t.Workload.Name, t.Workload.UID
	}
	if object != "" {
		raw, err := c.client.raw(ctx, object, nil)
		switch {
		case errors.Is(err, cfg.ErrChanged):
			// Deleted: the recorded name is reviewed; no replacement exists.
		case err != nil:
			return value.AccessReviewAnswer{}, targetReadError(err)
		default:
			var got struct {
				Metadata struct{ Name, Namespace, UID string }
			}
			if json.Unmarshal(raw, &got) != nil || !identity.Text(got.Metadata.UID, 64) {
				return value.AccessReviewAnswer{}, value.ErrUnavailable
			}
			if got.Metadata.UID != objectUID || got.Metadata.Namespace != t.Namespace.Name {
				return answer(value.AccessTargetChanged)
			}
		}
	}
	spec := authorizationv1.SubjectAccessReviewSpec{ResourceAttributes: &attributes, User: mapping.UsernamePrefix + r.Principal.Subject}
	if mapping.UID {
		spec.UID = r.Principal.Subject
	}
	if mapping.GroupsPrefix != nil {
		for _, g := range r.Principal.Groups {
			spec.Groups = append(spec.Groups, *mapping.GroupsPrefix+g)
		}
	}
	// The authenticator adds this group to every authenticated user; the
	// review must see what a real request of the mapped user would.
	spec.Groups = append(spec.Groups, "system:authenticated")
	raw, err = c.client.proofPost(ctx, "/apis/authorization.k8s.io/v1/subjectaccessreviews", authorizationv1.SubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}, Spec: spec}, nil)
	if err != nil {
		return value.AccessReviewAnswer{}, value.ErrUnavailable
	}
	var review authorizationv1.SubjectAccessReview
	if strictGuardJSON(raw, &review) != nil {
		return value.AccessReviewAnswer{}, value.ErrUnavailable
	}
	if ctx.Err() != nil {
		return value.AccessReviewAnswer{}, value.ErrUnavailable
	}
	if review.Status.Allowed && !review.Status.Denied && review.Status.EvaluationError == "" {
		return answer(value.AccessAllowed)
	}
	return answer(value.AccessDenied)
}
