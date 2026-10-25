package kubernetes

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// SSR authenticates this API client's actual local Pod-bound identity. It does
// not validate a provider JWT; the external provider independently TokenReviews
// the separately projected dedicated-audience JWT. No TokenReview/mint grant is
// added to the worker to make this observation.
func (s *InstalledWorkerProjectionReader) configurationProviderIdentity(ctx context.Context, podUID string) (string, error) {
	raw, err := s.client.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	defer clear(raw)
	if err != nil {
		return "", cfg.ErrUnavailable
	}
	var who auth.SelfSubjectReview
	if strictGuardJSON(raw, &who) != nil || who.APIVersion != "authentication.k8s.io/v1" || who.Kind != "SelfSubjectReview" {
		return "", cfg.ErrDenied
	}
	return s.configurationProviderActor(who.Status.UserInfo, podUID)
}

// Pure same-process validation for each actual API authentication response.
// Every loaded projected client remains bound to this original worker account
// and Pod; a native denial by another non-administrator is insufficient.
func (s *InstalledWorkerProjectionReader) configurationProviderActor(u auth.UserInfo, podUID string) (string, error) {
	a := s.input.Activation.ServiceAccount
	if u.Username != "system:serviceaccount:"+s.input.Namespace.Name+":"+a.Name || u.UID != a.UID || len(u.Extra["authentication.kubernetes.io/pod-name"]) != 1 || len(u.Extra["authentication.kubernetes.io/pod-uid"]) != 1 || u.Extra["authentication.kubernetes.io/pod-uid"][0] != podUID {
		return "", cfg.ErrDenied
	}
	groups := slices.Clone(u.Groups)
	slices.Sort(groups)
	if !slices.Equal(groups, []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + s.input.Namespace.Name}) {
		return "", cfg.ErrDenied
	}
	for _, admin := range s.guard.plan.Administrators {
		if actorMatches(admin, u) {
			return "", cfg.ErrDenied
		}
	}
	name := u.Extra["authentication.kubernetes.io/pod-name"][0]
	if len(validation.IsDNS1123Subdomain(name)) != 0 {
		return "", cfg.ErrDenied
	}
	return name, nil
}

type configurationProviderProcess struct {
	ReplicaSetUID string
	Template      artifact.Digest
}

func (s *InstalledWorkerProjectionReader) configurationProviderProcess(ctx context.Context, state contracts.InitialRuntimeResourceState, name, uid string) (configurationProviderProcess, error) {
	var zero configurationProviderProcess
	d, _, release, err := s.checkedWorkerDeployment(ctx, state)
	if err != nil {
		return zero, err
	}
	return s.configurationProviderProcessDeployment(ctx, d, release, name, uid)
}

// Uses the actual Deployment already checked in this same named native bracket.
// This is pure response reuse, not a second observation or retained readiness.
// d is the checked original-image view; release maps the live ReplicaSet and
// Pod images the same way (ADR-227).
func (s *InstalledWorkerProjectionReader) configurationProviderProcessDeployment(ctx context.Context, d *apps.Deployment, release *contracts.ReleaseRecord, name, uid string) (configurationProviderProcess, error) {
	var zero configurationProviderProcess
	if d == nil {
		return zero, cfg.ErrInvalid
	}
	template, err := ConnectorAPITemplateDigest(d.Spec.Template)
	if err != nil {
		return zero, cfg.ErrChanged
	}
	_, imageText, ok := strings.Cut(d.Spec.Template.Spec.Containers[0].Image, "@sha256:")
	if !ok {
		return zero, cfg.ErrChanged
	}
	raw, err := hex.DecodeString(imageText)
	if err != nil || len(raw) != 32 {
		return zero, cfg.ErrChanged
	}
	var image artifact.Digest
	copy(image[:], raw)
	var pod core.Pod
	if err = s.get(ctx, "/api/v1/namespaces/"+s.input.Namespace.Name+"/pods/"+name, &pod); err != nil {
		return zero, err
	}
	if pod.APIVersion != "v1" || pod.Kind != "Pod" || !ownerMetadata(pod.ObjectMeta, s.input.Namespace.Name, name, uid) || pod.Spec.ServiceAccountName != s.input.Activation.ServiceAccount.Name || pod.Spec.NodeName == "" || pod.Status.Phase != core.PodRunning || !ownerEnrollmentSelector(d.Spec.Selector, pod.Labels) {
		return zero, cfg.ErrChanged
	}
	ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok {
		return zero, cfg.ErrChanged
	}
	var rs apps.ReplicaSet
	if err = s.get(ctx, "/apis/apps/v1/namespaces/"+s.input.Namespace.Name+"/replicasets/"+ref.Name, &rs); err != nil {
		return zero, err
	}
	if rs.APIVersion != "apps/v1" || rs.Kind != "ReplicaSet" || !ownerMetadata(rs.ObjectMeta, s.input.Namespace.Name, ref.Name, string(ref.UID)) || rs.Spec.Replicas == nil || *rs.Spec.Replicas < 1 || !ownerEnrollmentSelector(rs.Spec.Selector, pod.Labels) {
		return zero, cfg.ErrChanged
	}
	mappedReplica, mappedPod := releaseOriginalReplicaSet(rs, release), releaseOriginalPod(pod, release)
	owner, ok := ownerController(rs.OwnerReferences, "Deployment", "apps/v1")
	if !ok || owner.Name != d.Name || string(owner.UID) != string(d.UID) || connectorAPITemplateMatch(d, &mappedReplica, &mappedPod, template, image, nil, 0) != nil {
		return zero, cfg.ErrChanged
	}
	// Deployment status/RV may change during normal startup. Complete original
	// spec/metadata are independently checked on both reads; status is no authority.
	return configurationProviderProcess{ReplicaSetUID: string(rs.UID), Template: template}, nil
}
