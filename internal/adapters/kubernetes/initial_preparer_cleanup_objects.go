package kubernetes

import (
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func (s *InitialPreparer) removeHandoverSecret(ctx context.Context, ref contracts.WorkerObjectReference) error {
	path := "/api/v1/namespaces/" + s.plan.Workload.Namespace + "/secrets/" + ref.Name
	raw, e := s.creator.raw(ctx, path, nil)
	if apierrors.IsNotFound(e) {
		return nil
	}
	if e != nil {
		return cfg.ErrUnavailable
	}
	defer clear(raw)
	var secret core.Secret
	if strictGuardJSON(raw, &secret) != nil {
		return cfg.ErrChanged
	}
	defer func() {
		for _, b := range secret.Data {
			clear(b)
		}
	}()
	expectedType := core.SecretTypeOpaque
	if ref.Name == s.plan.Workload.Credentials {
		expectedType = s.providerProjectionType()
	}
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || !ownerMetadata(secret.ObjectMeta, s.plan.Workload.Namespace, ref.Name, ref.UID) || secret.Immutable == nil || !*secret.Immutable || secret.Type != expectedType || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 {
		return cfg.ErrChanged
	}
	uid := types.UID(ref.UID)
	rv := secret.ResourceVersion
	body, e := json.Marshal(meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &uid, ResourceVersion: &rv}})
	if e != nil {
		return cfg.ErrInvalid
	}
	if _, e = s.creator.api.Delete().AbsPath(path).MaxRetries(0).Body(body).DoRaw(ctx); e != nil {
		return cfg.ErrUnavailable
	}
	raw, e = s.creator.raw(ctx, path, nil)
	clear(raw)
	if !apierrors.IsNotFound(e) {
		return cfg.ErrUnavailable
	}
	return nil
}
func (s *InitialPreparer) retireHandoverProbe(ctx context.Context, w contracts.InitialPreparationRoot) error {
	_, state, e := s.readPrivate(ctx)
	if e != nil || state.RootUID != w.RootUID || state.Probe == nil || !state.Probe.CreateClosed || state.Probe.Anchor == nil || state.Probe.Issue == nil || state.Probe.Issue.Response == nil {
		return cfg.ErrChanged
	}
	p := state.Probe
	c := w.Activation.Handover.Cleanup
	if p.Anchor.UID != c.ProbeAnchor.UID || c.ProbeAnchor.Name != s.probeAnchorName() {
		return cfg.ErrChanged
	}
	if e = s.removeHandoverSecret(ctx, c.ProbeAnchor); e != nil {
		return e
	}
	// Actual original-token rejection is mandatory because Kubernetes caches
	// successful authentication; deleting its Secret alone is insufficient.
	body, e := json.Marshal(auth.TokenReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}, Spec: auth.TokenReviewSpec{Token: p.Issue.Response.Token, Audiences: []string{p.Issue.Audience}}})
	if e != nil {
		return cfg.ErrInvalid
	}
	defer clear(body)
	raw, e := s.protection.observer.api.Post().AbsPath("/apis/authentication.k8s.io/v1/tokenreviews").MaxRetries(0).Body(body).DoRaw(ctx)
	defer clear(raw)
	var review auth.TokenReview
	if e != nil || strictGuardJSON(raw, &review) != nil || review.APIVersion != "authentication.k8s.io/v1" || review.Kind != "TokenReview" || review.Status.Authenticated || review.Status.User.Username != "" || review.Status.User.UID != "" || len(review.Status.User.Groups) != 0 || len(review.Status.User.Extra) != 0 || len(review.Status.Audiences) != 0 {
		return cfg.ErrUnavailable
	}
	return nil
}
func (s *InitialPreparer) retireHandoverTargets(ctx context.Context, w contracts.InitialPreparationRoot) error {
	c := w.Activation.Handover.Cleanup
	if e := s.removeHandoverSecret(ctx, w.Activation.Handover.Credentials); e != nil {
		return e
	}
	return s.removeHandoverSecret(ctx, c.SQLState)
}
func (s *InitialPreparer) retireHandoverRBAC(ctx context.Context, w contracts.InitialPreparationRoot) error {
	for i, o := range s.objects {
		// This permanent minimal pair supports current independent historical-read
		// proof after setup token retirement. It confers no activation authority.
		if preparerMetadata(o.object).Name == s.plan.Workload.Name+"-history-probe" {
			continue
		}
		if !retirePreparationAuthority(o.object.DeepCopyObject()) {
			continue
		}
		intent := w.Creates[i]
		path := o.path + "/" + intent.Name
		raw, e := s.creator.raw(ctx, path, nil)
		if e != nil {
			return cfg.ErrUnavailable
		}
		v, _, e := s.verified(raw, o, intent, false)
		if e != nil {
			if _, _, e = s.verified(raw, o, intent, true); e != nil {
				return e
			}
			continue
		}
		if !retirePreparationAuthority(v) {
			return cfg.ErrInvalid
		}
		raw, e = json.Marshal(v)
		if e != nil {
			return cfg.ErrInvalid
		}
		raw, e = s.creator.api.Put().AbsPath(path).Param("fieldValidation", "Strict").MaxRetries(0).Body(raw).DoRaw(ctx)
		if e != nil {
			return cfg.ErrUnavailable
		}
		if _, _, e = s.verified(raw, o, intent, true); e != nil {
			return e
		}
	}
	return nil
}
func (s *InitialPreparer) retireHandoverPrivate(ctx context.Context, w contracts.InitialPreparationRoot) error {
	raw, e := s.creator.raw(ctx, s.privatePath(), nil)
	if e != nil {
		return cfg.ErrUnavailable
	}
	defer clear(raw)
	var secret core.Secret
	if strictGuardJSON(raw, &secret) != nil {
		return cfg.ErrChanged
	}
	defer func() {
		for _, b := range secret.Data {
			clear(b)
		}
	}()
	ref := s.plan.PrivateState
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || !ownerMetadata(secret.ObjectMeta, s.plan.BootstrapNamespace.Name, ref.Name, ref.UID) || secret.Type != core.SecretTypeOpaque || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || len(secret.StringData) != 0 || secret.Annotations[initialNamespaceInstallationAnnotation] != s.plan.InstallationID || secret.Annotations[initialNamespaceRequestAnnotation] != s.plan.RequestID {
		return cfg.ErrChanged
	}
	retired := map[string][]byte{"retired": []byte("true")}
	if secret.Immutable != nil && *secret.Immutable {
		if !equalJSON(secret.Data, retired) {
			return cfg.ErrChanged
		}
		return nil
	}
	_, state, e := s.decodePrivate(raw)
	if e != nil || state.RootUID != w.RootUID {
		return cfg.ErrChanged
	}
	secret.Data = retired
	secret.Immutable = ptr.To(true)
	body, e := json.Marshal(secret)
	if e != nil {
		return cfg.ErrInvalid
	}
	defer clear(body)
	response, e := s.creator.api.Put().AbsPath(s.privatePath()).Param("fieldValidation", "Strict").MaxRetries(0).Body(body).DoRaw(ctx)
	defer clear(response)
	if e != nil {
		return cfg.ErrUnavailable
	}
	var got core.Secret
	if strictGuardJSON(response, &got) != nil || string(got.UID) != ref.UID || got.Immutable == nil || !*got.Immutable || !equalJSON(got.Data, retired) {
		return cfg.ErrChanged
	}
	return nil
}
func (s *InitialPreparer) retireHandoverPod(ctx context.Context, w contracts.InitialPreparationRoot) error {
	path := s.handoverPodPath()
	raw, e := s.creator.raw(ctx, path, nil)
	if apierrors.IsNotFound(e) {
		return nil
	}
	if e != nil {
		return cfg.ErrUnavailable
	}
	pod, e := s.handoverPod(raw, w, false)
	if e != nil || !s.successfulHandoverPod(pod, w) {
		return cfg.ErrChanged
	}
	if pod.Annotations[initialPreparationRetiredAnnotation] == "" {
		if pod.DeletionTimestamp != nil {
			return cfg.ErrChanged
		}
		pod.Annotations[initialPreparationRetiredAnnotation] = string(pod.UID)
		raw, e = json.Marshal(pod)
		if e != nil {
			return cfg.ErrInvalid
		}
		raw, e = s.creator.api.Put().AbsPath(path).Param("fieldValidation", "Strict").MaxRetries(0).Body(raw).DoRaw(ctx)
		if e != nil {
			return cfg.ErrUnavailable
		}
		pod, e = s.handoverPod(raw, w, false)
		if e != nil {
			return e
		}
	}
	uid := pod.UID
	rv := pod.ResourceVersion
	body, e := json.Marshal(meta.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0), Preconditions: &meta.Preconditions{UID: &uid, ResourceVersion: &rv}})
	if e != nil {
		return cfg.ErrInvalid
	}
	if _, e = s.creator.api.Delete().AbsPath(path).MaxRetries(0).Body(body).DoRaw(ctx); e != nil {
		return cfg.ErrUnavailable
	}
	_, e = s.creator.raw(ctx, path, nil)
	if !apierrors.IsNotFound(e) {
		return cfg.ErrUnavailable
	}
	return nil
}
