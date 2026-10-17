package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/api/v1alpha1"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/rest"
)

// EnsureRetentionBaseline creates the hub's empty-scope baseline retention
// policy from the operator's values (ADR-195 D2), or reopens it only when its
// spec is unchanged. The caller runs it as an installation administrator,
// after the hub source's first acceptance, so that acceptance needs no review.
func EnsureRetentionBaseline(ctx context.Context, config *rest.Config, namespace, installation string, b contracts.InstallerRetentionBaseline) error {
	if ctx == nil || config == nil || namespace == "" || !authorization.UUID(installation) || b.PurposeRef == "" || len(b.PurposeRef) > 128 || b.DeletionBudgetSeconds < 1 {
		return cfg.ErrInvalid
	}
	durations := func(d contracts.InstallerRetentionDurations) v1alpha1.RetentionDurations {
		return v1alpha1.RetentionDurations{EvidenceSeconds: d.EvidenceSeconds, CaseMetadataSeconds: d.CaseMetadataSeconds, AuditMetadataSeconds: d.AuditMetadataSeconds}
	}
	spec := v1alpha1.RetentionPolicySpec{PurposeRef: b.PurposeRef, Defaults: durations(b.Defaults), Maxima: durations(b.Maxima), Rules: []v1alpha1.RetentionRule{}, DeletionBudgetSeconds: b.DeletionBudgetSeconds, LegalExceptions: "disabled"}
	name := contracts.RetentionBaselineName(installation)
	body, err := json.Marshal(map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceRetentionPolicy", "metadata": map[string]string{"name": name, "namespace": namespace}, "spec": spec})
	if err != nil {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	path := "/apis/asservat.io/v1alpha1/namespaces/" + namespace + "/evidenceretentionpolicies"
	_, err = api.CoreV1().RESTClient().Post().AbsPath(path).Body(body).MaxRetries(0).DoRaw(call)
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return cfg.ErrUnavailable
	}
	raw, err := api.CoreV1().RESTClient().Get().AbsPath(path + "/" + name).DoRaw(call)
	var existing struct {
		Spec v1alpha1.RetentionPolicySpec `json:"spec"`
	}
	if err != nil || json.Unmarshal(raw, &existing) != nil {
		return cfg.ErrUnavailable
	}
	if !equalJSON(existing.Spec, spec) {
		return cfg.ErrChanged
	}
	return nil
}
