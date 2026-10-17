package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func (s *ConfigurationWorkerInputs) inputObject(v contracts.InitialRuntimeResourceSnapshot, raw []byte) *core.ConfigMap {
	return &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{
		Name: s.resources.names.WorkerInputs, Namespace: s.roles.input.Namespace.Name,
		Annotations: configurationWorkerInputAnnotations(v.UID, v.State.SetupID, v.State.WorkerInputs)},
		Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(raw)}}
}

func (s *ConfigurationWorkerInputs) createInput(ctx context.Context, v contracts.InitialRuntimeResourceSnapshot, raw []byte) error {
	if v.State.WorkerInputs == nil || v.State.WorkerInputs.Receipt != nil || initialHandoverDeadline(ctx, s.resources.now, v.State.WorkerInputs.Until) != nil {
		return cfg.ErrUnavailable
	}
	// Only the acknowledged first claim reaches this method. Even an unknown
	// response leaves the attempt spent. A later call can only read the target.
	body := s.inputObject(v, raw)
	reply, err := s.roles.client.api.Post().AbsPath("/api/v1/namespaces/"+s.roles.input.Namespace.Name+"/configmaps").Param("fieldValidation", "Strict").MaxRetries(0).Body(body).DoRaw(ctx)
	clear(reply)
	if err != nil {
		return cfg.ErrUnavailable
	}
	return initialHandoverDeadline(ctx, s.resources.now, v.State.WorkerInputs.Until)
}

func (s *ConfigurationWorkerInputs) readInput(ctx context.Context, v contracts.InitialRuntimeResourceSnapshot, raw []byte) (contracts.ConfigurationWorkerInputReceipt, error) {
	var zero contracts.ConfigurationWorkerInputReceipt
	p := v.State.WorkerInputs
	if p == nil {
		return zero, cfg.ErrChanged
	}
	want := s.inputObject(v, raw)
	reply, err := s.roles.client.api.Get().AbsPath("/api/v1/namespaces/" + want.Namespace + "/configmaps/" + want.Name).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	var actual core.ConfigMap
	if permissionJSON(reply, contracts.OwnerDeploymentMaxBytes*2, 131072) != nil || strictGuardJSON(reply, &actual) != nil || actual.APIVersion != "v1" || actual.Kind != "ConfigMap" ||
		!authorization.UUID(string(actual.UID)) || !ownerMetadata(actual.ObjectMeta, want.Namespace, want.Name, string(actual.UID)) || actual.Immutable == nil || !*actual.Immutable ||
		len(actual.BinaryData) != 0 || len(actual.OwnerReferences) != 0 || len(actual.Finalizers) != 0 || len(actual.Labels) != 0 ||
		!equalJSON(actual.Annotations, want.Annotations) || !equalJSON(actual.Data, want.Data) {
		return zero, cfg.ErrChanged
	}
	receipt := contracts.ConfigurationWorkerInputReceipt{Configuration: contracts.WorkerObjectReference{Name: actual.Name, UID: string(actual.UID)}, ResourceVersion: actual.ResourceVersion, ObservedAt: s.resources.now().UTC().Truncate(time.Microsecond)}
	if p.Receipt != nil {
		if p.Receipt.Configuration != receipt.Configuration || p.Receipt.ResourceVersion != receipt.ResourceVersion {
			return zero, cfg.ErrChanged
		}
		receipt = *p.Receipt
	}
	until, ok := ctx.Deadline()
	if !ok {
		return zero, cfg.ErrInvalid
	}
	if initialHandoverDeadline(ctx, s.resources.now, until) != nil {
		return zero, cfg.ErrUnavailable
	}
	return receipt, nil
}
