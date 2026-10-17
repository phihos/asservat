package kubernetes

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

func (s *CapacityRuntimeProjection) observe(ctx context.Context, original contracts.InitialRuntimeResourceSnapshot, data map[string][]byte) (contracts.CapacityRuntimeProjectionReceipt, error) {
	var zero contracts.CapacityRuntimeProjectionReceipt
	raw, e := s.roles.client.api.Get().AbsPath(s.roles.path() + "/" + contracts.CapacityRuntimeProjectionName(s.input.InstallationID)).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	var object core.Secret
	if permissionJSON(raw, 768<<10, 65536) != nil || strictGuardJSON(raw, &object) != nil {
		return zero, cfg.ErrChanged
	}
	defer clearRuntimeProjection(object.Data)
	p := original.State.CapacityProjection
	if p == nil || object.APIVersion != "v1" || object.Kind != "Secret" || object.Namespace != s.input.Control.Namespace.Name ||
		object.Name != contracts.CapacityRuntimeProjectionName(s.input.InstallationID) || !authorization.UUID(string(object.UID)) || !identity.Text(object.ResourceVersion, 128) ||
		object.DeletionTimestamp != nil || len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 || len(object.Labels) != 0 ||
		!equalJSON(object.Annotations, capacityProjectionAnnotations(original.UID, original.State.SetupID, p)) || object.Immutable == nil || !*object.Immutable ||
		object.Type != core.SecretTypeOpaque || len(object.StringData) != 0 || len(object.Data) != len(data) {
		return zero, cfg.ErrChanged
	}
	for name, want := range data {
		if !bytes.Equal(object.Data[name], want) {
			return zero, cfg.ErrChanged
		}
	}
	r := contracts.CapacityRuntimeProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: object.Name, UID: string(object.UID)}, ResourceVersion: object.ResourceVersion, ObservedAt: s.resources.now().UTC().Truncate(time.Microsecond)}
	if p.Receipt != nil && !capacityProjectionSameObject(*p.Receipt, r) {
		return zero, cfg.ErrChanged
	}
	if e = s.bridge.deadline(ctx); e != nil {
		return zero, e
	}
	return r, nil
}
