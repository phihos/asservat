package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// configurationWorkerSeed is untrusted input for a read-only provider
// inspection. It deliberately contains no native observation or authority
// interval. Only the later actual SQL/native verification can accept it.
// Its endpoints/CA/token are never read from either journal.
type configurationWorkerSeed struct {
	resources            contracts.InitialRuntimeResourceSnapshot
	roleState            contracts.ConfigurationRuntimeRoleState
	roleUID, roleVersion string
}

func (s *ConfigurationWorkerInputs) readSeed(ctx context.Context) (configurationWorkerSeed, error) {
	var zero configurationWorkerSeed
	if ctx == nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	if err := s.resources.preparer.creator.administrator(ctx); err != nil {
		return zero, err
	}
	resources, _, err := s.resources.read(ctx)
	if err != nil {
		return zero, err
	}
	if !s.sameOriginalResources(resources) {
		return zero, cfg.ErrChanged
	}
	raw, err := s.roles.client.api.Get().AbsPath(s.roles.path() + "/" + s.roles.name()).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	out, err := s.decodeSeed(raw, resources)
	if err != nil {
		return zero, err
	}
	until, ok := ctx.Deadline()
	if !ok || initialHandoverDeadline(ctx, s.resources.now, until) != nil {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}

func (s *ConfigurationWorkerInputs) decodeSeed(raw []byte, resources contracts.InitialRuntimeResourceSnapshot) (configurationWorkerSeed, error) {
	var zero configurationWorkerSeed
	if permissionJSON(raw, permissionPageBytes, 131072) != nil {
		return zero, cfg.ErrUnavailable
	}
	var object core.Secret
	if strictGuardJSON(raw, &object) != nil {
		return zero, cfg.ErrChanged
	}
	defer clearRuntimeProjection(object.Data)
	if object.APIVersion != "v1" || object.Kind != "Secret" || object.Namespace != s.roles.input.Namespace.Name ||
		object.Name != s.roles.name() || !authorization.UUID(string(object.UID)) || object.ResourceVersion == "" ||
		object.DeletionTimestamp != nil || len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 ||
		object.Type != core.SecretTypeOpaque || object.Immutable != nil && *object.Immutable || len(object.Data) != 1 || len(object.StringData) != 0 {
		return zero, cfg.ErrChanged
	}
	state, err := contracts.DecodeConfigurationRuntimeRoleState(bytes.NewReader(object.Data["state.json"]))
	if err != nil || !configurationRoleStateValid(s.roles.input, state, s.resources.now()) || state.Projection == nil || !authorization.UUID(state.Projection.SecretUID) {
		return zero, cfg.ErrChanged
	}
	// Remove the resource reader's incidental time fields too: a provisional
	// parse must never be confused with a current bridge/source observation.
	resources.ValidUntil = time.Time{}
	return configurationWorkerSeed{resources: resources, roleState: state, roleUID: string(object.UID), roleVersion: object.ResourceVersion}, nil
}

func (s configurationWorkerSeed) roleMaterial() contracts.ConfigurationRuntimeRoleSnapshot {
	// No Sources, ObservedAt, or ValidUntil is fabricated for pure derivation.
	return contracts.ConfigurationRuntimeRoleSnapshot{State: s.roleState, UID: s.roleUID, ResourceVersion: s.roleVersion}
}

func (s configurationWorkerSeed) matchesRole(verified contracts.ConfigurationRuntimeRoleSnapshot) bool {
	if s.roleUID != verified.UID || s.roleVersion != verified.ResourceVersion {
		return false
	}
	// Include every retained role claim, credential, receipt and child, not only
	// the public recipe's subset. Neither value is logged or hashed into a journal.
	a, e := json.Marshal(s.roleState)
	if e != nil {
		return false
	}
	defer clear(a)
	b, e := json.Marshal(verified.State)
	if e != nil {
		return false
	}
	defer clear(b)
	return bytes.Equal(a, b)
}

func (s *ConfigurationWorkerInputs) sameOriginalResources(v contracts.InitialRuntimeResourceSnapshot) bool {
	a, b := v.State, s.original.State
	return v.UID == s.original.UID && a.SetupID == b.SetupID && a.BindingDigest == b.BindingDigest &&
		a.CreatedAt.Equal(b.CreatedAt) && a.Until.Equal(b.Until) && a.WorkerLayout == b.WorkerLayout && a.OwnerLayout == b.OwnerLayout &&
		equalJSON(a.WorkerProvider, b.WorkerProvider) && equalJSON(a.OwnerProvider, b.OwnerProvider) && equalJSON(a.Objects, b.Objects)
}
