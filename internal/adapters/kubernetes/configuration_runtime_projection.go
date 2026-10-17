package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func (s *ConfigurationRuntimeRoleRoot) projectionName() string {
	return "asservat-configuration-runtime-" + strings.ReplaceAll(s.input.InstallationID, "-", "")
}
func configurationProjectionData(v contracts.ConfigurationRuntimeRoleState) (map[string][]byte, error) {
	purposes := contracts.ConfigurationRuntimeRolePurposes()
	out := make(map[string][]byte, len(purposes))
	for _, purpose := range purposes {
		n := slices.IndexFunc(v.Roles, func(r contracts.ConfigurationRuntimeRoleMaterial) bool { return r.Purpose == purpose })
		if n < 0 || slices.IndexFunc(v.Roles[n+1:], func(r contracts.ConfigurationRuntimeRoleMaterial) bool { return r.Purpose == purpose }) >= 0 {
			clearRuntimeProjection(out)
			return nil, cfg.ErrUnavailable
		}
		r := v.Roles[n]
		if r.Claim == nil || r.Receipt == nil {
			clearRuntimeProjection(out)
			return nil, cfg.ErrUnavailable
		}
		b, err := json.Marshal(contracts.OwnerSQLCredential{Username: r.Receipt.RoleName, Password: r.Password})
		if err != nil {
			clearRuntimeProjection(out)
			return nil, cfg.ErrUnavailable
		}
		filename := map[string]string{"configuration-fleet": "sql-fleet.json", "configuration-source": "sql-configuration.json", "configuration-audit": "sql-audit.json"}[r.Purpose]
		out[filename] = b
	}
	return out, nil
}

func configurationProjectionManifest(original contracts.ConfigurationRuntimeRoleSnapshot) ([]byte, error) {
	m := contracts.ConfigurationRuntimeCredentialManifest{Format: contracts.ConfigurationRuntimeCredentialManifestFormat, Input: original.State.Input, RootUID: original.UID, SetupID: original.State.OperationID}
	for _, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		n := slices.IndexFunc(original.State.Roles, func(r contracts.ConfigurationRuntimeRoleMaterial) bool { return r.Purpose == purpose })
		if n < 0 || original.State.Roles[n].Claim == nil || original.State.Roles[n].Receipt == nil {
			return nil, cfg.ErrUnavailable
		}
		r := original.State.Roles[n]
		m.Roles = append(m.Roles, contracts.ConfigurationRuntimeCredentialProof{Purpose: purpose, Claim: *r.Claim, Receipt: *r.Receipt})
	}
	b, err := json.Marshal(m)
	if err != nil || len(b) > contracts.ConfigurationRuntimeRoleMaxBytes {
		return nil, cfg.ErrUnavailable
	}
	return b, nil
}
func (s *ConfigurationRuntimeRoleRoot) projection(ctx context.Context, original contracts.ConfigurationRuntimeRoleSnapshot, data map[string][]byte) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	raw, err := s.client.api.Get().AbsPath(s.path() + "/" + s.projectionName()).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	var object core.Secret
	if strictGuardJSON(raw, &object) != nil {
		return zero, cfg.ErrChanged
	}
	defer clearRuntimeProjection(object.Data)
	p := original.State.Projection
	if p == nil || object.APIVersion != "v1" || object.Kind != "Secret" || object.Name != s.projectionName() || object.Namespace != s.input.Namespace.Name || !authorization.UUID(string(object.UID)) || object.ResourceVersion == "" || object.DeletionTimestamp != nil || object.Immutable == nil || !*object.Immutable || object.Type != core.SecretTypeOpaque || len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 || len(object.StringData) != 0 || len(object.Data) != len(data) || len(object.Annotations) != 3 || object.Annotations["asservat.io/role-root-uid"] != original.UID || object.Annotations["asservat.io/role-setup-id"] != original.State.OperationID || object.Annotations["asservat.io/projection-id"] != p.OperationID || p.SecretUID != "" && p.SecretUID != string(object.UID) {
		return zero, cfg.ErrChanged
	}
	for name, want := range data {
		if !bytes.Equal(object.Data[name], want) {
			return zero, cfg.ErrChanged
		}
	}
	return contracts.WorkerObjectReference{Name: object.Name, UID: string(object.UID)}, nil
}

// PublishConfigurationRuntimeProjection is called after the concrete SQL producer has
// verified every fixed role and authenticated the original passwords. Its exact
// snapshot is compared again under the native guard. The reconciler receives this
// immutable three-role Secret, never the creation journal or administrator.
// Only an acknowledged first projection claim may CREATE. Unknown claim/write
// replies and every later invocation are lookup-only, even if the Secret is gone.
func (s *ConfigurationRuntimeRoleRoot) PublishConfigurationRuntimeProjection(ctx context.Context, verified contracts.ConfigurationRuntimeRoleSnapshot) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	ctx, end, err := s.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer end()
	old, object, err := s.read(ctx)
	if err != nil {
		return zero, err
	}
	if old.UID != verified.UID || old.State.Input != verified.State.Input || old.State.OperationID != verified.State.OperationID || !reflect.DeepEqual(old.State.Roles, verified.State.Roles) || !configurationRoleSameSources(old.Sources, verified.Sources) {
		return zero, cfg.ErrChanged
	}
	data, err := configurationProjectionData(old.State)
	if err != nil {
		return zero, err
	}
	defer clearRuntimeProjection(data)
	manifest, err := configurationProjectionManifest(old)
	if err != nil {
		return zero, err
	}
	data[contracts.ConfigurationRuntimeRoleManifestFile] = manifest
	fresh := old.State.Projection == nil
	if fresh {
		now := s.client.now().UTC().Truncate(time.Microsecond)
		until := old.ValidUntil
		if old.State.Until.Before(until) {
			until = old.State.Until
		}
		if verified.ValidUntil.Before(until) {
			until = verified.ValidUntil
		}
		until = until.UTC().Truncate(time.Microsecond)
		if !now.Before(until) {
			return zero, cfg.ErrUnavailable
		}
		next := old.State
		next.Projection = &contracts.PublicRuntimeProjectionClaim{OperationID: uuid.NewString(), ClaimedAt: now, Until: until}
		old, err = s.update(ctx, old, object, next, until)
		if err != nil {
			return zero, err
		}
	}
	until := old.ValidUntil
	if verified.ValidUntil.Before(until) {
		until = verified.ValidUntil
	}
	if fresh && old.State.Projection.Until.Before(until) {
		until = old.State.Projection.Until
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if bounded.Err() != nil || !s.client.now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	if fresh {
		v := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: s.projectionName(), Namespace: s.input.Namespace.Name, Annotations: map[string]string{"asservat.io/role-root-uid": old.UID, "asservat.io/role-setup-id": old.State.OperationID, "asservat.io/projection-id": old.State.Projection.OperationID}}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: data}
		// No retry, replacement or adoption. The exact random claim and all original
		// contents must be independently read back even after a successful response.
		raw, _ := s.client.api.Post().AbsPath(s.path()).Param("fieldValidation", "Strict").Body(&v).MaxRetries(0).DoRaw(bounded)
		clear(raw)
	}
	ref, err := s.projection(bounded, old, data)
	if err != nil {
		return zero, err
	}
	// The create followed a post-verification recheck; this readback records
	// its Secret UID under that proof's original deadline (ADR-188).
	started := s.client.now()
	proof, err := s.source.latestConfigurationRoleSource(bounded)
	if err != nil {
		return zero, err
	}
	current, rootObject, err := s.readObserved(bounded, proof, started)
	if err != nil || current.UID != old.UID || !reflect.DeepEqual(current.State, old.State) {
		return zero, cfg.ErrChanged
	}
	if current.State.Projection.SecretUID == "" {
		next := current.State
		claim := *next.Projection
		claim.SecretUID = ref.UID
		next.Projection = &claim
		if _, err = s.update(bounded, current, rootObject, next, until); err != nil {
			return zero, err
		}
	}
	if bounded.Err() != nil || !s.client.now().Before(until) {
		return zero, cfg.ErrUnavailable
	}
	return ref, nil
}
