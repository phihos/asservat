package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func (s *PublicRuntimeRoleRoot) projectionName() string {
	return contracts.PublicRuntimeProjectionName(s.input.InstallationID)
}
func runtimeProjectionData(v contracts.PublicRuntimeRoleState) (map[string][]byte, error) {
	purposes := contracts.PublicRuntimeHubRolePurposes()
	out := make(map[string][]byte, len(purposes))
	for _, purpose := range purposes {
		n := slices.IndexFunc(v.Roles, func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose })
		if n < 0 || slices.IndexFunc(v.Roles[n+1:], func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose }) >= 0 {
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
		out["sql-public-"+r.Purpose+".json"] = b
	}
	return out, nil
}
func clearRuntimeProjection(data map[string][]byte) {
	for _, b := range data {
		clear(b)
	}
}

// runtimeProjectionManifest proves each purpose's claim and receipt, in order.
func runtimeProjectionManifest(original contracts.PublicRuntimeRoleSnapshot, purposes []string) ([]byte, error) {
	m := contracts.PublicRuntimeCredentialManifest{Format: contracts.PublicRuntimeCredentialManifestFormat, Input: original.State.Input, RootUID: original.UID, SetupID: original.State.OperationID}
	for _, purpose := range purposes {
		n := slices.IndexFunc(original.State.Roles, func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose })
		if n < 0 || original.State.Roles[n].Claim == nil || original.State.Roles[n].Receipt == nil {
			return nil, cfg.ErrUnavailable
		}
		r := original.State.Roles[n]
		m.Roles = append(m.Roles, contracts.PublicRuntimeCredentialProof{Purpose: purpose, Claim: *r.Claim, Receipt: *r.Receipt})
	}
	b, err := json.Marshal(m)
	if err != nil || len(b) > contracts.PublicRuntimeCredentialManifestMaxBytes {
		return nil, cfg.ErrUnavailable
	}
	return b, nil
}

// roleProjection is one immutable Secret projected from the role root: the
// hub-api's runtime projection or the federation's (ADR-193). Each has its own
// one-use claim slot in the role state.
type roleProjection struct {
	name  string
	claim func(*contracts.PublicRuntimeRoleState) **contracts.PublicRuntimeProjectionClaim
	data  func(contracts.PublicRuntimeRoleSnapshot) (map[string][]byte, error)
}

func (s *PublicRuntimeRoleRoot) hubProjection() roleProjection {
	return roleProjection{name: s.projectionName(), claim: func(v *contracts.PublicRuntimeRoleState) **contracts.PublicRuntimeProjectionClaim {
		return &v.Projection
	},
		data: func(old contracts.PublicRuntimeRoleSnapshot) (map[string][]byte, error) {
			data, err := runtimeProjectionData(old.State)
			if err != nil {
				return nil, err
			}
			manifest, err := runtimeProjectionManifest(old, contracts.PublicRuntimeHubRolePurposes())
			if err != nil {
				clearRuntimeProjection(data)
				return nil, err
			}
			data[contracts.PublicRuntimeCredentialManifestFile] = manifest
			keys, err := runtimeAuditKeyProjection(old)
			if err != nil {
				clearRuntimeProjection(data)
				return nil, err
			}
			data[contracts.PublicAuditKeysFile] = keys
			return data, nil
		}}
}

func (s *PublicRuntimeRoleRoot) projection(ctx context.Context, original contracts.PublicRuntimeRoleSnapshot, p roleProjection, data map[string][]byte) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	raw, err := s.client.api.Get().AbsPath(s.path() + "/" + p.name).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	var object core.Secret
	if strictGuardJSON(raw, &object) != nil {
		return zero, cfg.ErrChanged
	}
	defer clearRuntimeProjection(object.Data)
	state := original.State
	c := *p.claim(&state)
	if c == nil || object.APIVersion != "v1" || object.Kind != "Secret" || object.Name != p.name || object.Namespace != s.input.Namespace.Name || !authorization.UUID(string(object.UID)) || object.ResourceVersion == "" || object.DeletionTimestamp != nil || object.Immutable == nil || !*object.Immutable || object.Type != core.SecretTypeOpaque || len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 || len(object.StringData) != 0 || len(object.Data) != len(data) || len(object.Annotations) != 3 || object.Annotations["asservat.io/role-root-uid"] != original.UID || object.Annotations["asservat.io/role-setup-id"] != original.State.OperationID || object.Annotations["asservat.io/projection-id"] != c.OperationID || c.SecretUID != "" && c.SecretUID != string(object.UID) {
		return zero, cfg.ErrChanged
	}
	for name, want := range data {
		if !bytes.Equal(object.Data[name], want) {
			return zero, cfg.ErrChanged
		}
	}
	return contracts.WorkerObjectReference{Name: object.Name, UID: string(object.UID)}, nil
}

// PublishPublicRuntimeProjection is called after the concrete SQL producer has
// verified every fixed role and authenticated the original passwords. Its exact
// snapshot is compared again under the native guard. The hub receives this
// immutable runtime-only Secret, never the creation journal or administrator.
// Only an acknowledged first projection claim may CREATE. Unknown claim/write
// replies and every later invocation are lookup-only, even if the Secret is gone.
func (s *PublicRuntimeRoleRoot) PublishPublicRuntimeProjection(ctx context.Context, verified contracts.PublicRuntimeRoleSnapshot) (contracts.WorkerObjectReference, error) {
	return s.publishProjection(ctx, verified, s.hubProjection())
}

// PublishFederationRuntimeProjection publishes the federation's six SQL
// logins and its audit keys for the permission root (ADR-193), with the same
// one-use claim, readback and current checks as the hub-api projection.
func (s *PublicRuntimeRoleRoot) PublishFederationRuntimeProjection(ctx context.Context, verified contracts.PublicRuntimeRoleSnapshot, permissionRoot string) (contracts.WorkerObjectReference, error) {
	if s == nil || !authorization.UUID(permissionRoot) {
		return contracts.WorkerObjectReference{}, cfg.ErrInvalid
	}
	return s.publishProjection(ctx, verified, roleProjection{name: contracts.FederationRuntimeProjectionName(s.input.InstallationID),
		claim: func(v *contracts.PublicRuntimeRoleState) **contracts.PublicRuntimeProjectionClaim {
			return &v.FederationProjection
		},
		data: func(old contracts.PublicRuntimeRoleSnapshot) (map[string][]byte, error) {
			return federationProjectionData(old, permissionRoot)
		}})
}

// PublishKeyServiceRuntimeProjection publishes the key service's three SQL
// logins (ADR-198) with the same one-use claim and readback; nothing else.
func (s *PublicRuntimeRoleRoot) PublishKeyServiceRuntimeProjection(ctx context.Context, verified contracts.PublicRuntimeRoleSnapshot) (contracts.WorkerObjectReference, error) {
	if s == nil {
		return contracts.WorkerObjectReference{}, cfg.ErrInvalid
	}
	return s.publishProjection(ctx, verified, roleProjection{name: contracts.KeyServiceRuntimeProjectionName(s.input.InstallationID),
		claim: func(v *contracts.PublicRuntimeRoleState) **contracts.PublicRuntimeProjectionClaim {
			return &v.KeyServiceProjection
		},
		data: func(old contracts.PublicRuntimeRoleSnapshot) (map[string][]byte, error) {
			return roleCredentialFiles(old.State, contracts.PublicRuntimeKeyServicePurposes(), "sql-")
		}})
}

// PublishPublisherRuntimeProjection publishes the publisher's six SQL logins
// and their manifest (ADR-203) with the same one-use claim and readback.
func (s *PublicRuntimeRoleRoot) PublishPublisherRuntimeProjection(ctx context.Context, verified contracts.PublicRuntimeRoleSnapshot) (contracts.WorkerObjectReference, error) {
	if s == nil {
		return contracts.WorkerObjectReference{}, cfg.ErrInvalid
	}
	return s.publishProjection(ctx, verified, roleProjection{name: contracts.PublisherRuntimeProjectionName(s.input.InstallationID),
		claim: func(v *contracts.PublicRuntimeRoleState) **contracts.PublicRuntimeProjectionClaim {
			return &v.PublisherProjection
		},
		data: func(old contracts.PublicRuntimeRoleSnapshot) (map[string][]byte, error) {
			purposes := contracts.PublicRuntimePublisherPurposes()
			data, err := roleCredentialFiles(old.State, purposes, "sql-public-")
			if err != nil {
				return nil, err
			}
			manifest, err := runtimeProjectionManifest(old, purposes)
			if err != nil {
				clearRuntimeProjection(data)
				return nil, err
			}
			data[contracts.PublisherCredentialManifestFile] = manifest
			return data, nil
		}})
}

func (s *PublicRuntimeRoleRoot) publishProjection(ctx context.Context, verified contracts.PublicRuntimeRoleSnapshot, p roleProjection) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	ctx, end, err := s.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer end()
	op := newPublicProjectionOperation(ctx, s, verified)
	defer op.close()
	// 1: independent enforcement and complete current identities before root read.
	if err = op.current(); err != nil {
		return zero, err
	}
	old, object, err := op.read()
	if err != nil {
		return zero, err
	}
	if old.UID != verified.UID || old.State.Input != verified.State.Input || old.State.OperationID != verified.State.OperationID || !reflect.DeepEqual(old.State.Roles, verified.State.Roles) || !reflect.DeepEqual(old.State.MAC, verified.State.MAC) {
		return zero, cfg.ErrChanged
	}
	data, err := p.data(old)
	if err != nil {
		return zero, err
	}
	defer clearRuntimeProjection(data)
	// 2: the root read cannot substitute for a current pre-claim check.
	if err = op.current(); err != nil {
		return zero, err
	}
	fresh := *p.claim(&old.State) == nil
	if fresh {
		now := s.client.now().UTC().Truncate(time.Microsecond)
		until := op.until
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
		*p.claim(&next) = &contracts.PublicRuntimeProjectionClaim{OperationID: uuid.NewString(), ClaimedAt: now, Until: until}
		op.restrict(until)
		old, err = op.update(old, object, next)
		if err != nil {
			return zero, err
		}
	}
	// 3: only a positively acknowledged first claim can reach CREATE.
	if err = op.current(); err != nil {
		return zero, err
	}
	claim := *p.claim(&old.State)
	if fresh {
		v := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: p.name, Namespace: s.input.Namespace.Name, Annotations: map[string]string{"asservat.io/role-root-uid": old.UID, "asservat.io/role-setup-id": old.State.OperationID, "asservat.io/projection-id": claim.OperationID}}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: data}
		// No retry, replacement or adoption. The exact random claim and all original
		// contents must be independently read back even after a successful response.
		raw, _ := s.client.api.Post().AbsPath(s.path()).Param("fieldValidation", "Strict").Body(&v).MaxRetries(0).DoRaw(op.ctx)
		clear(raw)
	}
	ref, err := s.projection(op.ctx, old, p, data)
	if err != nil {
		return zero, err
	}
	current, rootObject, err := op.read()
	if err != nil {
		return zero, err
	}
	if current.UID != old.UID || !reflect.DeepEqual(current.State, old.State) {
		return zero, cfg.ErrChanged
	}
	// 4: exact object/root readback followed by current checks before receipt CAS.
	if err = op.current(); err != nil {
		return zero, err
	}
	if c := *p.claim(&current.State); c.SecretUID == "" {
		next := current.State
		receipt := *c
		receipt.SecretUID = ref.UID
		*p.claim(&next) = &receipt
		if _, err = op.update(current, rootObject, next); err != nil {
			return zero, err
		}
	}
	// 5: an acknowledged receipt is not a substitute for the final current check.
	if err = op.current(); err != nil {
		return zero, err
	}
	return ref, nil
}

// federationProjectionData is the federation's six SQL logins and its audit
// keys (the role root's MAC material, bound to the permission root).
func federationProjectionData(original contracts.PublicRuntimeRoleSnapshot, permissionRoot string) (map[string][]byte, error) {
	v := original.State
	out, err := roleCredentialFiles(v, contracts.PublicRuntimeFederationPurposes(), "sql-federation-")
	if err != nil {
		return nil, err
	}
	m := v.MAC
	if m.InputVersion != v.OperationID+"-input/v1" || m.AccountVersion != v.OperationID+"-account/v1" || len(m.InputKey) != 32 || len(m.AccountKey) != 32 {
		clearRuntimeProjection(out)
		return nil, cfg.ErrUnavailable
	}
	b, err := json.Marshal(contracts.FederationAuditKeys{Format: contracts.FederationAuditKeysFormat, InstallationID: v.Input.InstallationID, RootID: permissionRoot,
		InputVersion: m.InputVersion, InputKey: m.InputKey, AccountVersion: m.AccountVersion, AccountKey: m.AccountKey})
	if err != nil {
		clearRuntimeProjection(out)
		return nil, cfg.ErrUnavailable
	}
	out[contracts.FederationAuditKeysFile] = b
	return out, nil
}

// roleCredentialFiles is each purpose's verified login, as prefix+purpose+".json".
func roleCredentialFiles(v contracts.PublicRuntimeRoleState, purposes []string, prefix string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, purpose := range purposes {
		n := slices.IndexFunc(v.Roles, func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose })
		if n < 0 || slices.IndexFunc(v.Roles[n+1:], func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose }) >= 0 || v.Roles[n].Claim == nil || v.Roles[n].Receipt == nil {
			clearRuntimeProjection(out)
			return nil, cfg.ErrUnavailable
		}
		b, err := json.Marshal(contracts.OwnerSQLCredential{Username: v.Roles[n].Receipt.RoleName, Password: v.Roles[n].Password})
		if err != nil {
			clearRuntimeProjection(out)
			return nil, cfg.ErrUnavailable
		}
		out[prefix+purpose+".json"] = b
	}
	return out, nil
}

func runtimeAuditKeyProjection(original contracts.PublicRuntimeRoleSnapshot) ([]byte, error) {
	m := original.State.MAC
	if !authorization.UUID(original.UID) || !authorization.UUID(original.State.OperationID) || m.InputVersion != original.State.OperationID+"-input/v1" || m.AccountVersion != original.State.OperationID+"-account/v1" || len(m.InputKey) != 32 || len(m.AccountKey) != 32 || bytes.Equal(m.InputKey, m.AccountKey) {
		return nil, cfg.ErrUnavailable
	}
	out := contracts.PublicAuditKeys{Format: contracts.PublicAuditKeysFormat, InstallationID: original.State.Input.InstallationID, RootUID: original.UID, SetupID: original.State.OperationID, Material: m}
	b, e := json.Marshal(out)
	if e != nil || len(b) > contracts.PublicAuditKeysMaxBytes {
		return nil, cfg.ErrUnavailable
	}
	return b, nil
}

// The separate capacity projection writer will call this only after its own
// positive projection claim. It includes neither input key nor public roles.
func runtimeCaptureAccountProjection(original contracts.PublicRuntimeRoleSnapshot) ([]byte, error) {
	m := original.State.MAC
	if !authorization.UUID(original.UID) || !authorization.UUID(original.State.OperationID) || m.AccountVersion != original.State.OperationID+"-account/v1" || len(m.AccountKey) != 32 {
		return nil, cfg.ErrUnavailable
	}
	out := contracts.CaptureAccountKey{Format: contracts.CaptureAccountKeyFormat, InstallationID: original.State.Input.InstallationID, RootUID: original.UID, SetupID: original.State.OperationID, Version: m.AccountVersion, Key: m.AccountKey}
	b, e := json.Marshal(out)
	if e != nil || len(b) > contracts.PublicAuditKeysMaxBytes {
		return nil, cfg.ErrUnavailable
	}
	return b, nil
}
