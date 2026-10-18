package kubernetes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

// PermissionRuntimeProjection publishes the hub-worker's permission stream
// input (ADR-189) as one immutable Secret, claimed and acknowledged in the
// original resource journal like the capacity projection. The runtime never
// receives this object, the role root or administrator credentials.
type PermissionRuntimeProjection struct {
	bridge         *InitialRuntimeBridge
	resources      *InitialRuntimeResources
	roles          *PublicRuntimeRoleRoot
	input          contracts.PermissionDeployment
	claimAttempted bool // serialized by the original bridge operation
}

func NewPermissionRuntimeProjection(bridge *InitialRuntimeBridge, resources *InitialRuntimeResources, roles *PublicRuntimeRoleRoot, input contracts.PermissionDeployment) (*PermissionRuntimeProjection, error) {
	if bridge == nil || resources == nil || roles == nil || bridge.preparer != resources.preparer || bridge.rootUID != resources.rootUID ||
		!equalJSON(bridge.initial, resources.initial) || resources.workerLayout == "" || resources.ownerLayout == "" ||
		input.Format != contracts.PermissionDeploymentFormat || input.InstallationID != bridge.initial.InstallationID || input.InstallationID != roles.input.InstallationID ||
		!authorization.UUID(input.RootID) || input.Control.Namespace != roles.input.Namespace || input.Control.ClusterID != roles.input.ClusterID ||
		input.Control.Guard.Name != contracts.PermissionGuardName(input.InstallationID) || !publicRuntimeWorkerBindingValid(roles.input) || !WorkerConfigurationSectionValid(input) {
		return nil, cfg.ErrInvalid
	}
	b, e := json.Marshal(input)
	if e != nil || len(b) > contracts.PermissionDeploymentMaxBytes {
		return nil, cfg.ErrInvalid
	}
	var cloned contracts.PermissionDeployment
	if e = json.Unmarshal(b, &cloned); e != nil {
		return nil, cfg.ErrInvalid
	}
	return &PermissionRuntimeProjection{bridge: bridge, resources: resources, roles: roles, input: cloned}, nil
}

// WorkerConfigurationSectionValid checks the shape of the projection's
// optional worker configuration section (ADR-204 decision 7). The projection
// is published once and immutable, so the installer and the hub-worker check
// the same shape; the guard, source and SQL revision are proved only at each
// observation. Workers never run in the hub namespace (ADR-204 decision 1),
// and the section names its own guard and Transit key.
func WorkerConfigurationSectionValid(c contracts.PermissionDeployment) bool {
	v := c.WorkerConfiguration
	if v == nil {
		return true
	}
	g := v.Guard
	if len(validation.IsDNS1123Label(v.Namespace.Name)) != 0 || !authorization.UUID(v.Namespace.UID) || v.Namespace.Name == c.Control.Namespace.Name || v.Namespace.UID == c.Control.Namespace.UID ||
		len(validation.IsDNS1123Subdomain(v.Source.Name)) != 0 || !authorization.UUID(v.Source.UID) ||
		len(validation.IsDNS1123Label(g.Name)) != 0 || g.Name == c.Control.Guard.Name || !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) || !identity.Text(g.BindingResourceVersion, 128) ||
		g.PolicyGeneration < 1 || g.PolicyGeneration > 2147483647 || len(g.Administrators) < 1 || len(g.Administrators) > 32 ||
		!ownerBootstrapProviderName.MatchString(v.AuditTransit.Mount) || !ownerBootstrapProviderName.MatchString(v.AuditTransit.Key) {
		return false
	}
	seen := map[contracts.OwnerDeploymentActor]bool{}
	for _, a := range g.Administrators {
		if (a.Kind != "User" && a.Kind != "Group") || !identity.Text(a.Name, 256) || seen[a] {
			return false
		}
		seen[a] = true
	}
	return true
}

// ContextDeletionSectionValid checks the optional ADR-205 section's syntax:
// the evidence store and the pinned deletion signing key. It
// grants nothing; each purge, record and release is still checked in SQL.
func ContextDeletionSectionValid(v *contracts.ContextDeletionDeployment, now time.Time) bool {
	if v == nil {
		return true
	}
	s := v.Signing
	if providerconfig.ValidateStore(v.EvidenceStore, now) != nil ||
		!ownerBootstrapProviderName.MatchString(s.Mount) || !ownerBootstrapProviderName.MatchString(s.Key) || s.Version < 1 || s.Version > 2147483647 ||
		!identity.Text(s.KeyID, 128) || len(s.PublicKeys) < 1 || len(s.PublicKeys) > 16 || len(s.PublicKeys[s.KeyID]) != ed25519.PublicKeySize {
		return false
	}
	for id, key := range s.PublicKeys {
		if !identity.Text(id, 128) || len(key) != ed25519.PublicKeySize {
			return false
		}
	}
	return true
}

// projectionStop names the fixed publication stage that stopped, with the
// elapsed time and the remaining deadline, for the operator stop message.
type projectionStop struct {
	Step string
	Err  error
}

func (e *projectionStop) Error() string     { return "projection stopped at " + e.Step }
func (e *projectionStop) Unwrap() error     { return e.Err }
func (e *projectionStop) FixedStep() string { return e.Step }

// PermissionRuntimePublicDigest covers public configuration only.
func PermissionRuntimePublicDigest(c contracts.PermissionDeployment, m contracts.PermissionCredentialManifest) string {
	return preparationDigest(struct {
		Format     string                                 `json:"format"`
		Deployment contracts.PermissionDeployment         `json:"deployment"`
		Manifest   contracts.PermissionCredentialManifest `json:"manifest"`
	}{"asservat-permission-projection-public/v1", c, m})
}

func permissionProjectionMaterial(c contracts.PermissionDeployment, original contracts.PublicRuntimeRoleSnapshot) (map[string][]byte, string, error) {
	v := original.State
	if c.InstallationID != v.Input.InstallationID || c.Control.ClusterID != v.Input.ClusterID || c.Control.Namespace != v.Input.Namespace ||
		c.RoleRootUID != original.UID || c.RoleSetupID != v.OperationID {
		return nil, "", cfg.ErrChanged
	}
	m := contracts.PermissionCredentialManifest{Format: contracts.PermissionCredentialManifestFormat, Input: v.Input, RootUID: original.UID, SetupID: v.OperationID}
	data := make(map[string][]byte, 4)
	ok := false
	defer func() {
		if !ok {
			clearRuntimeProjection(data)
		}
	}()
	for _, purpose := range contracts.PermissionProjectionPurposes(c.Retention != nil, c.WorkerConfiguration != nil, c.ContextDeletion) {
		i := slices.IndexFunc(v.Roles, func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose })
		if i < 0 || slices.IndexFunc(v.Roles[i+1:], func(r contracts.PublicRuntimeRoleMaterial) bool { return r.Purpose == purpose }) >= 0 {
			return nil, "", cfg.ErrChanged
		}
		r := v.Roles[i]
		if r.Claim == nil || r.Receipt == nil || r.Password == "" {
			return nil, "", cfg.ErrChanged
		}
		m.Roles = append(m.Roles, contracts.PublicRuntimeCredentialProof{Purpose: purpose, Claim: *r.Claim, Receipt: *r.Receipt})
		b, e := json.Marshal(contracts.OwnerSQLCredential{Username: r.Receipt.RoleName, Password: r.Password})
		if e != nil {
			return nil, "", cfg.ErrInvalid
		}
		data["sql-"+purpose+".json"] = b
	}
	for _, item := range []struct {
		name  string
		value any
		limit int
	}{
		{contracts.PermissionDeploymentFile, c, contracts.PermissionDeploymentMaxBytes},
		{contracts.PermissionCredentialManifestFile, m, contracts.PermissionCredentialManifestMaxBytes},
	} {
		b, e := json.Marshal(item.value)
		if e != nil || len(b) > item.limit {
			clear(b)
			return nil, "", cfg.ErrInvalid
		}
		data[item.name] = b
	}
	ok = true
	return data, PermissionRuntimePublicDigest(c, m), nil
}

func permissionProjectionAnnotations(resourceUID, setupID string, p *contracts.PermissionRuntimeProjectionClaim) map[string]string {
	return map[string]string{"asservat.io/runtime-resource-uid": resourceUID, "asservat.io/runtime-resource-setup": setupID, "asservat.io/projection-id": p.OperationID, "asservat.io/projection-public": p.PublicDigest}
}

// Publish requires the exact original SQL-verified role snapshot. Only a
// positively acknowledged first journal CAS may issue CREATE; later calls and
// uncertain claims are exact lookup only.
func (s *PermissionRuntimeProjection) Publish(ctx context.Context, verified contracts.PublicRuntimeRoleSnapshot) (contracts.PermissionRuntimeProjectionReceipt, error) {
	var out contracts.PermissionRuntimeProjectionReceipt
	if s == nil {
		return out, cfg.ErrInvalid
	}
	started, at := time.Now(), "bridge"
	err := s.bridge.operation(ctx, func(call context.Context) error {
		at = "roles-enter"
		call, release, e := s.roles.enter(call)
		if e != nil {
			return e
		}
		defer release()
		at = "borrow"
		call, releaseResources, e := s.resources.borrowWorkerProjection(call)
		if e != nil {
			return e
		}
		defer releaseResources()
		at = "roles-read"
		roles, _, e := s.roles.read(call)
		if e != nil {
			return e
		}
		defer clear(roles.State.MAC.AccountKey)
		defer clear(roles.State.MAC.InputKey)
		if roles.UID != verified.UID || roles.State.OperationID != verified.State.OperationID || roles.State.Input != verified.State.Input || !equalJSON(roles.State.Roles, verified.State.Roles) {
			return cfg.ErrChanged
		}
		until := identity.Earlier(roles.ValidUntil, verified.ValidUntil)
		call, end := context.WithDeadline(call, until)
		defer end()
		if e = s.bridge.deadline(call); e != nil {
			return e
		}
		at = "material"
		data, digest, e := permissionProjectionMaterial(s.input, roles)
		if e != nil {
			return e
		}
		defer clearRuntimeProjection(data)
		// ADR-191: one retained bracket for the whole publication. The role
		// operation's opening proof covers the owner workload and the worker
		// binding; the journal writes are CAS against this bracket's object.
		at = "journal-read"
		worker := roles.State.Input.Worker
		if s.bridge.source == nil || worker.Configuration != s.bridge.source.input || worker.Resources.Name != s.resources.name() || worker.ResourceBinding != s.resources.binding {
			return cfg.ErrChanged
		}
		retained, e := s.bridge.readRetainedOriginalResources(call, s.resources)
		if e != nil {
			return e
		}
		old, object := retained.resources, retained.object
		if !installedWorkerReceiptsMatch(s.resources, old, worker) {
			return cfg.ErrChanged
		}
		call, stop := context.WithDeadline(call, retained.until)
		defer stop()
		fresh := old.State.PermissionProjection == nil
		if fresh {
			if s.claimAttempted {
				return cfg.ErrUnavailable
			}
			at = "claim-write"
			now := s.resources.now().UTC().Truncate(time.Microsecond)
			until, _ = call.Deadline()
			until = identity.Earlier(until, old.State.Until).UTC().Truncate(time.Microsecond)
			if !now.Before(until) {
				return cfg.ErrUnavailable
			}
			id, e := prepUUID()
			if e != nil {
				return e
			}
			next := old.State
			next.PermissionProjection = &contracts.PermissionRuntimeProjectionClaim{OperationID: id, RootID: s.input.RootID, PublicDigest: digest, ClaimedAt: now, Until: until}
			s.claimAttempted = true
			if old, object, e = s.write(call, old, object, next); e != nil {
				return e
			} // Unknown CAS never owns CREATE.
		}
		p := old.State.PermissionProjection
		if p == nil || p.PublicDigest != digest || p.RootID != s.input.RootID {
			return cfg.ErrChanged
		}
		if fresh {
			var finish context.CancelFunc
			call, finish = context.WithDeadline(call, p.Until)
			defer finish()
			if e = s.bridge.deadline(call); e != nil {
				return e
			}
			at = "create"
			secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: contracts.PermissionRuntimeProjectionName(s.input.InstallationID), Namespace: s.input.Control.Namespace.Name, Annotations: permissionProjectionAnnotations(old.UID, old.State.SetupID, p)}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: data}
			// Even a positive CREATE is independently verified below. An unknown
			// response permits only that exact read, never another POST.
			raw, _ := s.roles.client.api.Post().AbsPath(s.roles.path()).Param("fieldValidation", "Strict").MaxRetries(0).Body(&secret).DoRaw(call)
			clear(raw)
		}
		at = "observe"
		observed, e := s.observe(call, old, data)
		if e != nil {
			return e
		}
		if p.Receipt != nil {
			if p.Receipt.Secret != observed.Secret || p.Receipt.ResourceVersion != observed.ResourceVersion {
				return cfg.ErrChanged
			}
			out = *p.Receipt
		} else {
			at = "receipt-write"
			next := old.State
			claim := *p
			claim.Receipt = &observed
			next.PermissionProjection = &claim
			ack, _, e := s.write(call, old, object, next)
			if e != nil {
				return e
			}
			out = *ack.State.PermissionProjection.Receipt
		}
		at = "closing"
		after, phase, e := s.bridge.phasePolicy(call, retained.bridge.State)
		if e != nil {
			return e
		}
		if phase != 2 || retained.policy == nil || after.Generation != retained.policy.Generation || !equalJSON(after.Spec, retained.policy.Spec) {
			return cfg.ErrChanged
		}
		return s.bridge.deadline(call)
	})
	if err != nil {
		left := "none"
		if d, ok := ctx.Deadline(); ok {
			left = time.Until(d).Round(time.Millisecond).String()
		}
		return contracts.PermissionRuntimeProjectionReceipt{}, &projectionStop{Step: at + " after " + time.Since(started).Round(time.Millisecond).String() + ", " + left + " left", Err: err}
	}
	return out, nil
}

func (s *PermissionRuntimeProjection) observe(ctx context.Context, original contracts.InitialRuntimeResourceSnapshot, data map[string][]byte) (contracts.PermissionRuntimeProjectionReceipt, error) {
	var zero contracts.PermissionRuntimeProjectionReceipt
	name := contracts.PermissionRuntimeProjectionName(s.input.InstallationID)
	raw, e := s.roles.client.api.Get().AbsPath(s.roles.path() + "/" + name).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	var object core.Secret
	if permissionJSON(raw, 256<<10, 65536) != nil || strictGuardJSON(raw, &object) != nil {
		return zero, cfg.ErrChanged
	}
	defer clearRuntimeProjection(object.Data)
	p := original.State.PermissionProjection
	if p == nil || object.APIVersion != "v1" || object.Kind != "Secret" || object.Namespace != s.input.Control.Namespace.Name ||
		object.Name != name || !authorization.UUID(string(object.UID)) || !identity.Text(object.ResourceVersion, 128) ||
		object.DeletionTimestamp != nil || len(object.OwnerReferences) != 0 || len(object.Finalizers) != 0 || len(object.Labels) != 0 ||
		!equalJSON(object.Annotations, permissionProjectionAnnotations(original.UID, original.State.SetupID, p)) || object.Immutable == nil || !*object.Immutable ||
		object.Type != core.SecretTypeOpaque || len(object.StringData) != 0 || len(object.Data) != len(data) {
		return zero, cfg.ErrChanged
	}
	for name, want := range data {
		if !bytes.Equal(object.Data[name], want) {
			return zero, cfg.ErrChanged
		}
	}
	r := contracts.PermissionRuntimeProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: object.Name, UID: string(object.UID)}, ResourceVersion: object.ResourceVersion, ObservedAt: s.resources.now().UTC().Truncate(time.Microsecond)}
	if p.Receipt != nil && (p.Receipt.Secret != r.Secret || p.Receipt.ResourceVersion != r.ResourceVersion) {
		return zero, cfg.ErrChanged
	}
	if e = s.bridge.deadline(ctx); e != nil {
		return zero, e
	}
	return r, nil
}

// write is one journal CAS against the bracket's object (ADR-191): the
// resource version in the body makes the API server refuse any change since
// that read. No re-read precedes it; an unknown reply stays lookup-only.
func (s *PermissionRuntimeProjection) write(ctx context.Context, current contracts.InitialRuntimeResourceSnapshot, object *core.Secret, next contracts.InitialRuntimeResourceState) (contracts.InitialRuntimeResourceSnapshot, *core.Secret, error) {
	var zero contracts.InitialRuntimeResourceSnapshot
	if object == nil || string(object.UID) != current.UID || object.ResourceVersion != current.ResourceVersion || !s.resources.valid(next) || !s.resources.now().Before(next.Until) || !permissionProjectionTransition(current.State, next) {
		return zero, nil, cfg.ErrChanged
	}
	call, end := context.WithDeadline(ctx, identity.Earlier(current.ValidUntil, next.Until))
	defer end()
	if e := s.bridge.deadline(call); e != nil {
		return zero, nil, e
	}
	b, e := json.Marshal(next)
	if e != nil || len(b) > contracts.InitialRuntimeResourcesMaxBytes {
		return zero, nil, cfg.ErrInvalid
	}
	updated := object.DeepCopy()
	updated.Data = map[string][]byte{"state.json": b}
	raw, e := s.roles.client.api.Put().AbsPath(s.resources.path()).Param("fieldValidation", "Strict").MaxRetries(0).Body(updated).DoRaw(call)
	if e != nil {
		return zero, nil, cfg.ErrUnavailable
	}
	got, obj, e := s.resources.decode(call, raw)
	if e != nil || got.UID != current.UID || got.ResourceVersion == current.ResourceVersion || !equalJSON(got.State, next) {
		return zero, nil, cfg.ErrChanged
	}
	if e = s.bridge.deadline(call); e != nil {
		return zero, nil, e
	}
	got.ValidUntil = identity.Earlier(got.ValidUntil, current.ValidUntil)
	return got, obj, nil
}
