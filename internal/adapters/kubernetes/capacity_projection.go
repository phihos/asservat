package kubernetes

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// CapacityRuntimeProjection is an administrator-side continuation of the
// original completed bridge. It owns one fixed immutable Secret. The runtime
// never receives this object, the broad role root or administrator credentials.
type CapacityRuntimeProjection struct {
	bridge         *InitialRuntimeBridge
	resources      *InitialRuntimeResources
	roles          *PublicRuntimeRoleRoot
	input          contracts.CapacityDeployment
	claimAttempted bool // serialized by the original bridge operation
}

func NewCapacityRuntimeProjection(bridge *InitialRuntimeBridge, resources *InitialRuntimeResources, roles *PublicRuntimeRoleRoot, input contracts.CapacityDeployment) (*CapacityRuntimeProjection, error) {
	if bridge == nil || resources == nil || roles == nil || bridge.preparer != resources.preparer || bridge.rootUID != resources.rootUID ||
		!equalJSON(bridge.initial, resources.initial) || resources.workerLayout == "" || !initialRuntimeProviderSelectionValid(resources.initial.InstallationID, resources.workerLayout, resources.ownerLayout, resources.workerProvider, resources.ownerProvider) ||
		input.LocalOwner == nil || resources.ownerLayout == "" || input.Format != contracts.CapacityDeploymentFormat || input.InstallationID != bridge.initial.InstallationID || input.InstallationID != roles.input.InstallationID ||
		input.Control.Namespace != roles.input.Namespace || input.Control.ClusterID != roles.input.ClusterID || !publicRuntimeWorkerBindingValid(roles.input) {
		return nil, cfg.ErrInvalid
	}
	// Copy every nested input; a caller cannot alter the original public digest
	// after a claim has acquired ownership of the sole CREATE.
	b, e := json.Marshal(input)
	if e != nil || len(b) > contracts.CapacityDeploymentMaxBytes {
		return nil, cfg.ErrInvalid
	}
	var cloned contracts.CapacityDeployment
	if e = json.Unmarshal(b, &cloned); e != nil {
		return nil, cfg.ErrInvalid
	}
	return &CapacityRuntimeProjection{bridge: bridge, resources: resources, roles: roles, input: cloned}, nil
}

// Publish requires the exact original SQL-verified role/setup snapshot. The
// producer re-reads that private snapshot under current native protection. Only
// a positively acknowledged first journal CAS can issue CREATE; all subsequent
// calls (including uncertain claim replies) are exact lookup only.
func (s *CapacityRuntimeProjection) Publish(ctx context.Context, verified contracts.PublicRuntimeRoleSnapshot) (contracts.CapacityRuntimeProjectionReceipt, error) {
	var out contracts.CapacityRuntimeProjectionReceipt
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
		if roles.UID != verified.UID || roles.State.OperationID != verified.State.OperationID || roles.State.Input != verified.State.Input ||
			!reflect.DeepEqual(roles.State.Roles, verified.State.Roles) || !reflect.DeepEqual(roles.State.MAC, verified.State.MAC) || !reflect.DeepEqual(roles.State.CapacitySetup, verified.State.CapacitySetup) {
			return cfg.ErrChanged
		}
		until := identity.Earlier(roles.ValidUntil, verified.ValidUntil)
		call, end := context.WithDeadline(call, until)
		defer end()
		if e = s.bridge.deadline(call); e != nil {
			return e
		}
		at = "material"
		data, digest, e := capacityProjectionMaterial(s.input, roles)
		if e != nil {
			return e
		}
		defer clearRuntimeProjection(data)
		var manifest contracts.CapacityCredentialManifest
		if json.Unmarshal(data[contracts.CapacityCredentialManifestFile], &manifest) != nil {
			return cfg.ErrInvalid
		}
		// ADR-191: one retained bracket for the whole publication; the journal
		// writes are CAS against this bracket's object.
		at = "journal-read"
		retained, e := s.bridge.readRetainedWorkerResources(call, s.resources, roles.State.Input.Worker)
		if e != nil {
			return e
		}
		old, object := retained.resources, retained.object
		call, stop := context.WithDeadline(call, retained.until)
		defer stop()
		at = "local-owner"
		carrier, carrierUntil, e := s.bridge.readCapacityLocalOwner(call, s.resources, old, s.input, manifest)
		if e != nil {
			return e
		}
		if !equalJSON(carrier, s.input.LocalOwner) {
			return cfg.ErrChanged
		}
		call, endCarrier := context.WithDeadline(call, carrierUntil)
		defer endCarrier()
		fresh := old.State.CapacityProjection == nil
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
			next.CapacityProjection = &contracts.CapacityRuntimeProjectionClaim{OperationID: id, PublicDigest: digest, Setup: *roles.State.CapacitySetup.Receipt, ClaimedAt: now, Until: until}
			s.claimAttempted = true
			if old, object, e = s.write(call, old, object, next); e != nil {
				return e
			} // Unknown CAS never owns CREATE.
		}
		p := old.State.CapacityProjection
		if p == nil || p.PublicDigest != digest || !equalJSON(p.Setup, *roles.State.CapacitySetup.Receipt) {
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
			secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: contracts.CapacityRuntimeProjectionName(s.input.InstallationID), Namespace: s.input.Control.Namespace.Name, Annotations: capacityProjectionAnnotations(old.UID, old.State.SetupID, p)}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: data}
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
			if !capacityProjectionSameObject(*p.Receipt, observed) {
				return cfg.ErrChanged
			}
			out = *p.Receipt
		} else {
			at = "receipt-write"
			next := old.State
			claim := *p
			claim.Receipt = &observed
			next.CapacityProjection = &claim
			ack, _, e := s.write(call, old, object, next)
			if e != nil {
				return e
			}
			out = *ack.State.CapacityProjection.Receipt
		}
		at = "closing"
		return s.bridge.closeRetained(call, retained)
	})
	if err != nil {
		left := "none"
		if d, ok := ctx.Deadline(); ok {
			left = time.Until(d).Round(time.Millisecond).String()
		}
		return contracts.CapacityRuntimeProjectionReceipt{}, &projectionStop{Step: "capacity " + at + " after " + time.Since(started).Round(time.Millisecond).String() + ", " + left + " left", Err: err}
	}
	return out, nil
}

func capacityProjectionSameClaim(a, b *contracts.CapacityRuntimeProjectionClaim) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := *a, *b
	x.Receipt, y.Receipt = nil, nil
	return equalJSON(x, y)
}
func capacityProjectionSameObject(a, b contracts.CapacityRuntimeProjectionReceipt) bool {
	return a.Secret == b.Secret && a.ResourceVersion == b.ResourceVersion
}

// write is one journal CAS against the bracket's object (ADR-191): the
// resource version in the body makes the API server refuse any change since
// that read. No re-read precedes it; an unknown reply stays lookup-only.
func (s *CapacityRuntimeProjection) write(ctx context.Context, current contracts.InitialRuntimeResourceSnapshot, object *core.Secret, next contracts.InitialRuntimeResourceState) (contracts.InitialRuntimeResourceSnapshot, *core.Secret, error) {
	var zero contracts.InitialRuntimeResourceSnapshot
	if object == nil || string(object.UID) != current.UID || object.ResourceVersion != current.ResourceVersion || !s.resources.valid(next) || !s.resources.now().Before(next.Until) || !capacityProjectionTransition(current.State, next) {
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
