package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
)

func (s *OwnerProjectionOperation) readChild(ctx context.Context, purpose string) (contracts.OwnerIdentityObjectReceipt, error) {
	got, err := s.projection.readObject(ctx, s.resources.State.OwnerIdentity, purpose, s.input, s.activation, s.data)
	if err != nil {
		return got, err
	}
	if s.pending != nil {
		want := s.pending.children[ownerProjectionChildIndex(purpose)]
		if want == nil || got.Object != want.Object || got.ResourceVersion != want.ResourceVersion {
			return contracts.OwnerIdentityObjectReceipt{}, cfg.ErrChanged
		}
	}
	return got, nil
}
func (s *OwnerProjectionOperation) readBothChildren(ctx context.Context) error {
	if _, err := s.readChild(ctx, "credentials"); err != nil {
		return err
	}
	_, err := s.readChild(ctx, "configuration")
	return err
}
func (s *OwnerProjectionOperation) readFinalChildren(ctx context.Context) error {
	switch s.step {
	case ownerProjectionInspect:
		p := s.resources.State.OwnerIdentity
		if p.Configuration != nil {
			return s.readBothChildren(ctx)
		}
		if p.Credentials != nil {
			_, err := s.readChild(ctx, "credentials")
			return err
		}
		return nil
	case ownerProjectionParent:
		return nil
	case ownerProjectionCreateCredentials, ownerProjectionAcknowledgeCredentials:
		_, err := s.readChild(ctx, "credentials")
		return err
	default:
		return s.readBothChildren(ctx)
	}
}

func (s *OwnerProjectionOperation) apply(ctx context.Context) error {
	switch s.step {
	case ownerProjectionParent:
		// The already positively acknowledged public intent has no object effect.
		if !s.fresh {
			return cfg.ErrUnavailable
		}
		s.fresh = false
		s.result = OwnerProjectionAdvanceAcknowledged
		return nil
	case ownerProjectionCreateCredentials, ownerProjectionCreateConfiguration:
		if !s.fresh {
			return cfg.ErrUnavailable
		}
		s.fresh = false
		purpose := "credentials"
		child := s.resources.State.OwnerIdentity.Credentials
		if s.step == ownerProjectionCreateConfiguration {
			purpose = "configuration"
			child = s.resources.State.OwnerIdentity.Configuration
			if _, err := s.readChild(ctx, "credentials"); err != nil {
				return err
			}
		}
		if child == nil || child.Receipt != nil {
			return cfg.ErrChanged
		}
		call, stop, err := s.originalEffect(ctx, child.Until)
		if err != nil {
			return err
		}
		defer stop()
		s.effectDispatched = true
		if s.pending != nil {
			var candidate contracts.OwnerIdentityObjectReceipt
			candidate, err = s.projection.createObjectCandidate(call, s.resources.State.OwnerIdentity, purpose, s.input, s.activation, s.data)
			if err == nil {
				s.pending.children[ownerProjectionChildIndex(purpose)] = &candidate
			}
		} else {
			err = s.projection.createObject(call, s.resources.State.OwnerIdentity, purpose, s.input, s.activation, s.data)
		}
		if err != nil {
			return err
		}
		s.result = OwnerProjectionAdvancePending
		return nil
	case ownerProjectionAcknowledgeCredentials, ownerProjectionAcknowledgeConfiguration:
		purpose := "credentials"
		if s.step == ownerProjectionAcknowledgeConfiguration {
			purpose = "configuration"
			if _, err := s.readChild(ctx, "credentials"); err != nil {
				return err
			}
		}
		if s.controller.receiptAttempts[s.step] {
			return cfg.ErrUnavailable
		}
		receipt, err := s.readChild(ctx, purpose)
		if err != nil {
			return err
		}
		next := s.resources.State
		parent := *next.OwnerIdentity
		next.OwnerIdentity = &parent
		var child contracts.OwnerIdentityObjectAttempt
		if purpose == "credentials" {
			child = *parent.Credentials
			parent.Credentials = &child
		} else {
			child = *parent.Configuration
			parent.Configuration = &child
		}
		if child.Receipt != nil {
			return cfg.ErrChanged
		}
		child.Receipt = &receipt
		s.controller.receiptAttempts[s.step] = true
		if err = s.writeResources(ctx, next, false, s.owner.until); err != nil {
			return err
		}
		s.result = OwnerProjectionAdvanceAcknowledged
		return nil
	case ownerProjectionAcknowledgeJoint:
		if s.controller.receiptAttempts[s.step] {
			return cfg.ErrUnavailable
		}
		if err := s.readBothChildren(ctx); err != nil {
			return err
		}
		next := s.resources.State
		parent := *next.OwnerIdentity
		next.OwnerIdentity = &parent
		c, f := parent.Credentials.Receipt, parent.Configuration.Receipt
		if c == nil || f == nil || parent.Receipt != nil {
			return cfg.ErrChanged
		}
		parent.Receipt = &contracts.OwnerIdentityProjectionReceipt{Credentials: c.Object, CredentialsResourceVersion: c.ResourceVersion, Configuration: f.Object, ConfigurationResourceVersion: f.ResourceVersion, ObservedAt: s.projection.root.resources.now().UTC().Truncate(time.Microsecond)}
		s.controller.receiptAttempts[s.step] = true
		if err := s.writeResources(ctx, next, false, s.owner.until); err != nil {
			return err
		}
		s.result = OwnerProjectionAdvanceComplete
		return nil
	case ownerProjectionReadComplete:
		if err := s.readBothChildren(ctx); err != nil {
			return err
		}
		s.result = OwnerProjectionAdvanceComplete
		return nil
	case ownerProjectionInspect, ownerProjectionInspectLaunch:
		return s.inspect(ctx)
	case ownerProjectionLaunch:
		return s.launch(ctx)
	case ownerProjectionAcknowledgeLaunch, ownerProjectionReadLaunch:
		if err := s.readBothChildren(ctx); err != nil {
			return err
		}
		d := s.owner.current.source.ownerDeployment
		if !ownerIdentityClaimedLaunchObject(d, s.resources.State, s.projection.root.input) {
			return cfg.ErrUnavailable
		}
		if s.step == ownerProjectionAcknowledgeLaunch {
			if s.controller.receiptAttempts[s.step] {
				return cfg.ErrUnavailable
			}
			next := s.resources.State
			launch := *next.OwnerLaunch
			next.OwnerLaunch = &launch
			if launch.Receipt != nil {
				return cfg.ErrChanged
			}
			launch.Receipt = &contracts.OwnerIdentityLaunchReceipt{ResourceVersion: d.ResourceVersion, Generation: d.Generation, ObservedAt: s.projection.root.resources.now().UTC().Truncate(time.Microsecond)}
			s.controller.receiptAttempts[s.step] = true
			if err := s.writeResources(ctx, next, true, s.owner.until); err != nil {
				return err
			}
		}
		s.result = OwnerProjectionAdvanceComplete
		return nil
	default:
		return cfg.ErrInvalid
	}
}

// Persist the child's original end into the operation before the only external
// CREATE/PUT. A later final phase cannot regain time by using its parent ctx.
func (s *OwnerProjectionOperation) originalEffect(ctx context.Context, end time.Time) (context.Context, context.CancelFunc, error) {
	s.owner.mu.Lock()
	s.owner.until = identity.Earlier(s.owner.until, end)
	until := s.owner.until
	s.owner.mu.Unlock()
	call, stop := context.WithDeadline(ctx, until)
	if initialHandoverDeadline(call, s.projection.root.resources.now, until) != nil {
		stop()
		return nil, nil, cfg.ErrUnavailable
	}
	return call, stop, nil
}
func (s *OwnerProjectionOperation) launch(ctx context.Context) error {
	if !s.fresh {
		return cfg.ErrUnavailable
	}
	s.fresh = false
	if err := s.readBothChildren(ctx); err != nil {
		return err
	}
	claim := s.resources.State.OwnerLaunch
	d := s.owner.current.source.ownerDeployment
	if claim == nil || claim.Receipt != nil || d.ResourceVersion != claim.InertResourceVersion || d.Spec.Replicas == nil || *d.Spec.Replicas != 0 || d.Annotations[ownerIdentityLaunchMarker] != "" {
		return cfg.ErrChanged
	}
	digest, err := ownerIdentitySpecDigest(d)
	if err != nil || digest != claim.InertDigest {
		return cfg.ErrChanged
	}
	call, stop, err := s.originalEffect(ctx, claim.Until)
	if err != nil {
		return err
	}
	defer stop()
	next := d.DeepCopy()
	*next.Spec.Replicas = 1
	if next.Annotations == nil {
		next.Annotations = map[string]string{}
	}
	next.Annotations[ownerIdentityLaunchMarker] = claim.OperationID
	s.effectDispatched = true
	raw, err := s.projection.root.bridge.source.client.api.Put().AbsPath(s.projection.launchPath()).Param("fieldValidation", "Strict").Body(next).MaxRetries(0).DoRaw(call)
	defer clear(raw)
	if err != nil {
		return cfg.ErrUnavailable
	}
	var actual apps.Deployment
	if permissionJSON(raw, 256<<10, 131072) != nil || strictGuardJSON(raw, &actual) != nil || !ownerIdentityClaimedLaunchObject(actual, s.resources.State, s.projection.root.input) {
		return cfg.ErrChanged
	}
	if initialHandoverDeadline(call, s.projection.root.resources.now, s.owner.until) != nil {
		return cfg.ErrUnavailable
	}
	s.result = OwnerProjectionAdvancePending
	return nil
}
