package kubernetes

import (
	"context"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Inspection contains no writer call. Its result may advance the finite driver
// only when the original state/result is positively verified. A missing child
// is never permission to CREATE; a locally uncertain receipt CAS is not retried.
func (s *OwnerProjectionOperation) inspect(ctx context.Context) error {
	p := s.resources.State.OwnerIdentity
	if p == nil {
		return cfg.ErrUnavailable
	}
	if s.step == ownerProjectionInspectLaunch {
		if err := s.readBothChildren(ctx); err != nil {
			return err
		}
		l := s.resources.State.OwnerLaunch
		if l == nil || !ownerIdentityClaimedLaunchObject(s.owner.current.source.ownerDeployment, s.resources.State, s.projection.root.input) {
			return cfg.ErrUnavailable
		}
		if l.Receipt != nil {
			s.result = OwnerProjectionAdvanceComplete
			return nil
		}
		if s.controller.receiptAttempts[ownerProjectionAcknowledgeLaunch] {
			return cfg.ErrUnavailable
		}
		s.result = OwnerProjectionAdvancePending
		return nil
	}
	if p.Configuration != nil {
		if err := s.readBothChildren(ctx); err != nil {
			return err
		}
		if p.Configuration.Receipt == nil {
			if s.controller.receiptAttempts[ownerProjectionAcknowledgeConfiguration] {
				return cfg.ErrUnavailable
			}
			s.result = OwnerProjectionAdvancePending
			return nil
		}
		if p.Receipt != nil {
			s.result = OwnerProjectionAdvanceComplete
			return nil
		}
		if s.controller.receiptAttempts[ownerProjectionAcknowledgeJoint] {
			return cfg.ErrUnavailable
		}
		s.result = OwnerProjectionAdvanceAcknowledged
		return nil
	}
	if p.Credentials != nil {
		if _, err := s.readChild(ctx, "credentials"); err != nil {
			return err
		}
		if p.Credentials.Receipt == nil {
			if s.controller.receiptAttempts[ownerProjectionAcknowledgeCredentials] {
				return cfg.ErrUnavailable
			}
			s.result = OwnerProjectionAdvancePending
			return nil
		}
	}
	s.result = OwnerProjectionAdvanceAcknowledged
	return nil
}
