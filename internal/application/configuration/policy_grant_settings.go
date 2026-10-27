package configuration

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

// PolicyGrantSettingsSource is implemented by the existing protected, cached
// identity reader. It does not introduce directory credentials or a watcher.
type PolicyGrantSettingsSource interface {
	IdentityPolicy(context.Context, string) (value.Policy, error)
}

// PolicyGrantSettingsProjection accepts the observation and clamps every older
// pending/approved policy grant in one transaction. It rechecks original source
// deadlines after locks; lower settings are never published before their clamp.
type PolicyGrantSettingsProjection interface {
	AcceptPolicyGrantSettings(context.Context, value.PolicyGrantSettingsObservation) error
}

// PolicyGrantSettingsObserver is owned by one joined permission-worker child.
// Its ten-second cadence is independent from permission and browser loops. A
// failed source/SQL call cannot refresh the prior projection's original expiry.
// There is no revision history or attempt to claim unseen ConfigMap transitions.
type PolicyGrantSettingsObserver struct {
	Issuer     string
	Source     PolicyGrantSettingsSource
	Projection PolicyGrantSettingsProjection
	Now        func() time.Time
	accepted   value.PolicyGrantSettingsObservation
}

const PolicyGrantSettingsCadence = 10 * time.Second

func (s *PolicyGrantSettingsObserver) Reconcile(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.Source == nil || s.Projection == nil || s.Now == nil || !value.Text(s.Issuer, 2048) {
		return value.ErrUnavailable
	}
	started := s.Now()
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p, err := s.Source.IdentityPolicy(call, s.Issuer)
	now := s.Now()
	if err != nil || call.Err() != nil || now.Before(started) || p.Issuer != s.Issuer || p.Validate(now) != nil {
		return value.ErrUnavailable
	}
	periods := value.DefaultPolicyGrantApproval()
	if p.PolicyGrants != nil {
		periods = *p.PolicyGrants
	}
	observation := value.PolicyGrantSettingsObservation{Issuer: p.Issuer, Revision: p.Revision, Values: periods, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}
	if !observation.Valid(now) {
		return value.ErrUnavailable
	}
	if observation == s.accepted {
		return nil
	} // exact cache hit cannot renew SQL time
	bounded, stop := context.WithDeadline(call, p.FreshUntil)
	defer stop()
	if err = s.Projection.AcceptPolicyGrantSettings(bounded, observation); err != nil || bounded.Err() != nil || !observation.Valid(s.Now()) {
		return value.ErrUnavailable
	}
	s.accepted = observation
	return nil
}

// Run owns one serial observer and joins any current bounded request when its
// parent lease is lost. Report receives errors locally; no failure escapes into
// another worker loop or terminates permission/browser observation.
func (s *PolicyGrantSettingsObserver) Run(ctx context.Context, report func(error)) {
	if ctx == nil {
		return
	}
	ticker := time.NewTicker(PolicyGrantSettingsCadence)
	defer ticker.Stop()
	for ctx.Err() == nil {
		err := s.Reconcile(ctx)
		if report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
