package authorization

import (
	"context"
	"errors"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// PreviewProjections reads the accepted permission projection cells of a
// proposal in one consistent snapshot.
type PreviewProjections interface {
	PreviewProjections(context.Context, cfg.PreviewRead) (cfg.PreviewSnapshot, error)
}

// PreviewAdministration is the protected fleet administration source that
// names the installation's operators.
type PreviewAdministration interface {
	FleetAdministration(context.Context) (fleet.Administration, error)
}

// BindingSpecDecoder applies the observed AccessBinding schema and checks.
type BindingSpecDecoder interface {
	DecodeAccessBindingSpec([]byte) (cfg.Binding, error)
}

// ProposedChange is one administrator-supplied change; Spec is the raw
// AccessBinding spec for create and update.
type ProposedChange struct {
	Action, Kind, UID string
	Spec              []byte
}

// AccessPreviewer answers preview_access_change (ADR-237): the delta of the
// ordinary evaluator's decisions that a proposed AccessBinding configuration
// would cause, over the current accepted projections. Only a current fleet
// operator (the installation-wide administrator) may call it; it reads no
// catalog or evidence, writes nothing and returns no authority.
type AccessPreviewer struct {
	InstallationID string
	Administration PreviewAdministration
	Projections    PreviewProjections
	Decoder        BindingSpecDecoder
	Recovery       ExplainRecovery
	// Clusters are the installation's enrolled clusters (the hub and the
	// guarded catalog read at process start).
	Clusters []string
	Now      func() time.Time
}

// Preview returns the preview and the reply's metadata deadline. cfg.ErrInvalid
// marks an invalid proposal, cfg.ErrLimit one beyond the preview bounds.
func (s AccessPreviewer) Preview(ctx context.Context, current identities.CurrentIdentity, proposed []ProposedChange) (cfg.AccessPreview, time.Time, error) {
	var zero cfg.AccessPreview
	if ctx == nil || current == nil || s.Administration == nil || s.Projections == nil || s.Decoder == nil || s.Recovery == nil || s.Now == nil || !value.UUID(s.InstallationID) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrDenied
	}
	// Authority precedes decoding, so a non-administrator learns nothing,
	// not even whether a proposal is well formed.
	admin, err := s.Administration.FleetAdministration(ctx)
	if err != nil || !admin.Valid(s.Now()) || admin.InstallationID != s.InstallationID {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	if !admin.Operator(i) {
		return zero, time.Time{}, identity.ErrDenied
	}
	until := identity.Earlier(i.ValidUntil, admin.FreshUntil)
	if len(proposed) < 1 || len(proposed) > cfg.MaxPreviewChanges {
		return zero, time.Time{}, cfg.ErrLimit
	}
	changes := make([]cfg.AccessChange, len(proposed))
	for n, p := range proposed {
		changes[n] = cfg.AccessChange{Action: p.Action, Kind: p.Kind, UID: p.UID}
		if p.Action == "delete" {
			if len(p.Spec) != 0 {
				return zero, time.Time{}, cfg.ErrInvalid
			}
			continue
		}
		if changes[n].Binding, err = s.Decoder.DecodeAccessBindingSpec(p.Spec); err != nil {
			return zero, time.Time{}, cfg.ErrInvalid
		}
	}
	changes, read, err := cfg.PreviewChanges(changes)
	if err != nil {
		return zero, time.Time{}, err
	}
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	snap, err := s.Projections.PreviewProjections(ctx, read)
	if errors.Is(err, cfg.ErrLimit) {
		return zero, time.Time{}, cfg.ErrLimit
	}
	if err != nil {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	out, err := cfg.PreviewAccess(changes, snap, s.Clusters, i.Policy, s.Now())
	if err != nil {
		return zero, time.Time{}, err
	}
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !fresh.Valid(s.Now()) || !admin.Operator(fresh) {
		return zero, time.Time{}, identity.ErrDenied
	}
	until = identity.Earlier(until, fresh.ValidUntil)
	if ctx.Err() != nil || !s.Now().Before(until) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	return out, until, nil
}
