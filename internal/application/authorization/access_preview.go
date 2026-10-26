package authorization

import (
	"context"
	"errors"
	"slices"
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

// BindingSpecDecoder applies the observed AccessBinding and PermissionSource
// schemas and checks.
type BindingSpecDecoder interface {
	DecodeAccessBindingSpec([]byte) (cfg.Binding, error)
	DecodePermissionSourceSpec([]byte) (cfg.Source, error)
}

// ProposedChange is one administrator-supplied change; Spec is the raw
// AccessBinding or PermissionSource spec for create and update.
type ProposedChange struct {
	Action, Kind, UID string
	Spec              []byte
}

// PreviewPrincipal is one browser identity (a user subject or a stable group
// ID of the configured issuer).
type PreviewPrincipal struct{ Issuer, Kind, ID string }

func (p PreviewPrincipal) matches(i identity.Identity) bool {
	if p.Issuer != i.Principal.Issuer {
		return false
	}
	switch p.Kind {
	case "User":
		return i.Principal.Kind == identity.Human && i.Principal.Subject == p.ID
	case "Group":
		return slices.Contains(i.Groups, p.ID)
	}
	return false
}

// PreviewDelegation is one installation-configured delegation envelope of the
// permission guard (ADR-189) and the browser principals that may preview
// changes within it.
type PreviewDelegation struct {
	Previewers []PreviewPrincipal
	Envelope   cfg.PreviewEnvelope
}

// AccessPreviewer answers preview_access_change (ADR-237): the delta of the
// ordinary evaluator's decisions that a proposed permission configuration
// would cause, over the current accepted projections. A current fleet
// operator (the installation-wide administrator) previews any change; a
// configured delegation previewer previews within their delegation
// envelopes. It reads no catalog or evidence, writes nothing and returns no
// authority.
type AccessPreviewer struct {
	InstallationID string
	// Administration is nil without fleet administration; then only
	// delegation previewers exist.
	Administration PreviewAdministration
	Delegations    []PreviewDelegation
	Projections    PreviewProjections
	Decoder        BindingSpecDecoder
	Recovery       ExplainRecovery
	// Clusters are the installation's enrolled clusters (the hub and the
	// guarded catalog read at process start).
	Clusters []string
	Now      func() time.Time
}

// administration reads the protected fleet administration once per request;
// ok is false when it is unavailable or absent.
func (s AccessPreviewer) administration(ctx context.Context) (fleet.Administration, bool) {
	if s.Administration == nil {
		return fleet.Administration{}, false
	}
	admin, err := s.Administration.FleetAdministration(ctx)
	return admin, err == nil && admin.Valid(s.Now()) && admin.InstallationID == s.InstallationID
}

// authority returns nil envelopes for a fleet operator, the caller's
// delegation envelopes otherwise, or an error.
func (s AccessPreviewer) authority(i identity.Identity, admin fleet.Administration, adminValid bool) ([]cfg.PreviewEnvelope, time.Time, error) {
	if adminValid && admin.Operator(i) {
		return nil, identity.Earlier(i.ValidUntil, admin.FreshUntil), nil
	}
	var envelopes []cfg.PreviewEnvelope
	for _, d := range s.Delegations {
		if slices.ContainsFunc(d.Previewers, func(p PreviewPrincipal) bool { return p.matches(i) }) {
			envelopes = append(envelopes, d.Envelope)
		}
	}
	if len(envelopes) > 0 {
		return envelopes, i.ValidUntil, nil
	}
	if s.Administration != nil && !adminValid {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	return nil, time.Time{}, identity.ErrDenied
}

// Preview returns the preview and the reply's metadata deadline. cfg.ErrInvalid
// marks an invalid proposal, cfg.ErrLimit one beyond the preview bounds and
// cfg.ErrDenied one outside the caller's delegation envelopes.
func (s AccessPreviewer) Preview(ctx context.Context, current identities.CurrentIdentity, proposed []ProposedChange) (cfg.AccessPreview, time.Time, error) {
	var zero cfg.AccessPreview
	if ctx == nil || current == nil || s.Administration == nil && len(s.Delegations) == 0 || s.Projections == nil || s.Decoder == nil || s.Recovery == nil || s.Now == nil || !value.UUID(s.InstallationID) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrDenied
	}
	// Authority precedes decoding, so a caller without it learns nothing,
	// not even whether a proposal is well formed.
	admin, adminValid := s.administration(ctx)
	envelopes, until, err := s.authority(i, admin, adminValid)
	if err != nil {
		return zero, time.Time{}, err
	}
	if len(proposed) < 1 || len(proposed) > cfg.MaxPreviewChanges {
		return zero, time.Time{}, cfg.ErrLimit
	}
	changes := make([]cfg.AccessChange, len(proposed))
	for n, p := range proposed {
		changes[n] = cfg.AccessChange{Action: p.Action, Kind: p.Kind, UID: p.UID}
		switch {
		case p.Action == "delete":
			if len(p.Spec) != 0 {
				return zero, time.Time{}, cfg.ErrInvalid
			}
		case p.Kind == "PermissionSource":
			if changes[n].Source, err = s.Decoder.DecodePermissionSourceSpec(p.Spec); err != nil {
				return zero, time.Time{}, cfg.ErrInvalid
			}
		default:
			if changes[n].Binding, err = s.Decoder.DecodeAccessBindingSpec(p.Spec); err != nil {
				return zero, time.Time{}, cfg.ErrInvalid
			}
		}
	}
	changes, read, err := cfg.PreviewChanges(changes, envelopes)
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
	out, err := cfg.PreviewAccess(changes, snap, s.Clusters, envelopes, i.Policy, s.Now())
	if err != nil {
		return zero, time.Time{}, err
	}
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !fresh.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrDenied
	}
	if again, _, err := s.authority(fresh, admin, adminValid); err != nil || (again == nil) != (envelopes == nil) || len(again) != len(envelopes) {
		return zero, time.Time{}, identity.ErrDenied
	}
	until = identity.Earlier(until, fresh.ValidUntil)
	if ctx.Err() != nil || !s.Now().Before(until) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	return out, until, nil
}
