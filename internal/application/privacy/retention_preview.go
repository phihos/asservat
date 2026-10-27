package privacy

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// RetentionPreviewCatalog reads the sources and the bounded retained catalog
// that a retention impact preview evaluates (ADR-240).
type RetentionPreviewCatalog interface {
	RetentionPreviewCatalog(context.Context, int) (value.PreviewCatalog, error)
}

// RetentionSpecDecoder applies the observed EvidenceRetentionPolicy schema
// and checks to a proposed spec of the hub (true) or a local source.
type RetentionSpecDecoder interface {
	DecodeRetentionPolicySpec([]byte, bool) (value.ScopedPolicy, error)
}

// PreviewAdministration is the protected fleet administration source that
// names the installation's operators.
type PreviewAdministration interface {
	FleetAdministration(context.Context) (fleet.Administration, error)
}

type PreviewRecovery interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

// PreviewIdentity resolves the current caller of one request.
type PreviewIdentity interface {
	ResolveIdentity(context.Context) (identity.Identity, error)
}

// ProposedRetentionChange is one administrator-supplied change; Spec is the
// raw EvidenceRetentionPolicy spec for create and update, SourceClusterID is
// empty for the hub control namespace.
type ProposedRetentionChange struct {
	Action, SourceClusterID, UID string
	Spec                         []byte
}

// RetentionPreviewer answers preview_retention_change (ADR-240): how a
// proposed EvidenceRetentionPolicy change would shorten the effective
// deadlines of retained evidence, computed by the catch-up's own functions
// over the current catalog. Callers are the installation's current fleet
// operators: retention policies are installation-wide administrator
// configuration and the browser has no mapping to their Kubernetes writers.
// It returns counts and dates only, never evidence, and writes nothing.
type RetentionPreviewer struct {
	InstallationID string
	Administration PreviewAdministration
	Catalog        RetentionPreviewCatalog
	Decoder        RetentionSpecDecoder
	Recovery       PreviewRecovery
	Now            func() time.Time
}

// Preview returns the preview and the reply's metadata deadline.
// identity.ErrDenied marks a caller who is not a fleet operator,
// value.ErrInvalid an invalid proposal and value.ErrPreviewLimit one beyond
// the preview bounds.
func (s RetentionPreviewer) Preview(ctx context.Context, current PreviewIdentity, proposed []ProposedRetentionChange) (value.RetentionPreview, time.Time, error) {
	var zero value.RetentionPreview
	if ctx == nil || current == nil || s.Administration == nil || s.Catalog == nil || s.Decoder == nil || s.Recovery == nil || s.Now == nil || !authorization.UUID(s.InstallationID) {
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
	admin, err := s.Administration.FleetAdministration(ctx)
	if err != nil || !admin.Valid(s.Now()) || admin.InstallationID != s.InstallationID {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	if !admin.Operator(i) {
		return zero, time.Time{}, identity.ErrDenied
	}
	until := identity.Earlier(i.ValidUntil, admin.FreshUntil)
	if len(proposed) < 1 || len(proposed) > value.MaxRetentionPreviewChanges {
		return zero, time.Time{}, value.ErrPreviewLimit
	}
	changes := make([]value.RetentionChange, len(proposed))
	for n, p := range proposed {
		changes[n] = value.RetentionChange{Action: p.Action, SourceClusterID: p.SourceClusterID, UID: p.UID}
		if p.Action == "delete" {
			if len(p.Spec) != 0 {
				return zero, time.Time{}, value.ErrInvalid
			}
			continue
		}
		if changes[n].Policy, err = s.Decoder.DecodeRetentionPolicySpec(p.Spec, p.SourceClusterID == ""); err != nil {
			return zero, time.Time{}, value.ErrInvalid
		}
	}
	// Restored databases carry stale effective dates; refuse during recovery.
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	catalog, err := s.Catalog.RetentionPreviewCatalog(ctx, value.MaxRetentionPreviewArtifacts)
	if err != nil {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	out, err := value.PreviewRetention(changes, catalog, s.Now().UTC())
	if errors.Is(err, value.ErrInvalid) || errors.Is(err, value.ErrPreviewLimit) {
		return zero, time.Time{}, err
	}
	if err != nil {
		return zero, time.Time{}, identity.ErrUnavailable
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
