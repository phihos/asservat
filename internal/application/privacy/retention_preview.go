package privacy

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// RetentionPreviewCatalog reads the current policies and aggregates the
// effect of proposed policies over stored deadlines (ADR-240).
type RetentionPreviewCatalog interface {
	CurrentRetentionPolicies(context.Context) ([]value.ScopedPolicy, error)
	PreviewRetentionEffects(context.Context, []value.PolicyEffect) ([]value.PreviewRow, error)
}

// RetentionSpecDecoder applies the observed EvidenceRetentionPolicy schema
// and checks to a proposed spec of the hub (true) or a local source.
type RetentionSpecDecoder interface {
	DecodeRetentionPolicySpec([]byte, bool) (value.ScopedPolicy, error)
}

// PreviewAdministrators reads the identity settings whose administrators
// list names the installation administrators (ADR-335 D14).
type PreviewAdministrators interface {
	IdentityPolicy(context.Context, string) (identity.Policy, error)
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
// over stored deadlines. Callers are the installation administrators: retention policies are installation-wide administrator
// configuration and the browser has no mapping to their Kubernetes writers.
// It returns counts and dates only, never evidence, and writes nothing.
type RetentionPreviewer struct {
	InstallationID string
	Administrators PreviewAdministrators
	Catalog        RetentionPreviewCatalog
	Decoder        RetentionSpecDecoder
	Now            func() time.Time
}

// Preview returns the preview and the reply's metadata deadline.
// identity.ErrDenied marks a caller who is not an administrator and
// value.ErrInvalid an invalid proposal.
func (s RetentionPreviewer) Preview(ctx context.Context, current PreviewIdentity, proposed []ProposedRetentionChange) (value.RetentionPreview, time.Time, error) {
	var zero value.RetentionPreview
	if ctx == nil || current == nil || s.Administrators == nil || s.Catalog == nil || s.Decoder == nil || s.Now == nil || !authorization.UUID(s.InstallationID) {
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
	admin, err := s.Administrators.IdentityPolicy(ctx, i.Principal.Issuer)
	if errors.Is(err, identity.ErrDenied) || err == nil && !admin.Administrator(i) {
		return zero, time.Time{}, identity.ErrDenied
	}
	if err != nil || !s.Now().Before(admin.FreshUntil) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	until := identity.Earlier(i.ValidUntil, admin.FreshUntil)
	if len(proposed) < 1 {
		return zero, time.Time{}, value.ErrInvalid
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
	policies, err := s.Catalog.CurrentRetentionPolicies(ctx)
	if err != nil {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	effects, skipped, baseline, err := value.PlanPreview(changes, policies)
	if err != nil {
		return zero, time.Time{}, value.ErrInvalid
	}
	var rows []value.PreviewRow
	if len(effects) > 0 {
		if rows, err = s.Catalog.PreviewRetentionEffects(ctx, effects); err != nil {
			return zero, time.Time{}, identity.ErrUnavailable
		}
	}
	out := value.SummarizePreview(rows, skipped, baseline, s.Now().UTC())
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !fresh.Valid(s.Now()) || !admin.Administrator(fresh) {
		return zero, time.Time{}, identity.ErrDenied
	}
	until = identity.Earlier(until, fresh.ValidUntil)
	if ctx.Err() != nil || !s.Now().Before(until) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	return out, until, nil
}
