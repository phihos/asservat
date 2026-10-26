// Package sharing owns concrete evidence shares (C-17, ADR-232): creation,
// listing and revocation. Read-time recipient evaluation stays in the
// authorization domain; this package grants nothing by itself.
package sharing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

// CaseRoutes are the bounded published case locators; they carry no
// evidence and are read before eligibility exactly as get_case reads them.
type CaseRoutes interface {
	ResolveContextCase(context.Context, catalog.CaseRouteQuery) (catalog.ContextCaseRoutes, error)
}
type RecoveryReader interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

// Service implements create_share, list_shares and revoke_share
// (ADR-232). It grants nothing itself: reads re-check every share through
// value.EvaluateShare against current permissions.
type Service struct {
	RootID, InstallationID string
	Routes                 CaseRoutes
	Permissions            authapp.ProjectionReader
	Catalog                authapp.ContextDownloadCatalog
	Store                  Store
	Recovery               RecoveryReader
	NewID                  func() string
	Now                    func() time.Time
}

// CreateInput is the validated create_share input. A zero ExpiresAt
// selects value.ShareDefaultLifetime.
type CreateInput struct {
	CaseID, ArtifactID string
	Version            artifact.Digest
	Recipients         []value.ShareRecipient
	ExpiresAt          time.Time
	Reason             string
	IdempotencyKey     string
}

// View is one listed share with its phase derived now.
type View struct {
	Share value.Share
	Phase value.SharePhase
}

func (s Service) ready() bool {
	return s.Routes != nil && s.Permissions != nil && s.Catalog != nil && s.Store != nil && s.Recovery != nil && s.NewID != nil && s.Now != nil && value.UUID(s.RootID) && value.UUID(s.InstallationID)
}

// identity resolves the caller: a human with evidence:read and evidence:share.
func (s Service) caller(ctx context.Context, current identities.CurrentIdentity) (identity.Identity, error) {
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || i.Principal.Kind != identity.Human || !slices.Contains(i.Scopes, "evidence:read") || !slices.Contains(i.Scopes, value.ShareScope) {
		return identity.Identity{}, capture.ErrDenied
	}
	return i, nil
}

func (s Service) recovery(ctx context.Context) (artifact.RecoveryProof, error) {
	r, err := s.Recovery.RecoveryState(ctx)
	if err != nil || r.InstallationID != s.InstallationID || !r.Valid(s.Now()) {
		return artifact.RecoveryProof{}, capture.ErrUnavailable
	}
	return r, nil
}

// Create shares one published artifact that the caller currently owns. The
// target comes from the case route; ordinary target eligibility precedes the
// catalog read; the share pins the caller's contributing evidence-owner
// assignments and never outlives the artifact's effective access deadline.
func (s Service) Create(ctx context.Context, current identities.CurrentIdentity, in CreateInput) (value.Share, bool, error) {
	var zero value.Share
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() {
		return zero, false, capture.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.caller(ctx, current)
	if err != nil {
		return zero, false, err
	}
	now := s.Now()
	if !value.UUID(in.CaseID) || !value.UUID(in.ArtifactID) || in.Version == (artifact.Digest{}) || !identity.Text(in.Reason, 512) || !identity.Text(in.IdempotencyKey, 128) || len(in.Recipients) < 1 || len(in.Recipients) > value.ShareMaxRecipients {
		return zero, false, capture.ErrInvalid
	}
	recipients := slices.Clone(in.Recipients)
	seen := map[string]bool{}
	for _, r := range recipients {
		// Recipients are stable IDs of the caller's own (configured) issuer.
		if !r.Valid() || r.Issuer != i.Principal.Issuer || seen[r.Key()] {
			return zero, false, capture.ErrInvalid
		}
		seen[r.Key()] = true
	}
	expires := in.ExpiresAt
	if expires.IsZero() {
		expires = now.Add(value.ShareDefaultLifetime)
	}
	if !expires.After(now) || expires.After(now.Add(value.ShareMaxLifetime)) {
		return zero, false, capture.ErrInvalid
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	routes, err := s.Routes.ResolveContextCase(ctx, catalog.CaseRouteQuery{RootID: s.RootID, CaseID: in.CaseID, Identity: i, Recovery: recovery})
	if err != nil || routes.CaseID != in.CaseID || !routes.Valid(s.Now()) {
		return zero, false, capture.ErrDenied
	}
	var route *catalog.ContextCaseRoute
	for _, r := range routes.Routes {
		if r.ArtifactID == in.ArtifactID {
			route = &r
		}
	}
	if route == nil {
		return zero, false, capture.ErrDenied
	}
	p, err := s.Permissions.Permissions(ctx, route.Target)
	if err != nil {
		return zero, false, capture.ErrUnavailable
	}
	// No catalog read without current ordinary target eligibility.
	if !value.ScopeEligibility(i, p, value.ReadApproved, route.Target, s.Now()).Eligible {
		return zero, false, capture.ErrDenied
	}
	record, err := s.Catalog.ContextDownloadEvidence(ctx, route.ArtifactID)
	if err != nil {
		return zero, false, capture.ErrUnavailable
	}
	r := record.Retained
	if !r.Valid() || r.RootID != s.RootID || r.Registration.Location.ArtifactID != route.ArtifactID || r.Input.Target != route.Target || record.CaptureID != route.CaptureID || record.Version == (artifact.Digest{}) || !identity.Fresh(record.ObservedAt, record.ValidUntil, s.Now(), 5*time.Second) {
		return zero, false, capture.ErrUnavailable
	}
	if record.Version != in.Version {
		// A share is a concrete snapshot of the version the creator reviewed.
		return zero, false, capture.ErrChanged
	}
	retained := value.Retained{ArtifactID: route.ArtifactID, Target: route.Target, DataClass: "metadata", ExpiresAt: r.Effective.ExpiresAt, Audience: slices.Clone(record.Audience)}
	eligible, owners := value.ShareManagement(i, p, route.Target, &retained, s.Now())
	if !eligible.Eligible {
		return zero, false, capture.ErrDenied
	}
	expires = identity.Earlier(expires, r.Effective.ExpiresAt).UTC().Truncate(time.Microsecond)
	if !expires.After(s.Now()) {
		return zero, false, capture.ErrDenied
	}
	slices.SortFunc(recipients, func(a, b value.ShareRecipient) int { return strings.Compare(a.Key(), b.Key()) })
	digest, err := json.Marshal(struct {
		CaseID, ArtifactID string
		Version            artifact.Digest
		Recipients         []value.ShareRecipient
		ExpiresAt          time.Time
		Reason             string
	}{in.CaseID, in.ArtifactID, in.Version, recipients, in.ExpiresAt.UTC(), in.Reason})
	if err != nil {
		return zero, false, capture.ErrUnavailable
	}
	share := value.Share{ID: s.NewID(), RootID: s.RootID, ArtifactID: route.ArtifactID, CaseID: in.CaseID, Target: route.Target, Version: record.Version,
		Creator: i.Principal, Management: owners, Recipients: recipients, ExpiresAt: expires, Revision: 1}
	out, replay, err := s.Store.CreateShare(ctx, Request{Share: share, IdempotencyKey: in.IdempotencyKey, RequestDigest: sha256.Sum256(digest)}, recovery)
	if err != nil {
		return zero, false, err
	}
	if out.ArtifactID != share.ArtifactID || out.CaseID != share.CaseID || out.Creator.Subject != i.Principal.Subject || out.Creator.Issuer != i.Principal.Issuer {
		return zero, false, capture.ErrUnavailable
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || !final.Valid(s.Now()) || final.Principal != i.Principal || ctx.Err() != nil {
		return zero, false, capture.ErrDenied
	}
	return out, replay, nil
}

// List returns the caller's own shares (owned: every phase; Revoked and
// Expired need no projection, and a target without a current projection
// shows Suspended rather than failing the list) or the shares received by
// the caller (received: unrevoked, unexpired shares whose share-level checks
// pass, never another recipient's or a suspended/denied one). Received rows
// are candidates: the artifact's retained audience, retention end and data
// class are checked only by the read itself (get_case, inspection, download).
func (s Service) List(ctx context.Context, current identities.CurrentIdentity, view string, limit int) ([]View, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() || limit < 1 || limit > 100 || view != "owned" && view != "received" {
		return nil, time.Time{}, capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return nil, time.Time{}, capture.ErrDenied
	}
	if view == "owned" && (i.Principal.Kind != identity.Human || !slices.Contains(i.Scopes, value.ShareScope)) {
		return nil, time.Time{}, capture.ErrDenied
	}
	var rows []value.Share
	if view == "owned" {
		rows, err = s.Store.OwnedShares(ctx, i.Principal, limit)
	} else {
		// Filtering happens after the SQL page, so fetch the full bound and
		// trim: a suspended or denied row never pushes a readable one off a
		// small page. ponytail: beyond 100 candidates add keyset paging.
		rows, err = s.Store.ReceivedShares(ctx, i, 100)
	}
	if err != nil {
		return nil, time.Time{}, capture.ErrUnavailable
	}
	until := i.ValidUntil
	projections := map[value.Target]value.Projection{}
	out := make([]View, 0, len(rows))
	for _, row := range rows {
		if row.RootID != s.RootID {
			return nil, time.Time{}, capture.ErrUnavailable
		}
		if view == "owned" && (row.Creator.Issuer != i.Principal.Issuer || row.Creator.Subject != i.Principal.Subject) {
			return nil, time.Time{}, capture.ErrUnavailable
		}
		if view == "owned" && (!row.RevokedAt.IsZero() || !s.Now().Before(row.ExpiresAt)) {
			// Final phases do not depend on permissions.
			out = append(out, View{row, row.Phase(value.Projection{}, s.Now())})
			continue
		}
		p, ok := projections[row.Target]
		if !ok {
			if p, err = s.Permissions.Permissions(ctx, row.Target); err != nil {
				p = value.Projection{}
			}
			projections[row.Target] = p
		}
		until = identity.Earlier(until, row.ValidUntil)
		if view == "received" {
			if len(out) == limit {
				break
			}
			r := value.EvaluateShare(i, p, row.Target, nil, row, s.Now())
			if !r.Eligible {
				continue
			}
			until = identity.Earlier(until, r.ValidUntil)
			out = append(out, View{row, value.ShareActive})
			continue
		}
		// Without a current projection the managers cannot be proven, so the
		// row shows Suspended instead of failing the whole list (revocation
		// must stay reachable).
		if !projectionCurrentFor(p, row.Target, s.Now()) {
			out = append(out, View{row, value.ShareSuspended})
			continue
		}
		until = identity.Earlier(until, identity.Earlier(p.FreshUntil, p.DeniesFreshUntil))
		out = append(out, View{row, row.Phase(p, s.Now())})
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || !final.Valid(s.Now()) || final.Principal != i.Principal || ctx.Err() != nil {
		return nil, time.Time{}, capture.ErrDenied
	}
	return out, identity.Earlier(until, final.ValidUntil), nil
}

// Revoke revokes one of the caller's own shares (increment 1: the creator
// only). Revocation only restricts access, so it needs no current owner
// assignment; another principal's share is NotAvailable.
func (s Service) Revoke(ctx context.Context, current identities.CurrentIdentity, shareID string, expected int64, key string) (value.Share, bool, error) {
	var zero value.Share
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() {
		return zero, false, capture.ErrUnavailable
	}
	if !value.UUID(shareID) || expected < 1 || !identity.Text(key, 128) {
		return zero, false, capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.caller(ctx, current)
	if err != nil {
		return zero, false, err
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	out, replay, err := s.Store.RevokeShare(ctx, Revocation{ShareID: shareID, Creator: i.Principal, ExpectedRevision: expected, IdempotencyKey: key}, recovery)
	if err != nil {
		return zero, false, err
	}
	if out.ID != shareID || out.RevokedAt.IsZero() || out.Revision != 2 {
		return zero, false, capture.ErrUnavailable
	}
	return out, replay, nil
}

// projectionCurrentFor exposes the domain's projection precondition for an
// identity-free phase derivation.
func projectionCurrentFor(p value.Projection, t value.Target, now time.Time) bool {
	return p.Target == t && p.DeniesComplete && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 60*time.Second) && identity.Fresh(p.DeniesObservedAt, p.DeniesFreshUntil, now, value.PermissionObservationInterval)
}
