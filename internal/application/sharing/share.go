// Package sharing owns concrete evidence shares (C-17, ADR-232): creation,
// listing and revocation. Read-time recipient evaluation stays in the
// authorization domain; this package grants nothing by itself.
package sharing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
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
	// Administration names the installation administrators who may revoke
	// any share (ADR-238); nil disables administrator revocation.
	Administration Administrators
	// Policies revokes recurring policy sharing (ADR-239); nil leaves
	// revoke-all unavailable.
	Policies PolicySharingStore
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
	// Management is the optional explicit selection (ADR-238); the zero
	// value selects the default owner teams.
	Management value.ManagementRequest
}

// TransferInput is the validated transfer_share input: the complete new
// management selection (mode creator or teams).
type TransferInput struct {
	ShareID          string
	ExpectedRevision int64
	Management       value.ManagementRequest
	IdempotencyKey   string
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
	if !value.UUID(in.CaseID) || !value.UUID(in.ArtifactID) || in.Version == (artifact.Digest{}) || !identity.Text(in.Reason, 512) || !identity.Text(in.IdempotencyKey, 128) || len(in.Recipients) < 1 || len(in.Recipients) > value.ShareMaxRecipients || !in.Management.Valid() {
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
	eligible, owners := value.SelectShareManagement(i, p, route.Target, &retained, in.Management, s.Now())
	if eligible.Reason == "ManagementNotHeld" && in.Management.Mode == "teams" && s.administrator(ctx, i) {
		// The creator may share (ordinary rights, evidence:share and an own
		// owner assignment; the default selection proves it), and an
		// administrator's scoped delegation may name owner teams the creator
		// does not belong to (ADR-238).
		if creator, _ := value.ShareManagement(i, p, route.Target, &retained, s.Now()); creator.Eligible || creator.Reason == "ManagementTooBroad" {
			eligible, owners = value.AdministeredShareManagement(i.Principal.Issuer, p, route.Target, &retained, in.Management.Teams, s.Now())
		}
	}
	if err := managementError(eligible); err != nil {
		return zero, false, err
	}
	expires = identity.Earlier(expires, r.Effective.ExpiresAt).UTC().Truncate(time.Microsecond)
	if !expires.After(s.Now()) {
		return zero, false, capture.ErrDenied
	}
	slices.SortFunc(recipients, func(a, b value.ShareRecipient) int { return strings.Compare(a.Key(), b.Key()) })
	// A default selection keeps the increment 1 request digest.
	var selection *value.ManagementRequest
	if in.Management.Mode != "" {
		m := in.Management
		m.Teams = slices.Sorted(slices.Values(m.Teams))
		selection = &m
	}
	digest, err := json.Marshal(struct {
		CaseID, ArtifactID string
		Version            artifact.Digest
		Recipients         []value.ShareRecipient
		ExpiresAt          time.Time
		Reason             string
		Management         *value.ManagementRequest `json:",omitempty"`
	}{in.CaseID, in.ArtifactID, in.Version, recipients, in.ExpiresAt.UTC(), in.Reason, selection})
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

// List returns the shares the caller created or currently manages (owned:
// created shares in every phase, where Revoked and Expired need no projection
// and a target without a current projection shows Suspended rather than
// failing the list; plus unrevoked, unexpired shares of which the caller holds
// a current pinned management assignment, ADR-232 increment 4) or the shares
// received by
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
	// Filtering happens after the SQL page, so fetch the full bound and trim:
	// a suspended, denied or no longer managed row never pushes a listed one
	// off a small page. ponytail: beyond 100 candidates add keyset paging.
	var rows []value.Share
	if view == "owned" {
		rows, err = s.Store.OwnedShares(ctx, i, 100)
	} else {
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
		if len(out) == limit {
			break
		}
		created := createdBy(row, i.Principal)
		if view == "owned" && created && (!row.RevokedAt.IsZero() || !s.Now().Before(row.ExpiresAt)) {
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
		if view == "owned" && !created {
			// A team share is listed only while the caller holds one of its
			// pinned management assignments now.
			held, valid := row.ManagedBy(i, p, s.Now())
			if len(held) == 0 {
				continue
			}
			until = identity.Earlier(until, valid)
			out = append(out, View{row, row.Phase(p, s.Now())})
			continue
		}
		if view == "received" {
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

// Revoke revokes one share for its creator, a current manager (ADR-232
// increment 4: a principal holding one of the pinned management assignments
// now) or an installation administrator (ADR-238: an operator of the
// protected fleet administration). Revocation only restricts access, so the
// creator needs no current owner assignment and the administrator no evidence
// right; the operation audit records the acting principal. A share the
// caller may not revoke is NotAvailable without saying why.
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
	share, err := s.Store.Share(ctx, shareID)
	if errors.Is(err, capture.ErrDenied) {
		return zero, false, capture.ErrDenied
	}
	if err != nil || share.ID != shareID || share.RootID != s.RootID {
		return zero, false, capture.ErrUnavailable
	}
	revocation := Revocation{ShareID: shareID, Actor: i.Principal, ExpectedRevision: expected, IdempotencyKey: key}
	if !createdBy(share, i.Principal) {
		var held []artifact.AudienceAssignment
		if p, err := s.Permissions.Permissions(ctx, share.Target); err == nil {
			held, _ = share.ManagedBy(i, p, s.Now())
		}
		for _, a := range held {
			revocation.Managers = append(revocation.Managers, a.AssignmentID)
		}
		// Without current management only an administrator may revoke; an
		// unavailable projection does not block that restriction.
		if len(held) == 0 && !s.administrator(ctx, i) {
			return zero, false, capture.ErrDenied
		}
		revocation.Administrator = len(held) == 0
	}
	out, replay, err := s.Store.RevokeShare(ctx, revocation, recovery)
	if err != nil {
		return zero, false, err
	}
	if out.ID != shareID || out.RevokedAt.IsZero() || out.Revision < 2 {
		return zero, false, capture.ErrUnavailable
	}
	return out, replay, nil
}

// ListAdministered is the installation administrator's management-only
// listing of all shares (ADR-238; REQ-SHR-008 "a management-only view exposes
// opaque IDs, expiry and revoke/stop controls"): newest first, at most limit
// (≤100) rows after the opaque cursor, each with its derived phase. Rows are
// returned whole to the transport, which projects only IDs, phase, expiry,
// revision, creator and managing subjects — never recipients or evidence.
// The second result is the next page's cursor ("" on the last page).
func (s Service) ListAdministered(ctx context.Context, current identities.CurrentIdentity, cursor string, limit int) ([]View, string, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() || limit < 1 || limit > 100 {
		return nil, "", time.Time{}, capture.ErrInvalid
	}
	after, ok := decodeShareCursor(cursor)
	if !ok {
		return nil, "", time.Time{}, capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.caller(ctx, current)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	if !s.administrator(ctx, i) {
		return nil, "", time.Time{}, capture.ErrDenied
	}
	rows, err := s.Store.AdministeredShares(ctx, after, limit+1)
	if err != nil {
		return nil, "", time.Time{}, capture.ErrUnavailable
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[limit-1]
		next = encodeShareCursor(ShareCursor{CreatedAt: last.CreatedAt, ID: last.ID})
	}
	until := i.ValidUntil
	projections := map[value.Target]value.Projection{}
	out := make([]View, 0, len(rows))
	for _, row := range rows {
		if row.RootID != s.RootID {
			return nil, "", time.Time{}, capture.ErrUnavailable
		}
		until = identity.Earlier(until, row.ValidUntil)
		if !row.RevokedAt.IsZero() || !s.Now().Before(row.ExpiresAt) {
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
		// Without a current projection the managers cannot be proven: shown
		// Suspended (recovery and revocation stay reachable).
		if !projectionCurrentFor(p, row.Target, s.Now()) {
			out = append(out, View{row, value.ShareSuspended})
			continue
		}
		until = identity.Earlier(until, identity.Earlier(p.FreshUntil, p.DeniesFreshUntil))
		out = append(out, View{row, row.Phase(p, s.Now())})
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || !final.Valid(s.Now()) || final.Principal != i.Principal || ctx.Err() != nil || !s.administrator(ctx, final) {
		return nil, "", time.Time{}, capture.ErrDenied
	}
	return out, next, identity.Earlier(until, final.ValidUntil), nil
}

// The administrator cursor is an opaque keyset position:
// "s1.<created_at unix microseconds>.<share id>".
func encodeShareCursor(c ShareCursor) string {
	return "s1." + strconv.FormatInt(c.CreatedAt.UnixMicro(), 10) + "." + c.ID
}

func decodeShareCursor(s string) (ShareCursor, bool) {
	if s == "" {
		return ShareCursor{}, true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] != "s1" || !value.UUID(parts[2]) {
		return ShareCursor{}, false
	}
	micros, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || micros <= 0 {
		return ShareCursor{}, false
	}
	return ShareCursor{CreatedAt: time.UnixMicro(micros).UTC(), ID: parts[2]}, true
}

// administrator reports whether i is an operator of the current protected
// fleet administration of this installation.
func (s Service) administrator(ctx context.Context, i identity.Identity) bool {
	if s.Administration == nil {
		return false
	}
	a, err := s.Administration.FleetAdministration(ctx)
	return err == nil && a.InstallationID == s.InstallationID && a.Valid(s.Now()) && i.Valid(s.Now()) && a.Operator(i)
}

// Transfer replaces the management of one live share (ADR-238,
// REQ-SHR-008). A current manager names owner teams they hold now (or, as the
// creator, only themselves) inside the artifact's retained audience. An
// installation administrator holds the scoped delegation to assign
// management: any current evidence-owner teams covering the target inside
// that audience, also for a Suspended share (authority recovery, the explicit
// resume). Creator, recipients, artifact and expiry are unchanged, so a
// transfer never extends access; the share is Suspended as soon as no pinned
// assignment is current. The operation audit records the acting principal.
func (s Service) Transfer(ctx context.Context, current identities.CurrentIdentity, in TransferInput) (value.Share, bool, error) {
	var zero value.Share
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() {
		return zero, false, capture.ErrUnavailable
	}
	if !value.UUID(in.ShareID) || in.ExpectedRevision < 1 || !identity.Text(in.IdempotencyKey, 128) || in.Management.Mode == "" || !in.Management.Valid() {
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
	share, err := s.Store.Share(ctx, in.ShareID)
	if errors.Is(err, capture.ErrDenied) {
		return zero, false, capture.ErrDenied
	}
	if err != nil || share.ID != in.ShareID || share.RootID != s.RootID {
		return zero, false, capture.ErrUnavailable
	}
	p, err := s.Permissions.Permissions(ctx, share.Target)
	if err != nil {
		// Management can be neither proven nor refused without the
		// projection: a transient outage is not a loss of management.
		return zero, false, capture.ErrUnavailable
	}
	held, _ := share.ManagedBy(i, p, s.Now())
	// Authority precedes every further read: a current manager, otherwise
	// an installation administrator (scoped management delegation).
	administered := len(held) == 0
	if administered && !s.administrator(ctx, i) {
		return zero, false, capture.ErrDenied
	}
	if !share.RevokedAt.IsZero() || !s.Now().Before(share.ExpiresAt) {
		return zero, false, capture.ErrDenied
	}
	// Creator mode pins individual assignments, so only the creator (as a
	// current manager) may choose it: management never names another person.
	if in.Management.Mode == "creator" && (administered || !createdBy(share, i.Principal)) {
		return zero, false, ErrManagementNotHeld
	}
	// No catalog read without current ordinary target eligibility or the
	// administrator authority checked above.
	if !administered && !value.ScopeEligibility(i, p, value.ReadApproved, share.Target, s.Now()).Eligible {
		return zero, false, capture.ErrDenied
	}
	record, err := s.Catalog.ContextDownloadEvidence(ctx, share.ArtifactID)
	if err != nil {
		return zero, false, capture.ErrUnavailable
	}
	r := record.Retained
	if !r.Valid() || r.RootID != s.RootID || r.Registration.Location.ArtifactID != share.ArtifactID || r.Input.Target != share.Target || !identity.Fresh(record.ObservedAt, record.ValidUntil, s.Now(), 5*time.Second) {
		return zero, false, capture.ErrUnavailable
	}
	retained := value.Retained{ArtifactID: share.ArtifactID, Target: share.Target, DataClass: "metadata", ExpiresAt: r.Effective.ExpiresAt, Audience: slices.Clone(record.Audience)}
	var eligible value.Result
	var owners []artifact.AudienceAssignment
	if !administered {
		eligible, owners = value.SelectShareManagement(i, p, share.Target, &retained, in.Management, s.Now())
	}
	if administered || eligible.Reason == "ManagementNotHeld" && in.Management.Mode == "teams" && s.administrator(ctx, i) {
		eligible, owners = value.AdministeredShareManagement(i.Principal.Issuer, p, share.Target, &retained, in.Management.Teams, s.Now())
	}
	if err := managementError(eligible); err != nil {
		return zero, false, err
	}
	m := in.Management
	m.Teams = slices.Sorted(slices.Values(m.Teams))
	digest, err := json.Marshal(struct {
		ShareID    string
		Management value.ManagementRequest
	}{in.ShareID, m})
	if err != nil {
		return zero, false, capture.ErrUnavailable
	}
	t := Transfer{ShareID: in.ShareID, Actor: i.Principal, Administrator: administered, Management: owners, ExpectedRevision: in.ExpectedRevision, IdempotencyKey: in.IdempotencyKey, RequestDigest: sha256.Sum256(digest)}
	for _, a := range held {
		t.Managers = append(t.Managers, a.AssignmentID)
	}
	// The final identity check precedes the write, as in Create: once the
	// transfer commits, a definite refusal would misreport a change that
	// happened.
	final, err := current.ResolveIdentity(ctx)
	if err != nil || !final.Valid(s.Now()) || final.Principal != i.Principal || ctx.Err() != nil {
		return zero, false, capture.ErrDenied
	}
	out, replay, err := s.Store.TransferShare(ctx, t, recovery)
	if err != nil {
		return zero, false, err
	}
	if out.ID != in.ShareID || !out.RevokedAt.IsZero() || out.Revision < 2 || out.Creator != share.Creator || !out.ExpiresAt.Equal(share.ExpiresAt) || out.ArtifactID != share.ArtifactID {
		return zero, false, capture.ErrUnavailable
	}
	return out, replay, nil
}

// managementError maps a refused management selection.
func managementError(r value.Result) error {
	switch {
	case r.Eligible:
		return nil
	case r.Reason == "ManagementTooBroad":
		return ErrManagementTooBroad
	case r.Reason == "ManagementNotHeld":
		return ErrManagementNotHeld
	}
	return capture.ErrDenied
}

// ErrManagementTooBroad refuses a share whose creator holds more than
// value.ShareMaxManagers owner-team assignments: management is never
// silently truncated (REQ-SHR-008).
var ErrManagementTooBroad = errors.New("share management exceeds eight owner assignments")

// ErrManagementNotHeld refuses an explicit management selection naming a
// team (or individual assignment) the caller does not hold now for the
// artifact (ADR-238): management is never assigned to others.
var ErrManagementNotHeld = errors.New("share management names an assignment the caller does not hold")

func createdBy(s value.Share, p identity.Principal) bool {
	return s.Creator.Issuer == p.Issuer && s.Creator.Subject == p.Subject
}

// projectionCurrentFor exposes the domain's projection precondition for an
// identity-free phase derivation.
func projectionCurrentFor(p value.Projection, t value.Target, now time.Time) bool {
	return p.Target == t && p.DeniesComplete && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 60*time.Second) && identity.Fresh(p.DeniesObservedAt, p.DeniesFreshUntil, now, value.PermissionObservationInterval)
}

// PolicyRevokeResult is the outcome of revoking one acceptance's recurring
// sharing (ADR-239).
type PolicyRevokeResult struct {
	AcceptanceID string
	Revoked      int
	Replay       bool
}

// RevokePolicySharing revokes every share of one policy acceptance's
// recurring sharing and stops its future sharing (ADR-239, REQ-SHR-007), for
// the instruction's creator, a current manager (a principal holding one of
// the pinned owner-team assignments now on the policy's workload) or an
// installation administrator (ADR-238). Revocation only restricts access.
// Expected is the sharing's revision: 1 before revocation; the same key after
// success is a replay. An acceptance without sharing, or one the caller may
// not revoke, is NotAvailable.
func (s Service) RevokePolicySharing(ctx context.Context, current identities.CurrentIdentity, acceptanceID string, expected int64, key string) (PolicyRevokeResult, error) {
	var zero PolicyRevokeResult
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() || s.Policies == nil {
		return zero, capture.ErrUnavailable
	}
	if !value.UUID(acceptanceID) || expected < 1 || !identity.Text(key, 128) {
		return zero, capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.caller(ctx, current)
	if err != nil {
		return zero, err
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, err
	}
	sharing, err := s.Policies.PolicySharing(ctx, acceptanceID)
	if errors.Is(err, capture.ErrDenied) {
		return zero, capture.ErrDenied
	}
	if err != nil || sharing.AcceptanceID != acceptanceID {
		return zero, capture.ErrUnavailable
	}
	revocation := PolicyRevocation{AcceptanceID: acceptanceID, Actor: i.Principal, ExpectedRevision: expected, IdempotencyKey: key}
	in := sharing.Instruction
	if in.Creator.Issuer != i.Principal.Issuer || in.Creator.Subject != i.Principal.Subject {
		var held []artifact.AudienceAssignment
		if p, err := s.Permissions.Permissions(ctx, sharing.Target); err == nil {
			held, _ = value.PolicySharingManagedBy(in.Creator, in.Management, sharing.Target, i, p, s.Now())
		}
		if len(held) == 0 && !s.administrator(ctx, i) {
			return zero, capture.ErrDenied
		}
		revocation.Administrator = len(held) == 0
		for _, a := range held {
			revocation.Managers = append(revocation.Managers, a.AssignmentID)
		}
	}
	revoked, replay, err := s.Policies.RevokePolicySharing(ctx, revocation, recovery)
	if err != nil {
		return zero, err
	}
	return PolicyRevokeResult{AcceptanceID: acceptanceID, Revoked: revoked, Replay: replay}, nil
}
