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

// Service implements create_share, list_shares and revoke_share
// (ADR-232). It grants nothing itself: reads re-check every share through
// value.EvaluateShare against current permissions.
type Service struct {
	RootID, InstallationID string
	Routes                 CaseRoutes
	Permissions            authapp.ProjectionReader
	Catalog                authapp.ContextDownloadCatalog
	Store                  Store
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
// selects the artifact's access end.
type CreateInput struct {
	// OperationID is the current server-owned paid audit operation. It is
	// private plumbing, never part of the stable business request digest.
	OperationID        string `json:"-"`
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
	OperationID      string `json:"-"`
	ShareID          string
	ExpectedRevision int64
	Management       value.ManagementRequest
	IdempotencyKey   string
}

type RevokeInput struct {
	OperationID      string `json:"-"`
	ShareID          string
	ExpectedRevision int64
	IdempotencyKey   string
}

type PolicyRevokeInput struct {
	OperationID      string `json:"-"`
	AcceptanceID     string
	ExpectedRevision int64
	IdempotencyKey   string
}

// View is one listed share with its phase derived now.
type View struct {
	Share value.Share
	Phase value.SharePhase
}

func (s Service) ready() bool {
	return s.Routes != nil && s.Permissions != nil && s.Catalog != nil && s.Store != nil && s.NewID != nil && s.Now != nil && value.UUID(s.RootID) && value.UUID(s.InstallationID)
}

// identity resolves the caller: a human with evidence:read and evidence:share.
func (s Service) caller(ctx context.Context, current identities.CurrentIdentity) (identity.Identity, error) {
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || i.Principal.Kind != identity.Human || !slices.Contains(i.Scopes, "evidence:read") || !slices.Contains(i.Scopes, value.ShareScope) {
		return identity.Identity{}, capture.ErrDenied
	}
	return i, nil
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
	if !value.UUID(in.OperationID) {
		return zero, false, capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.caller(ctx, current)
	if err != nil {
		return zero, false, err
	}
	now := s.Now()
	if !value.UUID(in.CaseID) || !value.UUID(in.ArtifactID) || in.Version == (artifact.Digest{}) || !identity.Text(in.Reason, 512) || !identity.Text(in.IdempotencyKey, 128) || len(in.Recipients) < 1 || !in.Management.Valid() {
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
	if !in.ExpiresAt.IsZero() && !in.ExpiresAt.After(now) {
		return zero, false, capture.ErrInvalid
	}
	routes, err := s.Routes.ResolveContextCase(ctx, catalog.CaseRouteQuery{RootID: s.RootID, CaseID: in.CaseID, Identity: i})
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
	// ADR-279: raw output is never shared until the S-06 raw-share approval
	// exists; it is disclosed only through its approved grant's child.
	if record.DataClass != "metadata" {
		return zero, false, capture.ErrDenied
	}
	retained := value.Retained{ArtifactID: route.ArtifactID, Target: route.Target, DataClass: "metadata", ExpiresAt: r.Effective.ExpiresAt, Audience: slices.Clone(record.Audience)}
	eligible, owners := value.SelectShareManagement(i, p, route.Target, &retained, in.Management, s.Now())
	if eligible.Reason == "ManagementNotHeld" && in.Management.Mode == "teams" && s.administrator(ctx, i) {
		// The creator may share (ordinary rights, evidence:share and an own
		// owner assignment; the default selection proves it), and an
		// administrator's scoped delegation may name owner teams the creator
		// does not belong to (ADR-238).
		if creator, _ := value.ShareManagement(i, p, route.Target, &retained, s.Now()); creator.Eligible {
			eligible, owners = value.AdministeredShareManagement(i.Principal.Issuer, p, route.Target, &retained, in.Management.Teams, s.Now())
		}
	}
	if err := managementError(eligible); err != nil {
		return zero, false, err
	}
	// A share lasts until the artifact's access ends unless the creator
	// names an earlier end (ADR-335 D7).
	expires := r.Effective.ExpiresAt
	if !in.ExpiresAt.IsZero() {
		expires = identity.Earlier(in.ExpiresAt, expires)
	}
	expires = expires.UTC().Truncate(time.Microsecond)
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
	out, replay, err := s.Store.CreateShare(ctx, Request{OperationID: in.OperationID, Share: share, IdempotencyKey: in.IdempotencyKey, RequestDigest: sha256.Sum256(digest)})
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
// created shares in every phase plus unrevoked, unexpired shares of a
// managing group the caller is in) or the shares received by the caller
// (received: unrevoked, unexpired shares whose share-level checks pass).
// Received rows are candidates: the artifact's retained audience, retention
// end and data class are checked only by the read itself.
func (s Service) List(ctx context.Context, current identities.CurrentIdentity, view, cursor string, limit int) ([]View, string, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() || limit < 1 || limit > 100 || view != "owned" && view != "received" {
		return nil, "", time.Time{}, capture.ErrInvalid
	}
	after, ok := decodeShareCursor(cursor)
	if !ok {
		return nil, "", time.Time{}, capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return nil, "", time.Time{}, capture.ErrDenied
	}
	if view == "owned" && (i.Principal.Kind != identity.Human || !slices.Contains(i.Scopes, value.ShareScope)) {
		return nil, "", time.Time{}, capture.ErrDenied
	}
	// Filtering happens after each SQL page, so read keyset pages until the
	// caller's page is full or the candidates end; the cursor is the last
	// candidate examined, so no row is skipped or listed twice.
	until := i.ValidUntil
	projections := map[value.Target]value.Projection{}
	projection := func(t value.Target) value.Projection {
		p, ok := projections[t]
		if !ok {
			if p, err = s.Permissions.Permissions(ctx, t); err != nil {
				p = value.Projection{}
			}
			projections[t] = p
		}
		return p
	}
	out := make([]View, 0, limit)
	next := ""
	for {
		var rows []value.Share
		if view == "owned" {
			rows, err = s.Store.OwnedShares(ctx, i, after, 100)
		} else {
			rows, err = s.Store.ReceivedShares(ctx, i, after, 100)
		}
		if err != nil {
			return nil, "", time.Time{}, capture.ErrUnavailable
		}
		for _, row := range rows {
			if row.RootID != s.RootID {
				return nil, "", time.Time{}, capture.ErrUnavailable
			}
			if len(out) == limit {
				next = encodeShareCursor(after)
				break
			}
			after = ShareCursor{CreatedAt: row.CreatedAt, ID: row.ID}
			until = identity.Earlier(until, row.ValidUntil)
			if view == "owned" {
				// A team share is listed only while the caller manages it now.
				if !createdBy(row, i.Principal) {
					held, _ := row.ManagedBy(i, s.Now())
					if len(held) == 0 {
						continue
					}
					denied, current := value.ManagerDenied(projection(row.Target), row.Target, i, s.Now())
					if !current {
						return nil, "", time.Time{}, capture.ErrUnavailable
					}
					if denied {
						continue
					}
				}
				out = append(out, View{row, row.Phase(s.Now())})
				continue
			}
			r := value.EvaluateShare(i, projection(row.Target), row.Target, nil, row, s.Now())
			if !r.Eligible {
				continue
			}
			until = identity.Earlier(until, r.ValidUntil)
			out = append(out, View{row, value.ShareActive})
		}
		if next != "" || len(rows) < 100 {
			break
		}
		if len(out) == limit {
			next = encodeShareCursor(after)
			break
		}
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || !final.Valid(s.Now()) || final.Principal != i.Principal || ctx.Err() != nil {
		return nil, "", time.Time{}, capture.ErrDenied
	}
	return out, next, identity.Earlier(until, final.ValidUntil), nil
}

// Revoke revokes one share for its creator, a current manager (a member of
// a managing group) or an installation administrator (ADR-238: identity.administrators). Revocation only restricts access, so the
// creator needs no current owner assignment and the administrator no evidence
// right; the operation audit records the acting principal. A share the
// caller may not revoke is NotAvailable without saying why.
func (s Service) Revoke(ctx context.Context, current identities.CurrentIdentity, in RevokeInput) (value.Share, bool, error) {
	shareID, expected, key := in.ShareID, in.ExpectedRevision, in.IdempotencyKey
	var zero value.Share
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() {
		return zero, false, capture.ErrUnavailable
	}
	if !value.UUID(in.OperationID) || !value.UUID(shareID) || expected < 1 || !identity.Text(key, 128) {
		return zero, false, capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.caller(ctx, current)
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
	revocation := Revocation{OperationID: in.OperationID, ShareID: shareID, Actor: i.Principal, ExpectedRevision: expected, IdempotencyKey: key}
	if !createdBy(share, i.Principal) {
		held, _ := share.ManagedBy(i, s.Now())
		if held, err = s.managedHeld(ctx, held, share.Target, i); err != nil {
			return zero, false, err
		}
		for _, a := range held {
			revocation.Managers = append(revocation.Managers, a.AssignmentID)
		}
		// Without current management only an administrator may revoke.
		if len(held) == 0 && !s.administrator(ctx, i) {
			return zero, false, capture.ErrDenied
		}
		revocation.Administrator = len(held) == 0
	}
	out, replay, err := s.Store.RevokeShare(ctx, revocation)
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
	out := make([]View, 0, len(rows))
	for _, row := range rows {
		if row.RootID != s.RootID {
			return nil, "", time.Time{}, capture.ErrUnavailable
		}
		until = identity.Earlier(until, row.ValidUntil)
		out = append(out, View{row, row.Phase(s.Now())})
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

// administrator reports whether i is a current installation administrator.
func (s Service) administrator(ctx context.Context, i identity.Identity) bool {
	if s.Administration == nil {
		return false
	}
	p, err := s.Administration.IdentityPolicy(ctx, i.Principal.Issuer)
	return err == nil && s.Now().Before(p.FreshUntil) && i.Valid(s.Now()) && p.Administrator(i)
}

// Transfer replaces the management of one live share (ADR-238,
// REQ-SHR-008). A current manager names owner teams they hold now (or, as the
// creator, only themselves) inside the artifact's retained audience. An
// installation administrator may assign any group with sharing authority
// inside that audience. Creator, recipients, artifact and expiry are
// unchanged, so a transfer never extends access. The operation audit records
// the acting principal.
func (s Service) Transfer(ctx context.Context, current identities.CurrentIdentity, in TransferInput) (value.Share, bool, error) {
	var zero value.Share
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() {
		return zero, false, capture.ErrUnavailable
	}
	if !value.UUID(in.OperationID) || !value.UUID(in.ShareID) || in.ExpectedRevision < 1 || !identity.Text(in.IdempotencyKey, 128) || in.Management.Mode == "" || !in.Management.Valid() {
		return zero, false, capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.caller(ctx, current)
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
	held, _ := share.ManagedBy(i, s.Now())
	if held, err = s.managedHeld(ctx, held, share.Target, i); err != nil {
		return zero, false, err
	}
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
	p, err := s.Permissions.Permissions(ctx, share.Target)
	if err != nil {
		return zero, false, capture.ErrUnavailable
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
	if !r.Valid() || r.RootID != s.RootID || r.Registration.Location.ArtifactID != share.ArtifactID || r.Input.Target != share.Target || record.DataClass != "metadata" || !identity.Fresh(record.ObservedAt, record.ValidUntil, s.Now(), 5*time.Second) {
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
	t := Transfer{OperationID: in.OperationID, ShareID: in.ShareID, Actor: i.Principal, Administrator: administered, Management: owners, ExpectedRevision: in.ExpectedRevision, IdempotencyKey: in.IdempotencyKey, RequestDigest: sha256.Sum256(digest)}
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
	out, replay, err := s.Store.TransferShare(ctx, t)
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
	case r.Reason == "ManagementNotHeld":
		return ErrManagementNotHeld
	}
	return capture.ErrDenied
}

// ErrManagementNotHeld refuses an explicit management selection naming a
// team (or individual assignment) the caller does not hold now for the
// artifact (ADR-238): management is never assigned to others.
var ErrManagementNotHeld = errors.New("share management names an assignment the caller does not hold")

// ErrRetentionCapacity refuses a new share whose expiry cannot fit its
// original paid operation's backing. It never shortens an accepted expiry.
var ErrRetentionCapacity = errors.New("share expiry exceeds original retained metadata backing")

func createdBy(s value.Share, p identity.Principal) bool {
	return s.Creator.Issuer == p.Issuer && s.Creator.Subject == p.Subject
}

// PolicyRevokeResult is the outcome of revoking one acceptance's recurring
// sharing (ADR-239).
type PolicyRevokeResult struct {
	AcceptanceID string
	Revoked      int
	Replay       bool
}

// RevokePolicySharing revokes every share of one policy acceptance's
// recurring sharing and stops its future sharing (ADR-239, REQ-SHR-007).
// Expected is the sharing's revision (1, or 2 after a Stop); the same key
// after success is a replay.
func (s Service) RevokePolicySharing(ctx context.Context, current identities.CurrentIdentity, in PolicyRevokeInput) (PolicyRevokeResult, error) {
	var out PolicyRevokeResult
	err := s.changePolicySharing(ctx, current, in, func(ctx context.Context, r PolicyRevocation) error {
		revoked, replay, err := s.Policies.RevokePolicySharing(ctx, r)
		out = PolicyRevokeResult{AcceptanceID: in.AcceptanceID, Revoked: revoked, Replay: replay}
		return err
	})
	if err != nil {
		return PolicyRevokeResult{}, err
	}
	return out, nil
}

// StopPolicySharing stops future sharing of one policy acceptance
// (REQ-SHR-007): no further capture claims a slot; captures that already
// claimed one still publish their shares before notAfter; existing shares
// stay until they expire or are revoked. Expected must be revision 1.
func (s Service) StopPolicySharing(ctx context.Context, current identities.CurrentIdentity, in PolicyRevokeInput) (PolicyRevokeResult, error) {
	var out PolicyRevokeResult
	err := s.changePolicySharing(ctx, current, in, func(ctx context.Context, r PolicyRevocation) error {
		replay, err := s.Policies.StopPolicySharing(ctx, r)
		out = PolicyRevokeResult{AcceptanceID: in.AcceptanceID, Replay: replay}
		return err
	})
	if err != nil {
		return PolicyRevokeResult{}, err
	}
	return out, nil
}

// changePolicySharing authorizes a Stop or revoke-all for the instruction's
// creator, a current manager (a member of a managing group) or an installation
// administrator (ADR-238). Both only restrict access. An acceptance without
// sharing, or one the caller may not change, is NotAvailable.
func (s Service) changePolicySharing(ctx context.Context, current identities.CurrentIdentity, in PolicyRevokeInput, apply func(context.Context, PolicyRevocation) error) error {
	acceptanceID, expected, key := in.AcceptanceID, in.ExpectedRevision, in.IdempotencyKey
	if ctx == nil || ctx.Err() != nil || current == nil || !s.ready() || s.Policies == nil {
		return capture.ErrUnavailable
	}
	if !value.UUID(in.OperationID) || !value.UUID(acceptanceID) || expected < 1 || !identity.Text(key, 128) {
		return capture.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.caller(ctx, current)
	if err != nil {
		return err
	}
	sharing, err := s.Policies.PolicySharing(ctx, acceptanceID)
	if errors.Is(err, capture.ErrDenied) {
		return capture.ErrDenied
	}
	if err != nil || sharing.AcceptanceID != acceptanceID {
		return capture.ErrUnavailable
	}
	r := PolicyRevocation{OperationID: in.OperationID, AcceptanceID: acceptanceID, Actor: i.Principal, ExpectedRevision: expected, IdempotencyKey: key}
	instruction := sharing.Instruction
	if instruction.Creator.Issuer != i.Principal.Issuer || instruction.Creator.Subject != i.Principal.Subject {
		held, _ := value.PolicySharingManagedBy(instruction.Management, i, s.Now())
		if held, err = s.managedHeld(ctx, held, sharing.Target, i); err != nil {
			return err
		}
		if len(held) == 0 && !s.administrator(ctx, i) {
			return capture.ErrDenied
		}
		r.Administrator = len(held) == 0
		for _, a := range held {
			r.Managers = append(r.Managers, a.AssignmentID)
		}
	}
	return apply(ctx, r)
}

// managedHeld is the management i holds now on a share or policy sharing
// target: none while a current Deny names i. A projection outage or a stale
// projection is Unavailable, never a loss of management.
func (s Service) managedHeld(ctx context.Context, held []artifact.AudienceAssignment, t value.Target, i identity.Identity) ([]artifact.AudienceAssignment, error) {
	if len(held) == 0 {
		return nil, nil
	}
	p, err := s.Permissions.Permissions(ctx, t)
	if err != nil {
		return nil, capture.ErrUnavailable
	}
	denied, current := value.ManagerDenied(p, t, i, s.Now())
	if !current {
		return nil, capture.ErrUnavailable
	}
	if denied {
		return nil, nil
	}
	return held, nil
}
