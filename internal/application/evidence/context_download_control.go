package evidence

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var ErrDownloadMetadataUnavailable = errors.New("verified download metadata unavailable")

// ErrDownloadBindingStale is the database's refusal of a download session while
// the workload's capacity binding is stale (ADR-200). It is the custody
// unavailable class, so callers that do not retry see no difference.
var ErrDownloadBindingStale = fmt.Errorf("%w: capacity binding stale", privacy.ErrUnavailable)

type CurrentDownloadAuthority interface {
	CheckDownloadCurrent(context.Context, identities.CurrentIdentity, artifact.DownloadScope) (artifact.DownloadAuthority, error)
}
type ContextDownloadRecovery interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}
type ContextDownloadRoutes interface {
	ResolveContextDownload(context.Context, artifact.DownloadRouteQuery) (artifact.DownloadRoute, error)
}
type ContextDownloadSources interface {
	ReadContextDownloadSource(context.Context, artifact.DownloadAuthority) (ContextDownloadSource, error)
}
type ContextDownloadControlLedger interface {
	LookupDownloadKey(context.Context, artifact.DownloadKeyQuery) (artifact.DownloadKeyLookup, error)
	LookupDownload(context.Context, string, identity.Principal) (artifact.DownloadSession, error)
	ReserveDownload(context.Context, DownloadReservation) (artifact.DownloadSession, error)
	ObserveDownload(context.Context, string, artifact.DownloadAuthority, *artifact.DownloadPreparation) (artifact.DownloadObservation, error)
}
type ContextDownloadSource struct {
	Scope                  artifact.DownloadScope
	Expectation            artifact.ContextExpectation
	Copies                 artifact.Copies
	ObservedAt, ValidUntil time.Time
}

func (s ContextDownloadSource) Valid(now time.Time) bool {
	e, p := s.Expectation, s.Scope
	return identity.Fresh(s.ObservedAt, s.ValidUntil, now, artifact.DownloadLease) && p.Valid() && e.Validate() == nil && e.DataClass == "metadata" && s.Copies.Validate(e.Registration) == nil && ContextCopiesDigest(s.Copies) == p.Version && e.Registration.Location.ArtifactID == p.ArtifactID && e.CaptureUID == p.CaptureID && e.Registration.Location.ClusterID == p.ClusterID && e.NamespaceUID == p.NamespaceUID && e.WorkloadUID == p.WorkloadUID && e.PodUID == p.PodUID
}

// This read port supplies accepted, independently backed configuration; the
// coordinator cannot mint allocations or invent a default transfer budget.
type ContextDownloadPlans interface {
	ContextDownloadPlan(context.Context, artifact.DownloadScope) (ContextDownloadPlan, error)
}
type ContextDownloadPlan struct {
	Allocation                           artifact.DownloadAllocation
	OutputLimit, ReadLimit, RequestLimit int64
	Duration                             time.Duration
	// Freshness of this admission snapshot, consumed by session reservation.
	ObservedAt, ValidUntil time.Time
	// Absolute accepted backing end. Zero is historical component-only.
	HardUntil time.Time
}

func (p ContextDownloadPlan) Valid(scope artifact.DownloadScope, now time.Time) bool {
	return (p.HardUntil.IsZero() || now.Before(p.HardUntil) && !p.HardUntil.After(p.Allocation.ValidUntil)) && p.Allocation.Valid() && p.Allocation.Covers(scope) && identity.Fresh(p.ObservedAt, p.ValidUntil, now, artifact.DownloadLease) && now.Before(p.Allocation.ValidUntil) && p.OutputLimit >= artifact.MaxContextBytes && p.OutputLimit <= p.Allocation.OutputLimit && p.ReadLimit >= 2*ContextDownloadReadWork && p.ReadLimit <= p.Allocation.ReadLimit && p.RequestLimit >= 2 && p.RequestLimit <= artifact.MaxDownloadRequests && p.Duration > 0 && p.Duration <= 8*time.Hour
}

// All three methods belong to an actual configured regional native-work path.
// Check is passive readiness at consumption, not a lease for later effects.
// Read never dispatches, decrypts, refreshes keys or retries.
// Continue is an explicit prepare operation: it reuses the exact original
// session/worker and may do bounded prepaid work only under this live identity.
// Pending=true is an acknowledged startup wait, not an unknown effect reply.
type ContextDownloadRuntime interface {
	CheckContextDownloadRuntime(context.Context, artifact.DownloadScope) (time.Time, error)
	ReadPreparedContextDownload(context.Context, identities.CurrentIdentity, artifact.DownloadSession) (artifact.PreparedDownload, bool, error)
	ContinueContextDownload(context.Context, identities.CurrentIdentity, artifact.DownloadSession, ContextDownloadSource) (ContextDownloadContinuation, error)
}
type ContextDownloadContinuation struct{ Pending bool }
type ContextDownloadView struct {
	Session  artifact.DownloadSession
	Metadata *artifact.NativeDownloadMetadata
	// ContinuePreparation permits bounded automatic same-key prepare continuation
	// while the initiating view/session remains active. It never permits a new
	// key/session, a status-triggered decrypt or repair of a lost verified cache.
	ContinuePreparation bool
	ValidUntil          time.Time
	// These are current effective managed-evidence limits, including for
	// terminal-only status; the immutable session deadline is not a substitute.
	AccessUntil, DeleteBy time.Time
}

// Only ordinary approved pod-status is implemented. No public transport is
// mounted here. Cancellation/audit/attachment/production native runtime remain
// separate prerequisites; absence of a real runtime permits no reservation.
type ContextDownloadCoordinator struct {
	RootID, InstallationID string
	Recovery               ContextDownloadRecovery
	Routes                 ContextDownloadRoutes
	Sources                ContextDownloadSources
	Authority              CurrentDownloadAuthority
	Sessions               ContextDownloadControlLedger
	Plans                  ContextDownloadPlans
	Runtime                ContextDownloadRuntime
	// Refresh is optional (ADR-200): a refused reservation re-arms the
	// capacity refresh demand behind the allocation and is retried.
	Refresh ContextDownloadRefresh
	// Refused is optional operator diagnostics (ADR-197): it receives each
	// refused prepare/get once, labelled with its closed stage. It must report
	// only that stage, an error class and a coarse deadline bucket.
	Refused func(context.Context, string, error)
	Now     func() time.Time
	NewID   func() string
}

// ContextDownloadRefresh re-arms the capacity refresh demand for the workload
// behind a download allocation. It confers no authority.
type ContextDownloadRefresh interface {
	DemandDownloadRefresh(context.Context, string) error
}

func ContextDownloadRequestDigest(artifactID string) artifact.Digest {
	return sha256.Sum256([]byte("context-download-prepare/v1\x00" + artifactID))
}
func ContextDownloadKeyDigest(key string) artifact.Digest {
	return sha256.Sum256([]byte("context-download-prepare-key/v1\x00" + key))
}
func (s ContextDownloadCoordinator) valid() bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && s.Recovery != nil && s.Routes != nil && s.Sources != nil && s.Authority != nil && s.Sessions != nil && s.Plans != nil && s.Now != nil && s.NewID != nil
}
func downloadSameIdentity(a, b identity.Identity, now time.Time) bool {
	if !b.Valid(now) || a.Principal != b.Principal || a.Policy != b.Policy {
		return false
	}
	for _, pair := range [][2][]string{{a.Groups, b.Groups}, {a.Scopes, b.Scopes}} {
		x, y := slices.Clone(pair[0]), slices.Clone(pair[1])
		slices.Sort(x)
		slices.Sort(y)
		if !slices.Equal(x, y) {
			return false
		}
	}
	return true
}
func (s ContextDownloadCoordinator) begin(ctx context.Context, current identities.CurrentIdentity) (identity.Identity, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || current == nil || !s.valid() {
		return identity.Identity{}, time.Time{}, collapsed("configuration", artifact.ErrDownloadUnavailable, nil)
	}
	started := s.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:read") || !slices.Contains(i.Scopes, "evidence:download") {
		return i, time.Time{}, collapsed("identity", artifact.ErrDownloadUnavailable, err)
	}
	until := identity.Earlier(started.Add(artifact.DownloadLease), i.ValidUntil)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	return i, until, nil
}
func (s ContextDownloadCoordinator) authority(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope, until *time.Time) (artifact.DownloadAuthority, error) {
	a, err := s.Authority.CheckDownloadCurrent(ctx, current, scope)
	if err != nil {
		return artifact.DownloadAuthority{}, collapsed("authority", artifact.ErrDownloadUnavailable, err)
	}
	return s.consumeAuthority(ctx, a, scope, until)
}

// An already checked authority belongs only to this request. Consuming it again
// checks its original bounds locally; it does not reconstruct or renew it.
func (s ContextDownloadCoordinator) consumeAuthority(ctx context.Context, a artifact.DownloadAuthority, scope artifact.DownloadScope, until *time.Time) (artifact.DownloadAuthority, error) {
	if ctx.Err() != nil || !a.Valid(s.Now()) || a.Scope != scope || !a.Environment.Valid(s.Now()) || a.Environment.InstallationID != s.InstallationID || !a.Retention.Valid(s.Now()) || a.DeleteBy.IsZero() {
		return artifact.DownloadAuthority{}, collapsed("authority-bounds", artifact.ErrDownloadUnavailable, ctx.Err())
	}
	*until = identity.Earlier(*until, a.ValidUntil)
	if !s.Now().Before(*until) {
		return artifact.DownloadAuthority{}, collapsed("authority-expired", artifact.ErrDownloadUnavailable, nil)
	}
	a.ValidUntil = identity.Earlier(a.ValidUntil, *until)
	if !a.Valid(s.Now()) {
		return artifact.DownloadAuthority{}, collapsed("authority-expired", artifact.ErrDownloadUnavailable, nil)
	}
	return a, nil
}
func (s ContextDownloadCoordinator) PrepareContextDownload(ctx context.Context, current identities.CurrentIdentity, artifactID, key string) (ContextDownloadView, error) {
	view, err := s.prepare(ctx, current, artifactID, key)
	s.refused(ctx, "prepare", err)
	return view, err
}
func (s ContextDownloadCoordinator) prepare(ctx context.Context, current identities.CurrentIdentity, artifactID, key string) (ContextDownloadView, error) {
	var zero ContextDownloadView
	if !authorization.UUID(artifactID) || !identity.Text(key, 128) {
		return zero, collapsed("input", artifact.ErrInvalid, nil)
	}
	i, until, err := s.begin(ctx, current)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || !recovery.Valid(s.Now()) || recovery.InstallationID != s.InstallationID {
		return zero, collapsed("recovery", artifact.ErrDownloadUnavailable, err)
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	lookup, err := s.Sessions.LookupDownloadKey(ctx, artifact.DownloadKeyQuery{Identity: i, Recovery: recovery, Key: ContextDownloadKeyDigest(key)})
	if err != nil || !lookup.Valid(s.Now()) {
		return zero, collapsed("key-lookup", artifact.ErrDownloadUnavailable, err)
	}
	until = identity.Earlier(until, lookup.ValidUntil)
	var session artifact.DownloadSession
	var scope artifact.DownloadScope
	if lookup.Found {
		session = lookup.Session
		scope = session.Scope
		if scope.RootID != s.RootID || scope.Principal != i.Principal {
			return zero, collapsed("key-scope", artifact.ErrDownloadUnavailable, nil)
		}
		if scope.ArtifactID != artifactID || session.RequestDigest != ContextDownloadRequestDigest(artifactID) {
			return zero, collapsed("key-conflict", artifact.ErrDownloadConflict, nil)
		}
	} else {
		route, e := s.Routes.ResolveContextDownload(ctx, artifact.DownloadRouteQuery{ArtifactID: artifactID, Identity: i, Recovery: recovery})
		if e != nil || !route.Valid(s.Now()) || route.Scope.RootID != s.RootID || route.Scope.ArtifactID != artifactID || route.Scope.Principal != i.Principal {
			return zero, collapsed("route", artifact.ErrDownloadUnavailable, e)
		}
		scope = route.Scope
		until = identity.Earlier(until, route.ValidUntil)
	}
	a, err := s.authority(ctx, current, scope, &until)
	if err != nil {
		return zero, err
	}
	if lookup.Found && session.StopProtocol != artifact.DownloadStopProtocol {
		return zero, collapsed("stop-protocol", artifact.ErrDownloadUnavailable, nil)
	}
	// A replay observes the original result. Terminal/expired sessions and
	// active prepared sessions require no startup availability or new work.
	if lookup.Found && (session.State != artifact.DownloadPreparing || !s.Now().Before(session.Deadline)) {
		return s.viewAuthority(ctx, current, i, session, until, false, &a)
	}
	if s.Runtime == nil {
		return zero, collapsed("runtime-missing", artifact.ErrDownloadUnavailable, nil)
	}
	readyUntil, err := s.Runtime.CheckContextDownloadRuntime(ctx, scope)
	if err != nil || !s.Now().Before(readyUntil) || readyUntil.After(s.Now().Add(artifact.DownloadLease)) {
		return zero, collapsed("runtime-ready", artifact.ErrDownloadUnavailable, err)
	}
	// Readiness is consumed here. Worker effects independently require current
	// configuration and authority; an older readiness observation is not their
	// lifetime. Keep the original request/identity/authority bounds in until.
	if !lookup.Found {
		plan, e := s.Plans.ContextDownloadPlan(ctx, scope)
		if e != nil || !plan.Valid(scope, s.Now()) {
			return zero, collapsed("plan", artifact.ErrDownloadUnavailable, e)
		}
		admissionUntil := identity.Earlier(until, plan.ValidUntil)
		if ctx.Err() != nil || !s.Now().Before(admissionUntil) {
			return zero, collapsed("plan-expired", artifact.ErrDownloadUnavailable, ctx.Err())
		}
		now := s.Now().UTC().Truncate(time.Microsecond)
		session = artifact.DownloadSession{StopProtocol: artifact.DownloadStopProtocol, ID: s.NewID(), AllocationID: plan.Allocation.ID, Scope: scope, RequestDigest: ContextDownloadRequestDigest(artifactID), State: artifact.DownloadPreparing, CreatedAt: now, Deadline: identity.Earlier(now.Add(plan.Duration), identity.Earlier(a.AccessUntil, plan.Allocation.ValidUntil)).UTC().Truncate(time.Microsecond), OutputLimit: plan.OutputLimit, ReadLimit: plan.ReadLimit, RequestLimit: plan.RequestLimit}
		if !plan.HardUntil.IsZero() {
			session.Deadline = identity.Earlier(session.Deadline, plan.HardUntil).UTC().Truncate(time.Microsecond)
		}
		// The adapter resolves a racing original key before applying the new plan.
		reserveCtx, stop := context.WithDeadline(ctx, admissionUntil)
		session, err = s.reserve(reserveCtx, DownloadReservation{Session: session, IdempotencyDigest: ContextDownloadKeyDigest(key), Authority: a})
		admissionExpired := reserveCtx.Err() != nil || !s.Now().Before(admissionUntil)
		stop()
		if err != nil {
			return zero, stepped("reserve", err)
		}
		if admissionExpired {
			return zero, collapsed("reserve-expired", artifact.ErrDownloadUnavailable, nil)
		}
		// The acknowledged reservation consumes plan freshness. Its immutable
		// limits, backing/access deadline and spend remain in the session; later
		// effects use current SQL checks under the original request authority.
	}
	if !session.Valid() || session.Scope != scope || session.RequestDigest != ContextDownloadRequestDigest(artifactID) {
		return zero, collapsed("session", artifact.ErrDownloadUnavailable, nil)
	}
	if session.StopProtocol != artifact.DownloadStopProtocol {
		return zero, collapsed("stop-protocol", artifact.ErrDownloadUnavailable, nil)
	}
	pending := false
	if session.State == artifact.DownloadPreparing {
		if !s.Now().Before(session.Deadline) {
			return s.viewAuthority(ctx, current, i, session, until, false, &a)
		}
		workUntil := identity.Earlier(until, session.Deadline)
		workCtx, stop := context.WithDeadline(ctx, workUntil)
		defer stop()
		source, e := s.Sources.ReadContextDownloadSource(workCtx, a)
		if e != nil || !source.Valid(s.Now()) || source.Scope != scope {
			return zero, collapsed("source", artifact.ErrDownloadUnavailable, e)
		}
		until = identity.Earlier(until, source.ValidUntil)
		workUntil = identity.Earlier(workUntil, source.ValidUntil)
		if workCtx.Err() != nil || !s.Now().Before(workUntil) {
			return zero, collapsed("source-expired", artifact.ErrDownloadUnavailable, workCtx.Err())
		}
		continuationCtx, finish := context.WithDeadline(workCtx, workUntil)
		var continuation ContextDownloadContinuation
		if native, ok := s.Runtime.(*ContextNativeRuntime); ok {
			// The installed runtime consumes this request's exact initial proof.
			// Standalone runtime calls still construct their own observation.
			continuation, e = native.continueContextDownloadAuthority(continuationCtx, current, session, source, &a)
		} else {
			continuation, e = s.Runtime.ContinueContextDownload(continuationCtx, current, session, source)
		}
		finish()
		if e != nil {
			return zero, stepped("continue", e)
		} // uncertain effects never become acknowledged Pending
		pending = continuation.Pending
	}
	return s.viewAuthority(ctx, current, i, session, until, pending, &a)
}
func (s ContextDownloadCoordinator) GetContextDownload(ctx context.Context, current identities.CurrentIdentity, downloadID string) (ContextDownloadView, error) {
	view, err := s.get(ctx, current, downloadID)
	s.refused(ctx, "get", err)
	return view, err
}
func (s ContextDownloadCoordinator) get(ctx context.Context, current identities.CurrentIdentity, downloadID string) (ContextDownloadView, error) {
	if !authorization.UUID(downloadID) {
		return ContextDownloadView{}, collapsed("input", artifact.ErrInvalid, nil)
	}
	i, until, err := s.begin(ctx, current)
	if err != nil {
		return ContextDownloadView{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	session, err := s.Sessions.LookupDownload(ctx, downloadID, i.Principal)
	if err != nil || !session.Valid() || session.ID != downloadID || session.Scope.RootID != s.RootID || session.Scope.Principal != i.Principal {
		return ContextDownloadView{}, collapsed("lookup", artifact.ErrDownloadUnavailable, err)
	}
	return s.view(ctx, current, i, session, until, false)
}
func (s ContextDownloadCoordinator) view(ctx context.Context, current identities.CurrentIdentity, initial identity.Identity, session artifact.DownloadSession, until time.Time, pending bool) (ContextDownloadView, error) {
	return s.viewAuthority(ctx, current, initial, session, until, pending, nil)
}

func (s ContextDownloadCoordinator) viewAuthority(ctx context.Context, current identities.CurrentIdentity, initial identity.Identity, session artifact.DownloadSession, until time.Time, pending bool, handoff *artifact.DownloadAuthority) (ContextDownloadView, error) {
	view, err := s.viewChecked(ctx, current, initial, session, until, pending, handoff)
	return view, stepped("view", err)
}
func (s ContextDownloadCoordinator) viewChecked(ctx context.Context, current identities.CurrentIdentity, initial identity.Identity, session artifact.DownloadSession, until time.Time, pending bool, handoff *artifact.DownloadAuthority) (ContextDownloadView, error) {
	var zero ContextDownloadView
	var a artifact.DownloadAuthority
	var err error
	if handoff == nil {
		a, err = s.authority(ctx, current, session.Scope, &until)
	} else {
		a, err = s.consumeAuthority(ctx, *handoff, session.Scope, &until)
	}
	if err != nil {
		return zero, err
	}
	// Observe current durable state first. Terminal status requires no worker,
	// retained native facts or runtime; it never authorizes another transfer.
	observed, err := s.Sessions.ObserveDownload(ctx, session.ID, a, nil)
	if err != nil || !observed.Valid(s.Now()) || observed.Session.Scope != session.Scope || observed.Session.ID != session.ID {
		return zero, collapsed("observe", artifact.ErrDownloadUnavailable, err)
	}
	until = identity.Earlier(until, observed.ValidUntil)
	observed.Session.State = observed.Session.ObservedState(s.Now())
	var prepared artifact.PreparedDownload
	found := false
	switch observed.Session.State {
	case artifact.DownloadReady, artifact.DownloadStreaming, artifact.DownloadInterrupted:
		if s.Runtime == nil {
			return zero, collapsed("runtime-missing", ErrDownloadMetadataUnavailable, nil)
		}
		// This regional read is metadata-only: no dispatch, native read or
		// key refresh. Only active states require a retained verified result.
		if native, ok := s.Runtime.(*ContextNativeRuntime); ok {
			var release func()
			prepared, _, release, err = native.preparedAuthority(ctx, current, observed.Session, false, &a)
			if release != nil {
				release()
			}
			found = prepared.Preparation.Valid()
		} else {
			prepared, found, err = s.Runtime.ReadPreparedContextDownload(ctx, current, observed.Session)
		}
		if err != nil || !found {
			return zero, collapsed("prepared", ErrDownloadMetadataUnavailable, err)
		}
		if !prepared.Valid() || prepared.Scope != session.Scope || prepared.Preparation.SessionID != session.ID {
			return zero, collapsed("prepared-scope", artifact.ErrDownloadUnavailable, nil)
		}
		// The second observation verifies the exact historical acknowledged
		// preparation and notices cancellation/completion during the read.
		observed, err = s.Sessions.ObserveDownload(ctx, session.ID, a, &prepared.Preparation)
		if err != nil || !observed.Valid(s.Now()) || observed.Session.Scope != session.Scope || observed.Session.ID != session.ID {
			return zero, collapsed("observe-prepared", artifact.ErrDownloadUnavailable, err)
		}
		until = identity.Earlier(until, observed.ValidUntil)
	}
	latest, err := current.ResolveIdentity(ctx)
	if err != nil || !downloadSameIdentity(initial, latest, s.Now()) {
		return zero, collapsed("identity-final", artifact.ErrDownloadUnavailable, err)
	}
	until = identity.Earlier(until, latest.ValidUntil)
	observed.Session.State = observed.Session.ObservedState(s.Now())
	if !observed.Session.State.Terminal() {
		until = identity.Earlier(until, observed.Session.Deadline)
	}
	out := ContextDownloadView{Session: observed.Session, ValidUntil: until, AccessUntil: a.AccessUntil, DeleteBy: a.DeleteBy}
	switch observed.Session.State {
	case artifact.DownloadReady, artifact.DownloadStreaming, artifact.DownloadInterrupted:
		if !found {
			return zero, collapsed("prepared", ErrDownloadMetadataUnavailable, nil)
		}
		m := prepared.Native
		m.ReadUntil = a.AccessUntil
		m.DeleteBy = a.DeleteBy
		out.Metadata = &m
	case artifact.DownloadPreparing:
		out.ContinuePreparation = pending
	}
	if ctx.Err() != nil || !s.Now().Before(until) {
		return zero, collapsed("expired", artifact.ErrDownloadUnavailable, ctx.Err())
	}
	return out, nil
}

// reserve inserts the session. The database refuses it while the workload's
// capacity binding is stale (ADR-200); with Refresh set, the first refusal
// re-arms the refresh demand and the idempotent reservation is retried every
// 250 ms within the caller's original deadline. Only ErrDownloadBindingStale
// is retried; every other refusal, and one that outlasts the deadline, is
// returned unchanged.
func (s ContextDownloadCoordinator) reserve(ctx context.Context, r DownloadReservation) (artifact.DownloadSession, error) {
	session, err := s.Sessions.ReserveDownload(ctx, r)
	if !errors.Is(err, ErrDownloadBindingStale) || s.Refresh == nil || ctx.Err() != nil || s.Refresh.DemandDownloadRefresh(ctx, r.Session.AllocationID) != nil {
		return session, err
	}
	for {
		t := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return session, err
		case <-t.C:
		}
		if session, err = s.Sessions.ReserveDownload(ctx, r); !errors.Is(err, ErrDownloadBindingStale) {
			return session, err
		}
	}
}
