package authorization

import (
	"context"
	"slices"
	"sync"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// DownloadResponseAuthority belongs to one original content response. It is not
// a transport value, credential, global cache or authority for another request.
type DownloadResponseAuthority struct {
	mu       sync.Mutex
	owner    context.Context
	cancel   context.CancelFunc
	service  ContextDownloadAuthority
	scope    artifact.DownloadScope
	closed   bool
	ordinary *downloadEntitlement
}

func (s ContextDownloadAuthority) NewDownloadResponse(ctx context.Context, scope artifact.DownloadScope) (*DownloadResponseAuthority, error) {
	if ctx == nil || ctx.Err() != nil || !scope.Valid() || scope.RootID != s.RootID || s.Now == nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	owner, cancel := context.WithCancel(ctx)
	return &DownloadResponseAuthority{owner: owner, cancel: cancel, service: s, scope: scope}, nil
}

func (s *DownloadResponseAuthority) CheckDownloadCurrent(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !s.mu.TryLock() {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	defer s.mu.Unlock()
	if s.closed || s.owner.Err() != nil || scope != s.scope {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	if until, ok := s.owner.Deadline(); ok {
		cancel()
		call, cancel = context.WithDeadline(ctx, until)
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(s.owner, func() { defer close(joined); cancel() })
	defer func() {
		if !stop() {
			<-joined
		}
		cancel()
	}()
	a, err := s.service.checkDownloadCurrent(call, current, scope, &s.ordinary)
	if err != nil || call.Err() != nil || s.owner.Err() != nil || !a.Valid(s.service.Now()) {
		s.ordinary, s.closed = nil, true
		s.cancel()
		if err != nil {
			return artifact.DownloadAuthority{}, err
		}
		return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
	}
	return a, nil
}

func (s *DownloadResponseAuthority) Close() {
	if s == nil {
		return
	}
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.ordinary = nil
}

// Ordinary entitlement is accepted after fresh complete permission evaluation.
// Its separate reconstruction interval never changes the source projection's
// dates and is never a complete DownloadAuthority or a SQL effect permit.
const downloadPermissionRecheck = 30 * time.Second

type downloadEntitlement struct {
	scope                  artifact.DownloadScope
	identity               identity.Identity
	permission             identity.Revision
	audience, contributing []artifact.AudienceAssignment
	observedAt, recheckAt  time.Time
}

func newDownloadEntitlement(scope artifact.DownloadScope, i identity.Identity, permission identity.Revision, audience, contributing []artifact.AudienceAssignment, started time.Time) *downloadEntitlement {
	i.Groups, i.Scopes = slices.Clone(i.Groups), slices.Clone(i.Scopes)
	slices.Sort(i.Groups)
	slices.Sort(i.Scopes)
	audience = slices.Clone(audience)
	slices.SortFunc(audience, downloadAudienceOrder)
	// The old short identity is not reusable authority. Keep only its exact claim
	// set for comparison with each independently authenticated new batch.
	i.VerifiedAt, i.ValidUntil = time.Time{}, time.Time{}
	return &downloadEntitlement{scope: scope, identity: i, permission: permission, audience: audience, contributing: slices.Clone(contributing), observedAt: started, recheckAt: started.Add(downloadPermissionRecheck)}
}

func (d *downloadEntitlement) current(now time.Time) bool {
	return d != nil && !now.Before(d.observedAt) && now.Before(d.recheckAt)
}

func (d *downloadEntitlement) sameIdentity(i identity.Identity) bool {
	if d == nil || d.identity.Principal != i.Principal || d.identity.Policy != i.Policy {
		return false
	}
	for _, pair := range [][2][]string{{d.identity.Groups, i.Groups}, {d.identity.Scopes, i.Scopes}} {
		current := slices.Clone(pair[1])
		slices.Sort(current)
		if !slices.Equal(pair[0], current) {
			return false
		}
	}
	return true
}

func (d *downloadEntitlement) evaluate(i identity.Identity, scope artifact.DownloadScope, retained value.Retained, now time.Time) value.Result {
	if !d.current(now) || !i.Valid(now) || !d.sameIdentity(i) || scope != d.scope || retained.ArtifactID != scope.ArtifactID || retained.Target != (value.Target{ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID}) || retained.DataClass != "metadata" || !now.Before(retained.ExpiresAt) {
		return value.Result{}
	}
	audience := slices.Clone(retained.Audience)
	slices.SortFunc(audience, downloadAudienceOrder)
	if !slices.Equal(d.audience, audience) {
		return value.Result{}
	}
	return value.Result{Eligible: true, Reason: "Eligible", Principal: i.Principal, IdentityRevision: i.Policy, PermissionRevision: d.permission, ValidUntil: identity.Earlier(d.recheckAt, identity.Earlier(i.ValidUntil, retained.ExpiresAt)), ContributingAssignments: slices.Clone(d.contributing)}
}

func downloadAudienceOrder(x, y artifact.AudienceAssignment) int {
	if x.AssignmentID < y.AssignmentID {
		return -1
	}
	if x.AssignmentID > y.AssignmentID {
		return 1
	}
	return 0
}
