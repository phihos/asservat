package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// ContextProjectionEvidence comes from independently verified publication. It
// contains no native content, filename or checksum and is not a writer manifest.
type ContextProjectionEvidence struct {
	CaseID, CaptureID, PurposeRef   string
	Version, SourceProjectionDigest artifact.Digest
	SourceFormat, DataClass         string
	Audience                        []artifact.AudienceAssignment
	Retained                        privacy.RetainedArtifact
	ObservedAt, ValidUntil          time.Time
}

type ContextProjectionCatalog interface {
	ContextProjectionEvidence(context.Context, string) (ContextProjectionEvidence, error)
}

type ProjectionRetentionResolver interface {
	ResolveRetained(context.Context, privacy.Input, privacy.Deadlines, []artifact.RetentionRule) (privacy.RetainedResolution, error)
}

// ContextProjectionEnvironmentReader must independently accept the query's
// current recovery, processing and protected delivery path. Download policy or
// successful storage access alone cannot implement this port.
type ContextProjectionEnvironmentReader interface {
	ProjectionEnvironment(context.Context, ContextProjectionEvidence, identity.Principal) (analysis.ContextProjectionEnvironment, error)
}

// ContextProjectionAuthority produces a current internal decision only. Query
// admission, keys and disclosure still need their own transaction guards,
// prepaid budgets, audit and final current checks. It has no token fallback.
type ContextProjectionAuthority struct {
	RootID      string
	Permissions ProjectionReader
	Catalog     ContextProjectionCatalog
	Retention   ProjectionRetentionResolver
	Environment ContextProjectionEnvironmentReader
	// Shares is the ADR-232 recipient branch: consulted only when ordinary
	// target eligibility refuses, before the protected catalog read. Nil
	// disables shared inspection.
	Shares ShareReader
	// Reviews repeats the caller's recorded decision-time reviews before the
	// permission read (ADR-245); nil disables them.
	Reviews RecordedReviewRefresher
	Now     func() time.Time
}

func (s ContextProjectionAuthority) CheckProjectionCurrent(ctx context.Context, source identities.CurrentIdentity, scope analysis.ContextProjectionScope) (analysis.ContextProjectionAuthority, error) {
	if !scope.Valid() {
		return analysis.ContextProjectionAuthority{}, analysis.ErrInvalid
	}
	return s.checkProjection(ctx, source, scope.Candidate(), &scope)
}

// ResolveProjectionCurrent resolves the first scope only after current ordinary
// target eligibility. The route candidate contains no asserted source version;
// C-18 does not need a protected catalog read to construct this input.
func (s ContextProjectionAuthority) ResolveProjectionCurrent(ctx context.Context, source identities.CurrentIdentity, candidate analysis.ContextProjectionCandidate) (analysis.ContextProjectionAuthority, error) {
	return s.checkProjection(ctx, source, candidate, nil)
}

func (s ContextProjectionAuthority) checkProjection(ctx context.Context, source identities.CurrentIdentity, candidate analysis.ContextProjectionCandidate, expected *analysis.ContextProjectionScope) (analysis.ContextProjectionAuthority, error) {
	var zero analysis.ContextProjectionAuthority
	if ctx == nil || ctx.Err() != nil || source == nil || !value.UUID(s.RootID) || s.Permissions == nil || s.Catalog == nil || s.Retention == nil || s.Environment == nil || s.Now == nil {
		return zero, projectionRefused("configuration", analysis.ErrUnavailable, nil)
	}
	if !candidate.Valid() || candidate.RootID != s.RootID {
		return zero, projectionRefused("candidate", analysis.ErrInvalid, nil)
	}
	started := s.Now()
	until, bound := started.Add(identity.EvidenceReadRequestWindow), "window"
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until, bound = d, "request"
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	// Every child context retains all earlier intervals, including the initial
	// caller and empty-deny observations. Fresh reads can only shorten them.
	// bound names the component whose interval ends the decision, for the
	// operator report only (installed native83/84/86 were cut by one).
	shorten := func(name string, bounds ...time.Time) context.CancelFunc {
		for _, at := range bounds {
			if at.Before(until) {
				until, bound = at, name
			}
		}
		var cancel context.CancelFunc
		call, cancel = context.WithDeadline(call, until)
		return cancel
	}
	i, err := source.ResolveIdentity(call)
	i = cloneProjectionIdentity(i)
	if err != nil || !i.Valid(s.Now()) || i.Principal != candidate.Principal || call.Err() != nil {
		return zero, projectionRefused("identity", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	defer shorten("identity", i.ValidUntil)()
	target := value.Target{ClusterID: candidate.ClusterID, NamespaceUID: candidate.NamespaceUID, WorkloadUID: candidate.WorkloadUID, PodUID: candidate.PodUID}
	if s.Reviews != nil {
		_ = s.Reviews.ReviewRecorded(call, i, target)
	}
	p, err := s.Permissions.Permissions(call, target)
	p = cloneProjectionPermissions(p)
	preliminary := value.ScopeEligibility(i, p, value.ReadApproved, target, s.Now())
	var expectedVersion artifact.Digest
	if expected != nil {
		expectedVersion = expected.Version
	}
	// Recipient branch (ADR-232): only after ordinary target eligibility
	// refuses, the caller's own shares of this one artifact; no share, no
	// catalog read.
	shares := func(retained *value.Retained, version artifact.Digest) (*value.Share, value.Result, error) {
		if s.Shares == nil {
			return nil, value.Result{Reason: "NoEntitlement"}, nil
		}
		rows, e := s.Shares.RecipientShares(call, candidate.ArtifactID, i)
		if e != nil {
			return nil, value.Result{}, e
		}
		share, r := RecipientShare(i, p, target, retained, rows, s.RootID, candidate.CaseID, candidate.ArtifactID, version, s.Now())
		return share, r, nil
	}
	var share *value.Share
	if err == nil && !preliminary.Eligible && call.Err() == nil {
		share, preliminary, err = shares(nil, expectedVersion)
	}
	if err != nil || !preliminary.Eligible || call.Err() != nil {
		return zero, projectionRefused("permissions", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	defer shorten("permissions", preliminary.ValidUntil)()
	// The protected source lookup follows current ordinary target eligibility.
	record, err := s.Catalog.ContextProjectionEvidence(call, candidate.ArtifactID)
	record = cloneProjectionEvidence(record)
	scope := analysis.ContextProjectionScope{RootID: candidate.RootID, CaseID: candidate.CaseID, CaptureID: candidate.CaptureID, ArtifactID: candidate.ArtifactID, ClusterID: candidate.ClusterID, NamespaceUID: candidate.NamespaceUID, WorkloadUID: candidate.WorkloadUID, PodUID: candidate.PodUID, Selection: candidate.Selection, Principal: candidate.Principal, Version: record.Version, SourceProjectionDigest: record.SourceProjectionDigest, SourceFormat: record.SourceFormat, DisplayVersion: analysis.ContextDisplayVersion}
	if err != nil || !scope.Valid() || expected != nil && scope != *expected || !projectionEvidenceMatches(record, scope, s.Now()) || call.Err() != nil {
		return zero, projectionRefused("catalog", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	r := record.Retained
	retained := value.Retained{ArtifactID: scope.ArtifactID, Target: target, DataClass: record.DataClass, ExpiresAt: r.Effective.ExpiresAt, Audience: slices.Clone(record.Audience)}
	var initial value.Result
	if share == nil {
		initial = value.Evaluate(i, p, value.ReadApproved, target, &retained, s.Now())
		if !initial.Eligible {
			// Whole-pod rights outside the retained audience: a share may admit.
			if share, initial, err = shares(&retained, record.Version); err != nil {
				return zero, projectionRefused("share", analysis.ErrUnavailable, err)
			}
		}
	} else {
		share, initial = RecipientShare(i, p, target, &retained, []value.Share{*share}, s.RootID, candidate.CaseID, candidate.ArtifactID, record.Version, s.Now())
	}
	if !initial.Eligible {
		return zero, projectionRefused("audience", analysis.ErrUnavailable, nil)
	}
	defer shorten("audience", initial.ValidUntil)()
	defer shorten("catalog", record.ValidUntil)()
	defer shorten("expiry", r.Effective.ExpiresAt)()
	resolve := func() (privacy.RetainedResolution, error) {
		input := r.Input
		input.Parents = slices.Clone(input.Parents)
		v, e := s.Retention.ResolveRetained(call, input, r.Effective, slices.Clone(r.OriginPolicies))
		v.Policies = slices.Clone(v.Policies)
		if e != nil || !projectionRetentionMatches(v, record, scope, s.Now()) || call.Err() != nil {
			return privacy.RetainedResolution{}, projectionRefused("retention", analysis.ErrUnavailable, errors.Join(e, call.Err()))
		}
		return v, nil
	}
	resolved, err := resolve()
	if err != nil {
		return zero, err
	}
	defer shorten("retention", resolved.ValidUntil)()
	defer shorten("expiry", resolved.ExpiresAt)()
	environment, err := s.Environment.ProjectionEnvironment(call, cloneProjectionEvidence(record), i.Principal)
	if err != nil || !projectionEnvironmentMatches(environment, record, scope, s.Now()) || call.Err() != nil {
		return zero, projectionRefused("environment", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	defer shorten(environmentBound(environment), environment.ValidUntil)()

	// Recheck the request-owned identity and ordinary permissions after blocking
	// reads. Same principal/policy without the original groups/scopes is not the
	// same request authority. Retention and environment are checked afterwards.
	current, err := source.ResolveIdentity(call)
	current = cloneProjectionIdentity(current)
	if err != nil || !sameProjectionIdentity(i, current, s.Now()) || call.Err() != nil {
		return zero, projectionRefused("identity-again", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	defer shorten("identity", current.ValidUntil)()
	latest, err := s.Permissions.Permissions(call, target)
	latest = cloneProjectionPermissions(latest)
	retained.ExpiresAt = resolved.ExpiresAt
	final := value.Evaluate(current, latest, value.ReadApproved, target, &retained, s.Now())
	var latestShare value.Share
	if share != nil && err == nil {
		// A revocation or expiry since the first share read refuses.
		rows, e := s.Shares.RecipientShares(call, candidate.ArtifactID, current)
		same := false
		latestShare, same = SameShare(*share, rows)
		if e != nil || !same {
			return zero, projectionRefused("share-again", analysis.ErrUnavailable, e)
		}
		final = value.EvaluateShare(current, latest, target, &retained, latestShare, s.Now())
	}
	if err != nil || latest.Revision != p.Revision || !final.Eligible || call.Err() != nil {
		return zero, projectionRefused("permissions-again", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	defer shorten("permissions", final.ValidUntil)()
	lastRetention, err := resolve()
	if err != nil || !sameProjectionRetention(resolved, lastRetention) {
		return zero, projectionRefused("retention-again", analysis.ErrUnavailable, err)
	}
	defer shorten("retention", lastRetention.ValidUntil)()
	defer shorten("expiry", lastRetention.ExpiresAt)()
	lastEnvironment, err := s.Environment.ProjectionEnvironment(call, cloneProjectionEvidence(record), i.Principal)
	if err != nil || !projectionEnvironmentMatches(lastEnvironment, record, scope, s.Now()) || !sameProjectionEnvironment(environment, lastEnvironment) || call.Err() != nil {
		return zero, projectionRefused("environment-again", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	defer shorten(environmentBound(lastEnvironment), lastEnvironment.ValidUntil)()
	lastIdentity, err := source.ResolveIdentity(call)
	lastIdentity = cloneProjectionIdentity(lastIdentity)
	if err != nil || !sameProjectionIdentity(i, lastIdentity, s.Now()) || !sameProjectionIdentity(current, lastIdentity, s.Now()) || call.Err() != nil {
		return zero, projectionRefused("identity-last", analysis.ErrUnavailable, errors.Join(err, call.Err()))
	}
	defer shorten("identity", lastIdentity.ValidUntil)()
	now := s.Now()
	// Returning the original proofs keeps their observation identities and
	// freshness intact. Final readers cannot replace an expired initial proof.
	eligibleAt := func(id identity.Identity, projection value.Projection) bool {
		if share != nil {
			return value.EvaluateShare(id, projection, target, &retained, latestShare, now).Eligible
		}
		return value.Evaluate(id, projection, value.ReadApproved, target, &retained, now).Eligible
	}
	if !now.Before(until) || !resolved.Proof.Valid(now) || !environment.Valid(now) || !eligibleAt(i, p) || !eligibleAt(lastIdentity, latest) {
		return zero, projectionRefused("expired", analysis.ErrExpired, nil)
	}
	out := analysis.ContextProjectionAuthority{Scope: scope, Environment: environment, Retention: resolved.Proof, PermissionRevision: p.Revision, IdentityRevision: i.Policy, CheckedAt: started, ValidUntil: until, AccessUntil: resolved.ExpiresAt, DeleteBy: resolved.DeleteBy, Bound: bound}
	// A shared decision also binds the admitting share and its revision.
	var shareID string
	var shareRevision int64
	if share != nil {
		shareID, shareRevision = latestShare.ID, latestShare.Revision
	}
	encoded, err := json.Marshal(struct {
		Authority     analysis.ContextProjectionAuthority
		Assignments   []artifact.AudienceAssignment
		ShareID       string `json:",omitempty"`
		ShareRevision int64  `json:",omitempty"`
	}{out, final.ContributingAssignments, shareID, shareRevision})
	if err != nil {
		return zero, projectionRefused("decision", analysis.ErrUnavailable, nil)
	}
	out.DecisionDigest = sha256.Sum256(encoded)
	if call.Err() != nil || !out.Valid(s.Now()) {
		return zero, projectionRefused("expired", analysis.ErrExpired, call.Err())
	}
	return out, nil
}

func projectionEvidenceMatches(r ContextProjectionEvidence, scope analysis.ContextProjectionScope, now time.Time) bool {
	target := value.Target{ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID}
	return r.Retained.Valid() && r.Retained.RootID == scope.RootID && r.CaseID == scope.CaseID && r.CaptureID == scope.CaptureID &&
		r.Version == scope.Version && r.SourceFormat == artifact.ContextFormat && r.SourceFormat == scope.SourceFormat && r.SourceProjectionDigest == scope.SourceProjectionDigest &&
		r.SourceProjectionDigest == analysis.ContextSourceProjectionDigest() && r.DataClass == "metadata" && identity.Text(r.PurposeRef, 128) &&
		r.Retained.Registration.Location.ArtifactID == scope.ArtifactID && r.Retained.Registration.NativeLimit == artifact.MaxContextBytes && r.Retained.Input.Target == target &&
		r.Retained.Input.EvidenceType == "context" && r.Retained.Input.PrivacyClass == "potentialPersonalData" && identity.Fresh(r.ObservedAt, r.ValidUntil, now, identity.EvidenceReadRequestWindow)
}

func projectionRetentionMatches(v privacy.RetainedResolution, r ContextProjectionEvidence, scope analysis.ContextProjectionScope, now time.Time) bool {
	return v.Target == r.Retained.Input.Target && v.PurposeRef == r.PurposeRef && v.Deadlines.ValidRetained() && v.AnchorAt.Equal(r.Retained.Effective.AnchorAt) &&
		!v.ExpiresAt.After(r.Retained.Effective.ExpiresAt) && !v.DeleteBy.After(r.Retained.Effective.DeleteBy) && now.Before(v.ExpiresAt) && privacy.ValidPolicyOrigins(v.Policies) &&
		v.PolicyRevision.Valid() && v.Proof.Policy == v.PolicyRevision && v.Proof.Matches(scope.RootID, scope.ClusterID, scope.NamespaceUID, scope.WorkloadUID, scope.PodUID) &&
		v.Proof.Valid(now) && !v.ValidUntil.After(v.Proof.ValidUntil) && now.Before(v.ValidUntil)
}

func projectionEnvironmentMatches(v analysis.ContextProjectionEnvironment, r ContextProjectionEvidence, scope analysis.ContextProjectionScope, now time.Time) bool {
	return v.Valid(now) && v.RootID == scope.RootID && v.Location == r.Retained.Registration.Location && v.StoreID == r.Retained.Registration.StoreID &&
		v.Principal == scope.Principal && v.Processing.CaptureID == scope.CaptureID
}

func cloneProjectionIdentity(v identity.Identity) identity.Identity {
	v.Groups, v.Scopes = slices.Clone(v.Groups), slices.Clone(v.Scopes)
	slices.Sort(v.Groups)
	slices.Sort(v.Scopes)
	return v
}

func sameProjectionIdentity(a, b identity.Identity, now time.Time) bool {
	b = cloneProjectionIdentity(b)
	return a.Valid(now) && b.Valid(now) && a.Principal == b.Principal && a.Policy == b.Policy && slices.Equal(a.Groups, b.Groups) && slices.Equal(a.Scopes, b.Scopes)
}

func cloneProjectionPermissions(v value.Projection) value.Projection {
	v.Allows, v.Denies = slices.Clone(v.Allows), slices.Clone(v.Denies)
	return v
}

func cloneProjectionEvidence(v ContextProjectionEvidence) ContextProjectionEvidence {
	v.Audience = slices.Clone(v.Audience)
	v.Retained.OriginPolicies = slices.Clone(v.Retained.OriginPolicies)
	v.Retained.Input.Parents = slices.Clone(v.Retained.Input.Parents)
	return v
}

func sameProjectionRetention(a, b privacy.RetainedResolution) bool {
	x, y := a.Proof, b.Proof
	x.ObservedAt, y.ObservedAt, x.ValidUntil, y.ValidUntil = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	return a.Target == b.Target && a.PolicyRevision == b.PolicyRevision && a.PurposeRef == b.PurposeRef && a.AnchorAt.Equal(b.AnchorAt) &&
		a.ExpiresAt.Equal(b.ExpiresAt) && a.DeleteBy.Equal(b.DeleteBy) && slices.Equal(a.Policies, b.Policies) && x == y
}

func sameProjectionEnvironment(a, b analysis.ContextProjectionEnvironment) bool {
	a.ObservedAt, b.ObservedAt, a.ValidUntil, b.ValidUntil = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	a.Recovery.ObservedAt, b.Recovery.ObservedAt, a.Recovery.FreshUntil, b.Recovery.FreshUntil = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	a.Processing.ObservedAt, b.Processing.ObservedAt, a.Processing.ValidUntil, b.Processing.ValidUntil = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	return a == b
}

// environmentBound names the environment component whose interval ends it.
func environmentBound(e analysis.ContextProjectionEnvironment) string {
	switch {
	case e.ValidUntil.Equal(e.Recovery.FreshUntil):
		return "environment/recovery"
	case e.ValidUntil.Equal(e.Processing.ValidUntil):
		return "environment/processing"
	default:
		return "environment/policy"
	}
}
