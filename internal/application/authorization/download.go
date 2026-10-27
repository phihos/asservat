package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// ContextDownloadEvidence is a verified catalog/retention projection, not an
// upload manifest. No native evidence or checksum is needed for authorization.
type ContextDownloadEvidence struct {
	PurposeRef string
	CaptureID  string
	// CaseID binds a recipient's share to the artifact's case (ADR-233).
	CaseID                 string
	Version                artifact.Digest
	Audience               []artifact.AudienceAssignment
	Retained               privacy.RetainedArtifact
	ObservedAt, ValidUntil time.Time
}
type ContextDownloadCatalog interface {
	ContextDownloadEvidence(context.Context, string) (ContextDownloadEvidence, error)
}
type DownloadRetentionResolver interface {
	ResolveRetained(context.Context, privacy.Input, privacy.Deadlines, []artifact.RetentionRule) (privacy.RetainedResolution, error)
}

// The installation composition must supply current recovery, processing and
// regional/client policy. A static region string or successful SQL read does not
// implement this authority. The consuming effect/relay must fence it again.
type DownloadEnvironmentReader interface {
	DownloadEnvironment(context.Context, ContextDownloadEvidence, identity.Principal) (artifact.DownloadEnvironment, error)
}

// ContextDownloadAuthority composes ordinary approved-metadata entitlement with
// current retained obligations. Raw artifacts require their own reviewed
// authority facet; there is no fallback when a prerequisite is absent.
type ContextDownloadAuthority struct {
	RootID      string
	Identities  identities.Resolver
	Permissions ProjectionReader
	Catalog     ContextDownloadCatalog
	Retention   DownloadRetentionResolver
	Environment DownloadEnvironmentReader
	// Shares is the ADR-233 recipient branch: consulted only when ordinary
	// target eligibility refuses, before the catalog read, and re-read at the
	// final check and at every entitlement reconstruction. Nil disables it.
	Shares ShareReader
	// Reviews repeats the caller's recorded decision-time reviews before the
	// permission read (ADR-245); nil disables them.
	Reviews RecordedReviewRefresher
	Now     func() time.Time
}

func (s ContextDownloadAuthority) CheckDownload(ctx context.Context, token string, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	return s.CheckDownloadCurrent(ctx, credentialIdentity{s.Identities, token}, scope)
}

func (s ContextDownloadAuthority) CheckDownloadCurrent(ctx context.Context, source identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	return s.checkDownloadCurrent(ctx, source, scope, nil)
}

// A non-nil ordinary slot belongs to one original response. Only the
// entitlement (ordinary or shared) may survive a short identity batch; every other fact below is
// reobserved and the resulting effect authority still lasts at most five seconds.
func (s ContextDownloadAuthority) checkDownloadCurrent(ctx context.Context, source identities.CurrentIdentity, scope artifact.DownloadScope, ordinary **downloadEntitlement) (artifact.DownloadAuthority, error) {
	var out artifact.DownloadAuthority
	if !value.UUID(s.RootID) || source == nil || s.Permissions == nil || s.Catalog == nil || s.Retention == nil || s.Environment == nil || s.Now == nil || ctx.Err() != nil {
		return out, downloadRefused("configuration", ctx.Err())
	}
	if !scope.Valid() || scope.RootID != s.RootID {
		return out, downloadRefusedAs("scope", artifact.ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := s.Now()
	target := value.Target{ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID}
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || i.Principal != scope.Principal {
		return out, downloadRefused("identity", err)
	}
	var accepted *downloadEntitlement
	if ordinary != nil {
		accepted = *ordinary
		if accepted != nil && s.Now().Before(accepted.observedAt) {
			return out, downloadRefused("entitlement", nil)
		}
		if accepted != nil && (!accepted.current(s.Now()) || !accepted.sameIdentity(i)) {
			accepted, *ordinary = nil, nil
		}
	}
	var p value.Projection
	var share *value.Share
	if accepted == nil {
		if s.Reviews != nil {
			_ = s.Reviews.ReviewRecorded(ctx, i, target)
		}
		p, err = s.Permissions.Permissions(ctx, target)
		if err != nil {
			return out, downloadRefused("permission", err)
		}
		if !value.ScopeEligibility(i, p, value.DownloadApproved, target, s.Now()).Eligible {
			// Recipient branch (ADR-233): the caller's own shares of exactly
			// this artifact and version; no admitting share, no catalog read.
			if share, _, err = s.recipientShare(ctx, i, p, target, nil, "", scope); share == nil {
				return out, downloadRefused("permission", err)
			}
		}
	}
	record, err := s.Catalog.ContextDownloadEvidence(ctx, scope.ArtifactID)
	if err != nil {
		return out, downloadRefused("catalog", err)
	}
	r := record.Retained
	if !r.Valid() || r.RootID != s.RootID || r.Registration.Location.ArtifactID != scope.ArtifactID || r.Input.Target != target || !artifact.DownloadEvidenceType(r.Input.EvidenceType) || r.Input.PrivacyClass != "potentialPersonalData" || !identity.Text(record.PurposeRef, 128) || record.CaptureID != scope.CaptureID || record.Version != scope.Version || !identity.Fresh(record.ObservedAt, record.ValidUntil, s.Now(), 5*time.Second) {
		return out, downloadRefused("catalog-record", nil)
	}
	r.OriginPolicies = slices.Clone(r.OriginPolicies)
	retained := value.Retained{ArtifactID: scope.ArtifactID, Target: target, DataClass: "metadata", ExpiresAt: r.Effective.ExpiresAt, Audience: slices.Clone(record.Audience)}
	var initial value.Result
	switch {
	case accepted != nil:
		initial = accepted.evaluate(i, scope, retained, s.Now())
	case share != nil:
		// The share read above, now against the retained record and its case.
		if !value.UUID(record.CaseID) {
			return out, downloadRefused("catalog-record", nil)
		}
		share, initial = recipientShare(value.DownloadApproved, i, p, target, &retained, []value.Share{*share}, s.RootID, record.CaseID, scope.ArtifactID, scope.Version, s.Now())
	default:
		initial = value.Evaluate(i, p, value.DownloadApproved, target, &retained, s.Now())
		if !initial.Eligible && value.UUID(record.CaseID) {
			// Whole-pod rights outside the retained audience: a share may admit.
			if share, initial, err = s.recipientShare(ctx, i, p, target, &retained, record.CaseID, scope); err != nil {
				return out, downloadRefused("share", err)
			}
		}
	}
	if !initial.Eligible {
		return out, downloadRefused("audience", nil)
	}
	resolved, err := s.Retention.ResolveRetained(ctx, r.Input, r.Effective, slices.Clone(r.OriginPolicies))
	if err != nil || resolved.Target != target || resolved.PurposeRef != record.PurposeRef || !resolved.Deadlines.ValidRetained() || !resolved.AnchorAt.Equal(r.Effective.AnchorAt) || resolved.ExpiresAt.After(r.Effective.ExpiresAt) || resolved.DeleteBy.After(r.Effective.DeleteBy) || !resolved.PolicyRevision.Valid() || resolved.Proof.Policy != resolved.PolicyRevision || !resolved.Proof.Matches(s.RootID, scope.ClusterID, scope.NamespaceUID, scope.WorkloadUID, scope.PodUID) || !resolved.Proof.Valid(s.Now()) || resolved.ValidUntil.After(resolved.Proof.ValidUntil) {
		return out, downloadRefused("retention", err)
	}
	environment, err := s.Environment.DownloadEnvironment(ctx, record, i.Principal)
	if err != nil || !environment.Valid(s.Now()) || environment.RootID != s.RootID || environment.Location != r.Registration.Location || environment.StoreID != r.Registration.StoreID || environment.Principal != i.Principal {
		return out, downloadRefused("environment", err)
	}
	// Identity and safety facts remain current after blocking I/O. A new ordinary
	// observation also checks the permission revision again. A response hit uses
	// its distinct original reconstruction interval, never rewritten projection
	// freshness; SQL effects still reject known contrary permission revisions.
	current, err := source.ResolveIdentity(ctx)
	if err != nil || current.Principal != i.Principal || current.Policy != i.Policy {
		return out, downloadRefused("identity-final", err)
	}
	permission := p.Revision
	var final value.Result
	if accepted == nil {
		latest, err := s.Permissions.Permissions(ctx, target)
		if err != nil || latest.Revision != p.Revision {
			return out, downloadRefused("permission-final", err)
		}
		permission = latest.Revision
		if share == nil {
			final = value.Evaluate(current, latest, value.DownloadApproved, target, &retained, s.Now())
		} else {
			// A revocation or expiry since the first share read refuses.
			rows, err := s.Shares.RecipientShares(ctx, scope.ArtifactID, current)
			again, same := SameShare(*share, rows)
			if err != nil || !same {
				return out, downloadRefused("share-final", err)
			}
			share = &again
			final = value.EvaluateShareFor(value.DownloadApproved, current, latest, target, &retained, again, s.Now())
		}
	} else {
		permission = accepted.permission
		final = accepted.evaluate(current, scope, retained, s.Now())
	}
	now := s.Now()
	if !final.Eligible || ctx.Err() != nil || !now.Before(resolved.ExpiresAt) {
		return out, downloadRefused("audience-final", ctx.Err())
	}
	until := started.Add(5 * time.Second)
	if ordinary != nil {
		if deadline, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, deadline)
		}
	}
	for _, at := range []time.Time{initial.ValidUntil, final.ValidUntil, record.ValidUntil, resolved.ValidUntil, environment.ValidUntil, resolved.ExpiresAt} {
		until = identity.Earlier(until, at)
	}
	out = artifact.DownloadAuthority{Environment: environment, Scope: scope, PermissionEpoch: permission.UID, PermissionSequence: permission.Generation, ProjectionDigest: permission.Digest, IdentityRevision: current.Policy, CheckedAt: started, ValidUntil: until, AccessUntil: resolved.ExpiresAt, DeleteBy: resolved.DeleteBy, Retention: resolved.Proof}
	// This digest describes the current decision; it is neither an approval nor
	// an authentication token. Native hashes, credentials and evidence stay out.
	// A shared decision also binds the admitting share and its revision.
	var shareID string
	var shareRevision int64
	switch {
	case share != nil:
		shareID, shareRevision = share.ID, share.Revision
	case accepted != nil:
		shareID, shareRevision = accepted.shareID, accepted.shareRevision
	}
	encoded, err := json.Marshal(struct {
		Authority     artifact.DownloadAuthority
		Environment   artifact.DownloadEnvironment
		Assignments   []artifact.AudienceAssignment
		ShareID       string `json:",omitempty"`
		ShareRevision int64  `json:",omitempty"`
	}{out, environment, final.ContributingAssignments, shareID, shareRevision})
	if err != nil {
		return artifact.DownloadAuthority{}, downloadRefused("decision", nil)
	}
	out.DecisionDigest = sha256.Sum256(encoded)
	if !out.Valid(now) {
		return artifact.DownloadAuthority{}, downloadRefusedAs("decision-expired", artifact.ErrDownloadExpired)
	}
	if ordinary != nil && accepted == nil {
		// Commit the private observation only after the complete short authority
		// succeeds. Failure in retention/environment/final identity cannot seed it.
		*ordinary = newDownloadEntitlement(scope, current, permission, retained.Audience, final.ContributingAssignments, started, share)
	}
	return out, nil
}

// recipientShare reads the caller's shares of the scope's exact artifact and
// version and returns the admitting one, if any (ADR-233).
func (s ContextDownloadAuthority) recipientShare(ctx context.Context, i identity.Identity, p value.Projection, t value.Target, retained *value.Retained, caseID string, scope artifact.DownloadScope) (*value.Share, value.Result, error) {
	if s.Shares == nil {
		return nil, value.Result{Reason: "NoEntitlement"}, nil
	}
	rows, err := s.Shares.RecipientShares(ctx, scope.ArtifactID, i)
	if err != nil {
		return nil, value.Result{}, err
	}
	share, r := recipientShare(value.DownloadApproved, i, p, t, retained, rows, s.RootID, caseID, scope.ArtifactID, scope.Version, s.Now())
	return share, r, nil
}
