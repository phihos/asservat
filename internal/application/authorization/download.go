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
	PurposeRef             string
	CaptureID              string
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
// current retained obligations. Raw artifacts and shares require their own
// reviewed authority facets; there is no fallback when a prerequisite is absent.
type ContextDownloadAuthority struct {
	RootID      string
	Identities  identities.Resolver
	Permissions ProjectionReader
	Catalog     ContextDownloadCatalog
	Retention   DownloadRetentionResolver
	Environment DownloadEnvironmentReader
	Now         func() time.Time
}

func (s ContextDownloadAuthority) CheckDownload(ctx context.Context, token string, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	return s.CheckDownloadCurrent(ctx, credentialIdentity{s.Identities, token}, scope)
}

func (s ContextDownloadAuthority) CheckDownloadCurrent(ctx context.Context, source identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	return s.checkDownloadCurrent(ctx, source, scope, nil)
}

// A non-nil ordinary slot belongs to one original response. Only the ordinary
// entitlement may survive a short identity batch; every other fact below is
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
	if accepted == nil {
		p, err = s.Permissions.Permissions(ctx, target)
		if err != nil || !value.ScopeEligibility(i, p, value.DownloadApproved, target, s.Now()).Eligible {
			return out, downloadRefused("permission", err)
		}
	}
	record, err := s.Catalog.ContextDownloadEvidence(ctx, scope.ArtifactID)
	if err != nil {
		return out, downloadRefused("catalog", err)
	}
	r := record.Retained
	if !r.Valid() || r.RootID != s.RootID || r.Registration.Location.ArtifactID != scope.ArtifactID || r.Input.Target != target || r.Input.EvidenceType != "context" || r.Input.PrivacyClass != "potentialPersonalData" || !identity.Text(record.PurposeRef, 128) || record.CaptureID != scope.CaptureID || record.Version != scope.Version || !identity.Fresh(record.ObservedAt, record.ValidUntil, s.Now(), 5*time.Second) {
		return out, downloadRefused("catalog-record", nil)
	}
	r.OriginPolicies = slices.Clone(r.OriginPolicies)
	retained := value.Retained{ArtifactID: scope.ArtifactID, Target: target, DataClass: "metadata", ExpiresAt: r.Effective.ExpiresAt, Audience: slices.Clone(record.Audience)}
	var initial value.Result
	if accepted == nil {
		initial = value.Evaluate(i, p, value.DownloadApproved, target, &retained, s.Now())
	} else {
		initial = accepted.evaluate(i, scope, retained, s.Now())
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
		final = value.Evaluate(current, latest, value.DownloadApproved, target, &retained, s.Now())
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
	encoded, err := json.Marshal(struct {
		Authority   artifact.DownloadAuthority
		Environment artifact.DownloadEnvironment
		Assignments []artifact.AudienceAssignment
	}{out, environment, final.ContributingAssignments})
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
		*ordinary = newDownloadEntitlement(scope, current, permission, retained.Audience, final.ContributingAssignments, started)
	}
	return out, nil
}
