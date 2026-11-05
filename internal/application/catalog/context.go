package catalog

import (
	"context"
	"slices"
	"time"

	permissions "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

type ContextCaseRoutes interface {
	ResolveContextCase(context.Context, value.CaseRouteQuery) (value.ContextCaseRoutes, error)
}
type RecoveryReader interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

// ContextCaseService composes the existing ordinary evaluator and verified
// catalog/retention reader. It performs no acquisition, decryption or effects.
// Raw paths cannot fall back to this approved pod-status view; a concrete
// share (ADR-232) admits its recipients to exactly its artifact.
type ContextCaseService struct {
	RootID, InstallationID string
	Routes                 ContextCaseRoutes
	Permissions            permissions.ProjectionReader
	Catalog                permissions.ContextDownloadCatalog
	Retention              permissions.DownloadRetentionResolver
	Recovery               RecoveryReader
	Processing             permissions.DownloadProcessingReader
	// Shares is the ADR-232 recipient branch. It is consulted only after the
	// ordinary evaluator refuses, keyed by the caller and one artifact, and
	// before any catalog read of that artifact. Nil disables sharing.
	Shares permissions.ShareReader
	// Reviews repeats the caller's recorded decision-time reviews of each
	// route before its permission read (ADR-245); nil disables them.
	Reviews permissions.RecordedReviewRefresher
	Now     func() time.Time
}

type authorizedContext struct {
	artifact   value.ContextCaseArtifact
	retained   authorization.Retained
	permission identity.Revision
	record     permissions.ContextDownloadEvidence
	processing artifact.DownloadProcessingProof
	// share is the admitting share of a recipient read; nil for ordinary reads.
	share *authorization.Share
}

func (s ContextCaseService) GetContextCase(ctx context.Context, source identities.CurrentIdentity, caseID string) (value.ContextCase, error) {
	return s.getContextCase(ctx, source, caseID, nil)
}

func (s ContextCaseService) getContextCase(ctx context.Context, source identities.CurrentIdentity, caseID string, raw *rawCaseSelection) (value.ContextCase, error) {
	var zero value.ContextCase
	if ctx == nil || ctx.Err() != nil || source == nil || s.Routes == nil || s.Permissions == nil || s.Catalog == nil || s.Retention == nil || s.Recovery == nil || s.Processing == nil || s.Now == nil || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) || !authorization.UUID(caseID) {
		return zero, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := s.Now()
	op := authorization.ReadApproved
	if raw != nil {
		op = raw.operation
	}
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:read") || raw != nil && (i.Principal.Kind != identity.Human || (raw.operation == authorization.DownloadApproved && !slices.Contains(i.Scopes, "evidence:download") || raw.operation != authorization.DownloadApproved && !slices.Contains(i.Scopes, "evidence:raw"))) {
		return zero, value.ErrUnavailable
	}
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	routes, err := s.Routes.ResolveContextCase(ctx, value.CaseRouteQuery{RootID: s.RootID, CaseID: caseID, Identity: i, Recovery: recovery})
	if err != nil || routes.CaseID != caseID || !routes.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(started.Add(5*time.Second), identity.Earlier(i.ValidUntil, identity.Earlier(recovery.FreshUntil, routes.ValidUntil)))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if raw != nil {
		var selected []value.ContextCaseRoute
		for _, digest := range raw.digests {
			var matches []value.ContextCaseRoute
			for _, route := range routes.Routes {
				if route.Version == digest {
					matches = append(matches, route)
				}
			}
			if len(matches) != 1 {
				return zero, value.ErrUnavailable
			}
			selected = append(selected, matches[0])
		}
		routes.Routes = selected
	}
	var records []authorizedContext
	for _, route := range routes.Routes {
		// Target routing stays internal. Current whole-pod rights precede any
		// verified evidence, retained audience or effective-policy lookup.
		if s.Reviews != nil {
			_ = s.Reviews.ReviewRecorded(ctx, i, route.Target)
		}
		p, err := s.Permissions.Permissions(ctx, route.Target)
		if err != nil {
			return zero, value.ErrUnavailable
		}
		eligible := authorization.ScopeEligibility(i, p, op, route.Target, s.Now())
		var share *authorization.Share
		if !eligible.Eligible {
			if raw != nil {
				return zero, value.ErrUnavailable
			}
			// Recipient branch: the caller's own shares of this artifact are
			// read before, and instead of, any evidence lookup. No share, no
			// catalog read.
			if share, eligible = s.shared(ctx, i, p, route, caseID, nil, artifact.Digest{}); share == nil {
				continue
			}
		}
		record, err := s.Catalog.ContextDownloadEvidence(ctx, route.ArtifactID)
		if err != nil {
			return zero, value.ErrUnavailable
		}
		if raw != nil && (!rawRecordValid(record, route, caseID) || raw.operation == authorization.ReadPacketQuery && record.NativeType != artifact.RawPCAPNGArtifact || raw.operation == authorization.ReadSyscallQuery && record.NativeType != artifact.SyscallArgumentsArtifact || record.Version != route.Version) {
			return zero, value.ErrUnavailable
		}
		r := record.Retained
		if !r.Valid() || r.RootID != s.RootID || r.Registration.Location.ArtifactID != route.ArtifactID || r.Input.Target != route.Target || !artifact.DownloadEvidenceType(r.Input.EvidenceType) || r.Input.PrivacyClass != "potentialPersonalData" || !identity.Text(record.PurposeRef, 128) || record.CaptureID != route.CaptureID || record.Version == (artifact.Digest{}) || !identity.Fresh(record.ObservedAt, record.ValidUntil, s.Now(), 5*time.Second) {
			return zero, value.ErrUnavailable
		}
		retained := authorization.Retained{ArtifactID: route.ArtifactID, Target: route.Target, DataClass: "metadata", ExpiresAt: r.Effective.ExpiresAt, Audience: slices.Clone(record.Audience)}
		if raw != nil && raw.operation != authorization.DownloadApproved {
			retained.DataClass = "raw"
			retained.NativeType = record.NativeType
		}
		var initial authorization.Result
		if share == nil {
			initial = authorization.Evaluate(i, p, op, route.Target, &retained, s.Now())
			if !initial.Eligible {
				if raw != nil {
					return zero, value.ErrUnavailable
				}
				// Current whole-pod rights outside the retained audience: a
				// share may still admit this caller to the artifact.
				share, initial = s.shared(ctx, i, p, route, caseID, &retained, record.Version)
			}
		} else {
			// A share covers one concrete verified version and needs a current
			// pinned manager inside the retained audience.
			share, initial = permissions.RecipientShare(i, p, route.Target, &retained, []authorization.Share{*share}, s.RootID, caseID, route.ArtifactID, record.Version, s.Now())
		}
		if !initial.Eligible {
			continue
		}
		resolved, err := s.Retention.ResolveRetained(ctx, r.Input, r.Effective, slices.Clone(r.OriginPolicies))
		if err != nil || resolved.Target != route.Target || resolved.PurposeRef != record.PurposeRef || !resolved.Deadlines.ValidRetained() || !resolved.AnchorAt.Equal(r.Effective.AnchorAt) || resolved.ExpiresAt.After(r.Effective.ExpiresAt) || resolved.DeleteBy.After(r.Effective.DeleteBy) || !resolved.PolicyRevision.Valid() || resolved.Proof.Policy != resolved.PolicyRevision || !resolved.Proof.Matches(s.RootID, route.Target.ClusterID, route.Target.NamespaceUID, route.Target.WorkloadUID, route.Target.PodUID) || !resolved.Proof.Valid(s.Now()) || resolved.ValidUntil.After(resolved.Proof.ValidUntil) || !s.Now().Before(resolved.ExpiresAt) {
			return zero, value.ErrUnavailable
		}
		processing, err := s.Processing.ContextProcessing(ctx, record, recovery)
		if err != nil || !processing.Valid(s.Now()) || processing.RootID != s.RootID || processing.CaptureID != record.CaptureID || processing.Location != r.Registration.Location {
			return zero, value.ErrUnavailable
		}
		for _, at := range []time.Time{processing.ValidUntil, eligible.ValidUntil, initial.ValidUntil, record.ValidUntil, resolved.ValidUntil, resolved.ExpiresAt} {
			until = identity.Earlier(until, at)
		}
		retained.ExpiresAt = resolved.ExpiresAt
		records = append(records, authorizedContext{artifact: value.ContextCaseArtifact{Namespace: record.Namespace, WorkloadKind: record.WorkloadKind, WorkloadName: record.WorkloadName, PodName: record.PodName, NativeBytes: record.NativeBytes, ProfileAcquisition: cloneProfileAcquisition(record.ProfileAcquisition), ArtifactID: route.ArtifactID, CaptureID: route.CaptureID, Target: route.Target, Version: record.Version, ExpiresAt: resolved.ExpiresAt, DeleteBy: resolved.DeleteBy, Shared: share != nil, EvidenceType: r.Input.EvidenceType, NativeType: record.NativeType, DataClass: record.DataClass}, retained: retained, permission: p.Revision, record: record, processing: processing, share: share})
	}
	if len(records) == 0 {
		return zero, value.ErrUnavailable
	}
	// Recheck after every potentially blocking reader, without renewing the
	// original observations. A changed/expired included artifact denies the
	// response; no stale partial DTO is returned to a transport.
	current, err := source.ResolveIdentity(ctx)
	if err != nil || !sameIdentity(i, current, s.Now()) {
		return zero, value.ErrUnavailable
	}
	out := value.ContextCase{CaseID: caseID, ObservedAt: started}
	for _, record := range records {
		p, err := s.Permissions.Permissions(ctx, record.artifact.Target)
		if err != nil || p.Revision != record.permission {
			return zero, value.ErrUnavailable
		}
		eligible := authorization.Evaluate(current, p, op, record.artifact.Target, &record.retained, s.Now())
		if record.share != nil {
			// Re-read the share: a revocation or expiry since the first read
			// refuses the whole response.
			rows, err := s.Shares.RecipientShares(ctx, record.artifact.ArtifactID, current)
			latest, same := permissions.SameShare(*record.share, rows)
			if err != nil || !same {
				return zero, value.ErrUnavailable
			}
			eligible = authorization.EvaluateShare(current, p, record.artifact.Target, &record.retained, latest, s.Now())
		}
		if !eligible.Eligible {
			return zero, value.ErrUnavailable
		}
		latestProcessing, err := s.Processing.ContextProcessing(ctx, record.record, recovery)
		if err != nil || !latestProcessing.Valid(s.Now()) || latestProcessing.RootID != record.processing.RootID || latestProcessing.Epoch != record.processing.Epoch || latestProcessing.Sequence != record.processing.Sequence || latestProcessing.CaptureID != record.processing.CaptureID || latestProcessing.Location != record.processing.Location || latestProcessing.StateDigest != record.processing.StateDigest || !record.processing.Valid(s.Now()) {
			return zero, value.ErrUnavailable
		}
		until = identity.Earlier(until, latestProcessing.ValidUntil)
		until = identity.Earlier(until, eligible.ValidUntil)
		out.Artifacts = append(out.Artifacts, record.artifact)
	}
	latest, err := s.Recovery.RecoveryState(ctx)
	if err != nil || !latest.Valid(s.Now()) || latest.InstallationID != recovery.InstallationID || latest.IssuerEpoch != recovery.IssuerEpoch || latest.Revision != recovery.Revision {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, latest.FreshUntil)
	// Identity can disappear while final permission/recovery reads wait.
	final, err := source.ResolveIdentity(ctx)
	if err != nil || !sameIdentity(current, final, s.Now()) {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, final.ValidUntil)
	out.ValidUntil = until
	if ctx.Err() != nil || !out.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	if raw != nil {
		raw.records = records
		raw.until = out.ValidUntil
	}
	return out, nil
}

// shared is the recipient branch for one route: the caller's shares of this
// artifact only (keyed by caller and artifact), evaluated against the current
// projection. It returns nil when no share admits the caller.
func (s ContextCaseService) shared(ctx context.Context, i identity.Identity, p authorization.Projection, route value.ContextCaseRoute, caseID string, retained *authorization.Retained, version artifact.Digest) (*authorization.Share, authorization.Result) {
	if s.Shares == nil {
		return nil, authorization.Result{Reason: "NoEntitlement"}
	}
	rows, err := s.Shares.RecipientShares(ctx, route.ArtifactID, i)
	if err != nil {
		// An unavailable share ledger admits nobody through a share, but it
		// never makes an ordinary reader's other artifacts unavailable.
		return nil, authorization.Result{Reason: "ShareUnavailable"}
	}
	return permissions.RecipientShare(i, p, route.Target, retained, rows, s.RootID, caseID, route.ArtifactID, version, s.Now())
}

func sameIdentity(a, b identity.Identity, now time.Time) bool {
	return b.Valid(now) && a.Principal == b.Principal && a.Policy == b.Policy && sameSet(a.Groups, b.Groups) && sameSet(a.Scopes, b.Scopes)
}
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// The case owns its small metadata snapshot, independent of mutable adapter rows.
func cloneProfileAcquisition(p *artifact.ProfileAcquisitionMetadata) *artifact.ProfileAcquisitionMetadata {
	if p == nil {
		return nil
	}
	out := *p
	out.Acquisition = p.Acquisition.Clone()
	return &out
}
