package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	live "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"slices"
	"time"
)

// LiveSourceRecord is protected existing-source provenance, not a catalog
// artifact or caller-asserted source. The adapter verifies original audience
// digest and exact active acceptance/permit before returning it.
type LiveSourceRecord struct {
	Source                 live.Source
	Audience               []artifact.AudienceAssignment
	Executor               identity.Principal
	ObservedAt, ValidUntil time.Time
}
type LiveSourceCatalog interface {
	// Minimal source routing contains only exact UID scope, no evidence/details.
	LiveSourceTarget(context.Context, string, string) (value.Target, error)
	ReadLiveSourceID(context.Context, value.Target, string, string) (LiveSourceRecord, error)
	ListLiveSources(context.Context, value.WorkloadTarget, string, int) ([]LiveSourceRecord, string, error)
	ReadLiveSource(context.Context, live.Source) (LiveSourceRecord, error)
}
type LiveWorkloads interface {
	ResolveWorkloadIdentity(context.Context, targets.WorkloadRequest) (targets.WorkloadIdentityResolution, error)
}

// LiveEnvironment enforces accepted installation/collection-ceiling live-read,
// per-projection capability and allowed region. An old/missing configuration
// denies; an artifact download policy cannot stand in for this source decision.
type LiveEnvironment interface {
	LiveSourceRead(context.Context, live.Source, string, identity.Principal) (LiveEnvironmentDecision, error)
}
type LiveEnvironmentDecision struct {
	ValidUntil  time.Time
	Limits      live.Limits
	Projections []string
}
type LiveObservationGrants interface {
	ReadLiveSourceObservation(context.Context, string, string) (time.Time, error)
}
type LiveSourceAuthority struct {
	ObservationGrants LiveObservationGrants
	RootID            string
	Targets           LiveWorkloads
	Workloads         WorkloadProjectionReader
	Permissions       ProjectionReader
	Catalog           LiveSourceCatalog
	Accepted          AcceptedPolicyReader
	Automation        AutomationAuthorityReader
	Environment       LiveEnvironment
	Now               func() time.Time
	// Diagnose, when set, receives a fixed refusal stage name; never inputs.
	Diagnose func(stage string)
}

func (s LiveSourceAuthority) refuse(stage string, err error) error {
	if s.Diagnose != nil {
		s.Diagnose("live inventory refused at " + stage)
	}
	return err
}

func (s LiveSourceAuthority) configured() bool {
	return value.UUID(s.RootID) && s.Targets != nil && s.Workloads != nil && s.Permissions != nil && s.Catalog != nil && s.Environment != nil && s.Now != nil
}
func (s LiveSourceAuthority) Inventory(ctx context.Context, current identities.CurrentIdentity, target targets.WorkloadRequest, cursor string, limit int) ([]live.Source, string, error) {
	if !s.configured() || current == nil || ctx == nil || ctx.Err() != nil || !target.Valid() || limit < 1 || limit > 100 {
		return nil, "", s.refuse("input", live.ErrDenied)
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(call)
	i = cloneProjectionIdentity(i)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return nil, "", s.refuse("identity", live.ErrDenied)
	}
	resolved, err := s.Targets.ResolveWorkloadIdentity(call, target)
	if err != nil || !resolved.Valid(s.Now()) || resolved.Reference != target {
		return nil, "", s.refuse("target", live.ErrDenied)
	}
	p, err := s.Workloads.WorkloadPermissions(call, resolved.Target())
	if err != nil {
		return nil, "", s.refuse("workload-permissions", live.ErrDenied)
	}
	rights := value.WorkloadScopeEligibility(i, p, value.ReadLiveSource, resolved.Target(), s.Now())
	if !rights.Eligible {
		return nil, "", s.refuse("workload-rights", live.ErrDenied)
	}
	until := identity.Earlier(rights.ValidUntil, resolved.FreshUntil)
	bound, stop := context.WithDeadline(call, until)
	defer stop()
	records, next, err := s.Catalog.ListLiveSources(bound, resolved.Target(), cursor, limit)
	if err != nil || len(records) > limit {
		return nil, "", s.refuse("catalog", live.ErrUnavailable)
	}
	out := make([]live.Source, 0, len(records))
	for _, record := range records {
		source := record.Source
		if source.Target.ClusterID != resolved.ClusterID || source.Target.NamespaceUID != resolved.Namespace.UID || source.Target.WorkloadUID != resolved.Workload.UID {
			return nil, "", live.ErrDenied
		}
		// The entitled workload scan already supplied this protected record.
		// Check concrete Pod rights before disclosing it; do not issue a second
		// source lookup for every row in the same inventory operation.
		pod, e := s.Permissions.Permissions(bound, source.Target)
		if e != nil {
			_ = s.refuse("pod-permissions", e)
			continue
		}
		ordinary := value.ScopeEligibility(i, pod, value.ReadLiveSource, source.Target, s.Now())
		if !ordinary.Eligible {
			_ = s.refuse("pod-rights", nil)
			continue
		}
		checked, sourceUntil, e := s.checkFacts(bound, i, pod, source, "", record, identity.Earlier(until, ordinary.ValidUntil))
		if e == nil {
			until = identity.Earlier(until, sourceUntil)
			out = append(out, checked.Clone())
		} else {
			_ = s.refuse("source-facts", e)
		}
	}
	if len(out) > 0 {
		out, until, err = s.finishSources(bound, current, i, out, "", until)
		if err != nil {
			return nil, "", s.refuse("finish", err)
		}
	}
	final, err := current.ResolveIdentity(bound)
	if err != nil || !final.Valid(s.Now()) || !sameProjectionIdentity(i, final, s.Now()) || bound.Err() != nil || !s.Now().Before(until) {
		return nil, "", s.refuse("final-identity", live.ErrDenied)
	}
	return out, next, nil
}
func (s LiveSourceAuthority) Check(ctx context.Context, current identities.CurrentIdentity, expected live.Source, projection string) (live.Source, time.Time, error) {
	var zero live.Source
	if !s.configured() || ctx == nil || ctx.Err() != nil || current == nil || expected.Root() != s.RootID || !expected.Target.Valid() || projection != "" && !live.Projection(projection) {
		return zero, time.Time{}, live.ErrDenied
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(call)
	i = cloneProjectionIdentity(i)
	if err != nil || !i.Valid(s.Now()) {
		return zero, time.Time{}, live.ErrDenied
	}
	// Ordinary current maintainer/read scope precedes the protected source lookup.
	p, err := s.Permissions.Permissions(call, expected.Target)
	if err != nil {
		return zero, time.Time{}, live.ErrDenied
	}
	ordinary := value.ScopeEligibility(i, p, value.ReadLiveSource, expected.Target, s.Now())
	if !ordinary.Eligible {
		return zero, time.Time{}, live.ErrDenied
	}
	until := ordinary.ValidUntil
	record, err := s.Catalog.ReadLiveSource(call, expected)
	if err != nil {
		return zero, time.Time{}, live.ErrDenied
	}
	return s.checkRecord(call, current, i, p, expected, projection, record, until)
}
func (s LiveSourceAuthority) checkRecord(call context.Context, current identities.CurrentIdentity, i identity.Identity, p value.Projection, expected live.Source, projection string, record LiveSourceRecord, until time.Time) (live.Source, time.Time, error) {
	source, until, e := s.checkFacts(call, i, p, expected, projection, record, until)
	if e != nil {
		return live.Source{}, time.Time{}, e
	}
	out, end, e := s.finishSources(call, current, i, []live.Source{source}, projection, until)
	if e != nil || len(out) != 1 {
		return live.Source{}, time.Time{}, live.ErrDenied
	}
	return out[0], end, nil
}
func (s LiveSourceAuthority) checkFacts(call context.Context, i identity.Identity, p value.Projection, expected live.Source, projection string, record LiveSourceRecord, until time.Time) (live.Source, time.Time, error) {
	var zero live.Source

	source := record.Source
	if !source.Same(expected) || (!source.Valid(s.Now()) && (projection != "" || !source.ReferenceValid())) || !identity.Fresh(record.ObservedAt, record.ValidUntil, s.Now(), 5*time.Second) || projection != "" && !slices.Contains(source.Projections, projection) {
		return zero, time.Time{}, live.ErrDenied
	}
	rights := value.LiveSourceEligibility(i, p, source.Target, record.Audience, record.ValidUntil, s.Now())
	if !rights.Eligible {
		return zero, time.Time{}, live.ErrDenied
	}
	until = identity.Earlier(until, rights.ValidUntil)
	if source.Manual == nil {
		if s.Accepted == nil || s.Automation == nil {
			return zero, time.Time{}, live.ErrDenied
		}
		accepted, e := s.Accepted.AcceptedPolicyAuthority(call, source.Binding.PolicyUID)
		a := accepted.Authority
		if e != nil || !a.Valid(s.Now()) || a.Executor != record.Executor || a.PolicyUID != source.Binding.PolicyUID || [32]byte(a.ScopeDigest) != source.Binding.Scope || a.ClusterID != source.Target.ClusterID || a.NamespaceUID != source.Target.NamespaceUID || a.WorkloadUID != source.Target.WorkloadUID || !s.Now().Before(accepted.SourceUntil) {
			return zero, time.Time{}, live.ErrDenied
		}
		automation, e := s.Automation.PolicyAutomationAuthority(call, a, source.Target)
		if e != nil {
			return zero, time.Time{}, live.ErrDenied
		}
		executor := value.PolicyExecutorIdentity(a, accepted.ObservedAt, accepted.SourceUntil)
		eligible := value.PolicyContextEligibility(executor, a, automation, source.Target, s.Now())
		if !eligible.Eligible {
			return zero, time.Time{}, live.ErrDenied
		}
		until = identity.Earlier(until, identity.Earlier(eligible.ValidUntil, accepted.SourceUntil))
	} else {
		// The protected catalog joins the original accepted finite execution with
		// the current exact regional/node holder. No old human identity is rebuilt.
		if !record.Executor.Valid() || source.Manual == nil || !source.Manual.Valid() {
			return zero, time.Time{}, live.ErrDenied
		}
		until = identity.Earlier(until, source.Manual.HardUntil)
	}
	if source.Binding.ObservationGrantID != "" {
		if s.ObservationGrants == nil {
			return zero, time.Time{}, live.ErrDenied
		}
		originalUntil, e := s.ObservationGrants.ReadLiveSourceObservation(call, source.ID(), source.Binding.ObservationGrantID)
		if e != nil {
			return zero, time.Time{}, live.ErrDenied
		}
		until = identity.Earlier(until, originalUntil)
	}
	if projection != "" {
		until = identity.Earlier(until, source.LeaseUntil)
	}
	if call.Err() != nil || !s.Now().Before(until) {
		return zero, time.Time{}, live.ErrDenied
	}
	return source.Clone(), until, nil
}

type liveEnvironmentBatch interface {
	LiveSourceReads(context.Context, []live.Source, string, identity.Principal) ([]LiveEnvironmentDecision, error)
}

func (s LiveSourceAuthority) finishSources(call context.Context, current identities.CurrentIdentity, i identity.Identity, sources []live.Source, projection string, until time.Time) ([]live.Source, time.Time, error) {
	if len(sources) == 0 {
		return []live.Source{}, until, nil
	}
	var decisions []LiveEnvironmentDecision
	var err error
	if batch, ok := s.Environment.(liveEnvironmentBatch); ok {
		decisions, err = batch.LiveSourceReads(call, sources, projection, i.Principal)
	} else {
		decisions = make([]LiveEnvironmentDecision, len(sources))
		for n, source := range sources {
			decisions[n], err = s.Environment.LiveSourceRead(call, source, projection, i.Principal)
			if err != nil {
				break
			}
		}
	}
	if err != nil || len(decisions) != len(sources) {
		return nil, time.Time{}, live.ErrDenied
	}
	out := make([]live.Source, len(sources))
	for n, source := range sources {
		feature := decisions[n]
		if !feature.Limits.Valid() {
			return nil, time.Time{}, live.ErrDenied
		}
		source.ViewLimits = feature.Limits
		source.Projections = slices.DeleteFunc(slices.Clone(source.Projections), func(p string) bool { return !slices.Contains(feature.Projections, p) })
		if projection != "" && !slices.Contains(source.Projections, projection) {
			return nil, time.Time{}, live.ErrDenied
		}
		until = identity.Earlier(until, feature.ValidUntil)
		out[n] = source.Clone()
	}
	final, err := current.ResolveIdentity(call)
	if err != nil || !final.Valid(s.Now()) || !sameProjectionIdentity(i, final, s.Now()) || call.Err() != nil || !s.Now().Before(until) {
		return nil, time.Time{}, live.ErrDenied
	}
	return out, identity.Earlier(until, final.ValidUntil), nil
}

// Resolve is reached only after C-13 authenticates the short-lived reference.
// Current read identity precedes minimal routing; current whole-pod entitlement
// precedes the full source/audience lookup. The reference itself is no permit.
func (s LiveSourceAuthority) Resolve(ctx context.Context, current identities.CurrentIdentity, id, kind, projection string) (live.Source, time.Time, error) {
	var zero live.Source
	if !s.configured() || ctx == nil || ctx.Err() != nil || current == nil || !value.UUID(id) || (kind != "policy" && kind != "manualSession") || !live.Projection(projection) {
		return zero, time.Time{}, live.ErrDenied
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, e := current.ResolveIdentity(call)
	i = cloneProjectionIdentity(i)
	if e != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return zero, time.Time{}, live.ErrDenied
	}
	target, e := s.Catalog.LiveSourceTarget(call, id, kind)
	if e != nil || !target.Valid() {
		return zero, time.Time{}, live.ErrDenied
	}
	p, e := s.Permissions.Permissions(call, target)
	if e != nil {
		return zero, time.Time{}, live.ErrDenied
	}
	ordinary := value.ScopeEligibility(i, p, value.ReadLiveSource, target, s.Now())
	if !ordinary.Eligible {
		return zero, time.Time{}, live.ErrDenied
	}
	record, e := s.Catalog.ReadLiveSourceID(call, target, id, kind)
	if e != nil || record.Source.ID() != id || record.Source.OwnerKind != kind || record.Source.Target != target || record.Source.Root() != s.RootID {
		return zero, time.Time{}, live.ErrDenied
	}
	return s.checkRecord(call, current, i, p, record.Source, projection, record, ordinary.ValidUntil)
}
