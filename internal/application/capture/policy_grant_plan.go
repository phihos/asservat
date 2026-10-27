package capture

import (
	"context"
	"crypto/sha256"
	"reflect"
	"slices"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planning "asservat.local/asservat/internal/domain/planning"
)

// PolicyGrantAcceptanceReader exposes the existing current accepted read with
// its immutable provenance, so callers never author executor, workload or scope.
type PolicyGrantAcceptanceReader interface {
	AcceptedPolicyRecord(context.Context, string) (authorization.AcceptedPolicySnapshot, value.PolicyAcceptance, error)
}

// PolicyGrantPlans recompiles the protected accepted collection intent with the
// same profile/filter compiler used at activation. A changed interpretation is
// refused rather than silently renewing or replacing an accepted policy scope.
type PolicyGrantPlans struct {
	Accepted        PolicyGrantAcceptanceReader
	Documents       PolicyDocuments
	CompileRecorder PolicyRecorderCompiler
	RecipeName      string
	RecipeDigest    artifact.Digest
	Now             func() time.Time
}

func (s PolicyGrantPlans) PolicyGrantPlan(ctx context.Context, policy string) (authapp.PolicyGrantPlan, error) {
	var zero authapp.PolicyGrantPlan
	if ctx == nil || ctx.Err() != nil || s.Accepted == nil || s.Documents == nil || s.CompileRecorder == nil || s.Now == nil || !identity.Text(policy, 64) {
		return zero, authapp.ErrGrantUnavailable
	}
	snapshot, record, err := s.Accepted.AcceptedPolicyRecord(ctx, policy)
	now := s.Now()
	if err != nil || !record.Valid() || !reflect.DeepEqual(snapshot.Authority, record.Authority) || snapshot.Authority.PolicyUID != policy || snapshot.Authority.ScopeDigest != record.Authority.ScopeDigest || !snapshot.Authority.Valid(now) || !now.Before(snapshot.FreshUntil) {
		return zero, authapp.ErrGrantUnavailable
	}
	source, spec, err := s.Documents.ReadPolicy(ctx, record.Source.Name, policy)
	if err != nil || !source.Valid(s.Now()) || source.Revision.UID != policy || source.Name != record.Source.Name || source.InstallationID != record.Source.InstallationID || source.ClusterID != record.Source.ClusterID || source.NamespaceUID != record.Source.NamespaceUID || source.CollectionDigest != record.Source.CollectionDigest || source.Suspended || source.Deleted {
		return zero, authapp.ErrGrantUnavailable
	}
	compiled, err := CompilePolicyWithRecorders(spec, s.RecipeName, s.RecipeDigest, s.CompileRecorder)
	if err != nil || compiled.Recorder == nil {
		return zero, authapp.ErrGrantUnavailable
	}
	a := snapshot.Authority
	scope := RecorderPolicyScope(source.Revision.UID, record.IntentVersion, source.CollectionDigest, compiled, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits)
	if len(scope) == 0 || sha256.Sum256(scope) != a.ScopeDigest {
		return zero, authapp.ErrGrantUnavailable
	}
	action := compiled.Recorder.Action
	review := authapp.GrantReview{Namespace: compiled.Namespace, WorkloadKind: compiled.WorkloadKind, WorkloadName: compiled.WorkloadName, Deadline: a.NotAfter, Actions: []authapp.GrantReviewAction{{ActionID: action.ID, Kind: action.Kind, ExecutionMode: action.ExecutionMode, Before: action.Before, After: action.After, Filter: action.Filter, FilterDigest: action.FilterDigest, FilterInstructions: action.FilterInstructions, MaxBytes: action.MaxBytes, RingMaxAge: action.RingMaxAge, RingMaxBytes: action.RingMaxBytes, Sensitive: slices.Clone(action.Sensitive)}}}
	reasons := []authorization.SensitiveReason{{ActionID: action.ID, Code: "policyCollection"}}
	for _, code := range action.Sensitive {
		reasons = append(reasons, authorization.SensitiveReason{ActionID: action.ID, Code: code})
	}
	if slices.Contains(action.Sensitive, planning.ReasonRawBytePredicate) {
		duration, err := time.ParseDuration(action.Timeout)
		observed := min(planning.SensitiveMaxObservedBytes, a.Limits.MaxObservedBytes)
		if err != nil || duration < time.Second || observed < 1 {
			return zero, authapp.ErrGrantUnavailable
		}
		review.ObservationLimits = &authapp.GrantObservationLimits{MaxSessionSeconds: int64(min(duration, time.Hour) / time.Second), MaxObservedBytes: observed, MaxBytesPerSecond: planning.SensitiveMaxBytesPerSecond, MaxConcurrentSessions: 1}
	}
	until := identity.Earlier(snapshot.FreshUntil, identity.Earlier(source.FreshUntil, a.NotAfter))
	if ctx.Err() != nil || !s.Now().Before(until) {
		return zero, authapp.ErrGrantUnavailable
	}
	return authapp.PolicyGrantPlan{Authority: a, RecipeDigest: compiled.Recorder.RecipeDigest, Scope: scope, Review: review, DataClass: "extract", Reasons: reasons, FreshUntil: until}, nil
}
