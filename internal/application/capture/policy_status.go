package capture

import (
	"context"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type PolicyStatusLedger interface {
	Status(context.Context, string) (value.PolicyStatus, error)
}

// PolicyStatusService explains one accepted policy without content
// (REQ-TRG-005): counters, recent occurrences and suppression summaries.
// The caller needs current read rights on the policy's workload and either
// the creator identity or a current maintainer assignment, as for capture
// progress. Reading status samples nothing and collects nothing.
type PolicyStatusService struct {
	RootID, InstallationID string
	Documents              PolicyDocuments
	Ledger                 PolicyStatusLedger
	Permissions            PolicyPermissions
	Recovery               fleetapp.RecoveryReader
	Now                    func() time.Time
	CompileRecorder        PolicyRecorderCompiler
	RecipeName             string
	RecipeDigest           artifact.Digest
}

func (s PolicyStatusService) Get(ctx context.Context, current identities.CurrentIdentity, name string) (value.PolicyStatus, time.Time, error) {
	var zero value.PolicyStatus
	if ctx == nil || current == nil || s.Documents == nil || s.Ledger == nil || s.Permissions == nil || s.Recovery == nil || s.Now == nil || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) {
		return zero, time.Time{}, value.ErrUnavailable
	}
	if !identity.Text(name, 253) {
		return zero, time.Time{}, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, time.Time{}, value.ErrDenied
	}
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return zero, time.Time{}, value.ErrUnavailable
	}
	source, spec, err := s.Documents.ReadPolicy(ctx, name, "")
	if err != nil {
		return zero, time.Time{}, value.ErrUnavailable
	}
	status, err := s.Ledger.Status(ctx, source.Revision.UID)
	if err != nil || status.ActiveID == "" && status.DeactivatedID == "" {
		return zero, time.Time{}, value.ErrUnavailable
	}
	if status.ActiveID == "" {
		// A deactivated policy is not polled, so the ledger's source row is not
		// refreshed; report the current object's generation (a changed
		// revision can be activated again).
		status.Generation = source.Revision.Generation
	}
	// The current DebugPolicy's detector, for display (ADR-230).
	if d, ok := DescribePolicyDetector(spec); ok {
		status.Detector = &d
	}
	target := authorization.PolicyScope(status.Authority)
	projection, err := s.Permissions.Permissions(ctx, target)
	if err != nil {
		return zero, time.Time{}, value.ErrUnavailable
	}
	r := authorization.CaptureProgressEligibility(i, projection, target, status.Authority.Creator, s.Now())
	if !r.Eligible {
		return zero, time.Time{}, value.ErrDenied
	}
	status.MaxGrantStarts = 0
	if s.CompileRecorder != nil && status.ActiveID != "" && status.AcceptedIntentVersion > 0 && source.Valid(s.Now()) && !source.Suspended && !source.Deleted && source.InstallationID == status.Authority.InstallationID && source.Revision.UID == status.PolicyUID && status.Authority.Valid(s.Now()) {
		compiled, e := CompilePolicyWithRecorders(spec, s.RecipeName, s.RecipeDigest, s.CompileRecorder)
		if e == nil && compiled.Recorder != nil {
			a := status.Authority
			scope := RecorderPolicyScope(source.Revision.UID, status.AcceptedIntentVersion, source.CollectionDigest, compiled, a.NamespaceUID, a.WorkloadUID, a.Delegation, a.Owners, a.Actions, a.Limits)
			starts, e := authapp.PolicyGrantStartsPerExecution(scope, a, compiled.Recorder.RecipeDigest)
			if e == nil && starts > 0 && source.Valid(s.Now()) {
				status.MaxGrantStarts = min(int64(10000), a.Limits.MaxExecutions*int64(starts))
			}
		}
	}
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !fresh.Valid(s.Now()) {
		return zero, time.Time{}, value.ErrDenied
	}
	until := identity.Earlier(identity.Earlier(r.ValidUntil, fresh.ValidUntil), recovery.FreshUntil)
	if status.MaxGrantStarts > 0 {
		until = identity.Earlier(until, source.FreshUntil)
	}
	if !s.Now().Before(until) || ctx.Err() != nil {
		return zero, time.Time{}, value.ErrUnavailable
	}
	return status, until, nil
}
