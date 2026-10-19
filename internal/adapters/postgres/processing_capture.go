package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

var _ app.ContextProcessingCoverageReader = (*ProcessingReads)(nil)

func processingCaptureCoverage(p custodydb.ProcessingRoot, rows []custodydb.ProcessingRule, in value.ProcessingCoverageRequest, installation, issuerEpoch string, now time.Time) error {
	if !in.Valid() || in.AnchorAt.After(now) || uid(p.RootID) != in.RootID || !processingRootValid(p, installation, now) || uid(p.IssuerEpoch) != issuerEpoch ||
		!authorization.UUID(uid(p.InitializationID)) || !authorization.UUID(uid(p.Epoch)) || !authorization.UUID(uid(p.SourceUid)) || p.Sequence < 1 || p.Sequence > 1<<60 || p.BackingRevision < 1 ||
		len(p.ProtectionDigest) != 32 || bytes.Equal(p.ProtectionDigest, make([]byte, 32)) || p.Captures < 0 || p.Captures > p.MaxCaptures || p.Rules < int64(len(rows)) || p.Rules > p.MaxRules ||
		p.RootTransitions < 1 || p.RootTransitions > p.MaxRootTransitions || p.InitializedAt.Time.After(now) || len(rows) > privacy.MaxProcessingRules {
		return value.ErrUnavailable
	}
	short := in.DeleteBy.After(p.ValidUntil.Time)
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		r := privacy.ProcessingRule{ID: uid(row.ID), Revision: row.Revision, State: row.State, ReleaseAcknowledged: row.State == "released", AdministrationUntil: row.ValidUntil.Time, RetireBy: row.RetireBy.Time}
		if uid(row.RootID) != in.RootID || seen[r.ID] || len(row.Scope) > 2048 || !row.ValidUntil.Valid || !row.RetireBy.Valid ||
			json.Unmarshal(row.Scope, &r.Scope) != nil || !r.Valid() || (r.State != "restricted" && r.State != "released") {
			return value.ErrUnavailable
		}
		seen[r.ID] = true
		matches := r.Scope.Kind == "artifact" && r.Scope.Location == in.Location || r.Scope.Kind == "workloadInterval" && r.Scope.ClusterID == in.Target.ClusterID && r.Scope.NamespaceUID == in.Target.NamespaceUID && r.Scope.WorkloadUID == in.Target.WorkloadUID && !in.AnchorAt.Before(r.Scope.AcquiredFrom) && in.AnchorAt.Before(r.Scope.AcquiredUntil)
		// Administrative expiry does not release a retained restriction. Match
		// the publication guard's original per-rule horizon without fabricating
		// a lineage node, evaluating disclosure or changing privacy decisions.
		if r.State == "restricted" && matches && in.DeleteBy.After(r.AdministrationUntil) {
			short = true
		}
	}
	// Validate the entire bounded read before classifying a known limitation.
	// A malformed unrelated row remains unavailable, not an assurance of completeness.
	if short {
		return value.ErrProcessingCoverage
	}
	if p.Captures == p.MaxCaptures {
		return value.ErrCapacity
	}
	return nil
}

func readProcessingCaptureCoverage(ctx context.Context, q *custodydb.Queries, in value.ProcessingCoverageRequest, recovery artifact.RecoveryProof, started, until time.Time) (value.ProcessingCoverage, error) {
	var zero value.ProcessingCoverage
	p, err := q.ReadProcessingRoot(ctx, id(in.RootID))
	if err != nil {
		return zero, coverageStep("root")
	}
	rules, err := q.ReadProcessingRules(ctx, id(in.RootID))
	if err != nil {
		return zero, coverageStep("rules")
	}
	last, err := q.ReadProcessingRoot(ctx, id(in.RootID))
	if err != nil || !reflect.DeepEqual(last, p) {
		return zero, coverageStep("root-changed")
	}
	n, err := q.CurrentTime(ctx)
	if err != nil || ctx.Err() != nil || !recovery.Valid(n.Time) || !identity.Fresh(started, until, n.Time, 5*time.Second) {
		return zero, coverageStep("fresh")
	}
	coverageErr := processingCaptureCoverage(last, rules, in, recovery.InstallationID, recovery.IssuerEpoch, n.Time)
	// A bounded full inventory decode can cross the original cutoff too. Do not
	// classify an expired observation as a current known coverage limitation.
	n, err = q.CurrentTime(ctx)
	if err != nil || ctx.Err() != nil || !recovery.Valid(n.Time) || !identity.Fresh(started, until, n.Time, 5*time.Second) {
		return zero, coverageStep("fresh-after")
	}
	if !processingRootValid(last, recovery.InstallationID, n.Time) {
		return zero, coverageStep("root-invalid")
	}
	if coverageErr != nil {
		if errors.Is(coverageErr, value.ErrUnavailable) {
			return zero, coverageStep("coverage")
		}
		return zero, coverageErr
	}
	o := value.ProcessingCoverage{Request: in, ObservedAt: started, FreshUntil: identity.Earlier(until, p.ValidUntil.Time)}
	if !o.Current(n.Time) {
		return zero, coverageStep("current")
	}
	return o, nil
}

func (s *ProcessingReads) ContextProcessingCoverage(ctx context.Context, in value.ProcessingCoverageRequest, recovery artifact.RecoveryProof) (value.ProcessingCoverage, error) {
	var out value.ProcessingCoverage
	if s == nil || s.ledger == nil || s.recovery == nil || ctx == nil || ctx.Err() != nil || !in.Valid() || in.RootID != s.root || recovery.InstallationID != s.recovery.installation {
		return out, value.ErrUnavailable
	}
	started := time.Now().UTC().Truncate(time.Microsecond)
	until := identity.Earlier(started.Add(5*time.Second), recovery.FreshUntil)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, end := context.WithDeadline(ctx, until)
	defer end()
	err := s.ledger.transaction(call, func(q *custodydb.Queries) error {
		trust, err := s.recovery.lock(call, q, s.root, recovery)
		if err != nil {
			return coverageStepWith("recovery-lock", err)
		}
		out, err = readProcessingCaptureCoverage(call, q, in, recovery, started, until)
		if err != nil {
			return err
		}
		if err = s.recovery.check(call, q, trust, s.root, recovery); err != nil {
			return coverageStepWith("recovery-check", err)
		}
		n, err := q.CurrentTime(call)
		if err != nil || call.Err() != nil || !out.Current(n.Time) {
			return value.ErrUnavailable
		}
		return nil
	})
	if call.Err() != nil || !time.Now().Before(until) {
		return value.ProcessingCoverage{}, coverageStep("expired")
	}
	if err != nil {
		var step coverageStepError
		if errors.As(err, &step) {
			return value.ProcessingCoverage{}, coverageStepError{step.step, captureError(step.err)}
		}
		return value.ProcessingCoverage{}, captureError(err)
	}
	if !out.Current(time.Now()) {
		return value.ProcessingCoverage{}, value.ErrUnavailable
	}
	return out, nil
}

// coverageStepError keeps the classified error and names the closed step where
// a processing coverage read stopped, for diagnostics only.
type coverageStepError struct {
	step string
	err  error
}

func coverageStep(step string) error { return coverageStepError{step, value.ErrUnavailable} }
func coverageStepWith(step string, err error) error {
	return coverageStepError{step, err}
}
func (e coverageStepError) Error() string          { return e.err.Error() }
func (e coverageStepError) Unwrap() error          { return e.err }
func (e coverageStepError) ProcessingStep() string { return e.step }
