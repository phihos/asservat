package capture

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type ContextProcessingCoverageReader interface {
	ContextProcessingCoverage(context.Context, value.ProcessingCoverageRequest, artifact.RecoveryProof) (value.ProcessingCoverage, error)
}

func (s ContextInvestigation) processingCoverage(ctx context.Context, p value.ContextPreview, f contextFacts, recovery artifact.RecoveryProof, originalIdentityUntil time.Time) (value.ProcessingCoverage, error) {
	r := value.ProcessingCoverageRequest{RootID: s.RootID, Location: artifact.Location{ClusterID: p.Target.ClusterID, ArtifactID: p.ArtifactID, AttemptID: p.AttemptID}, Target: f.target.Target(), AnchorAt: f.retention.AnchorAt, DeleteBy: f.retention.DeleteBy}
	if s.Processing == nil || !r.Valid() {
		return value.ProcessingCoverage{}, previewFailure("processing/input", value.ErrUnavailable)
	}
	until := identity.Earlier(originalIdentityUntil, identity.Earlier(f.eligibility.ValidUntil, identity.Earlier(f.eligibility.VerifiedIdentity.ValidUntil, recovery.FreshUntil)))
	call, end := context.WithDeadline(ctx, until)
	defer end()
	o, err := s.Processing.ContextProcessingCoverage(call, r, recovery)
	// Do not expose a known limitation using expired authorization metadata.
	if call.Err() != nil || !s.Now().Before(until) || !s.factsCurrent(f, s.Now()) || !recovery.Valid(s.Now()) {
		return value.ProcessingCoverage{}, previewFailure("processing/current", value.ErrUnavailable)
	}
	if err != nil {
		return value.ProcessingCoverage{}, previewFailure("processing/read"+processingReadStep(err), err)
	}
	if o.Request != r || o.FreshUntil.After(until) || !o.Current(s.Now()) {
		return value.ProcessingCoverage{}, previewFailure("processing/proof", value.ErrUnavailable)
	}
	return o, nil
}

// processingReadStep appends a closed coverage-read step for diagnostics.
func processingReadStep(err error) string {
	var step interface{ ProcessingStep() string }
	if errors.As(err, &step) {
		switch s := step.ProcessingStep(); s {
		case "root", "rules", "root-changed", "fresh", "fresh-after", "root-invalid", "coverage", "current", "recovery-lock", "recovery-check", "expired", "tx", "other":
			return "/" + s
		}
	}
	return ""
}
