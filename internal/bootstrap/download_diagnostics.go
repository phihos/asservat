package bootstrap

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// downloadRefusalReport formats a refused native-download prepare/get or an
// approved query excerpt/result like the context start report (ADR-197): the
// closed stage path, the error class and the coarse remaining request deadline. It never logs error text, identifiers
// or user data.
func downloadRefusalReport(report func(string), now func() time.Time) func(context.Context, string, error) {
	return func(ctx context.Context, operation string, err error) {
		if err == nil || report == nil || now == nil {
			return
		}
		step := operation
		var fixed interface{ FixedStep() string }
		if errors.As(err, &fixed) {
			step += "/" + fixed.FixedStep()
		}
		report(step + " (" + downloadRefusalClass(err) + ") left" + fleetapp.RemainingBucket(ctx, now()))
	}
}

// downloadRefusalClass classifies the innermost retained dependency cause, or
// the returned error when a stage retained none, into a closed word.
func downloadRefusalClass(err error) string {
	for range 8 {
		var c interface{ StepCause() error }
		if !errors.As(err, &c) || c.StepCause() == nil {
			break
		}
		err = c.StepCause()
	}
	switch {
	case errors.Is(err, evidence.ErrDownloadBindingStale):
		return "binding-stale"
	case errors.Is(err, evidence.ErrDownloadMetadataUnavailable):
		return "metadata-unavailable"
	case errors.Is(err, artifact.ErrDownloadExpired):
		return "expired"
	case errors.Is(err, artifact.ErrDownloadConflict):
		return "conflict"
	case errors.Is(err, artifact.ErrDownloadCapacity):
		return "capacity"
	case errors.Is(err, artifact.ErrIntegrity):
		return "integrity"
	case errors.Is(err, artifact.ErrInvalid):
		return "invalid"
	case errors.Is(err, query.ErrExpired):
		return "expired"
	case errors.Is(err, query.ErrInvalid):
		return "invalid"
	case errors.Is(err, identity.ErrDenied):
		return "denied"
	}
	return regionalCause(err)
}
