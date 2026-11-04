package kubernetes

import (
	"context"
	"errors"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Private operator metadata on the existing failed body decision. No provider
// text or payload leaves this boundary; valid APIStatus denial bodies retain
// the original guard checks even when client-go returns a Forbidden error.
type ownerProbeFailureDiagnostic struct {
	err       error
	category  string
	remaining time.Duration
}

func (e *ownerProbeFailureDiagnostic) Error() string { return e.err.Error() }
func (e *ownerProbeFailureDiagnostic) Unwrap() error { return e.err }
func (e *ownerProbeFailureDiagnostic) ProbeFailureDiagnostic() (string, time.Duration) {
	return e.category, e.remaining
}

func ownerProbeFailure(ctx context.Context, rawErr error, remaining time.Duration) error {
	category := "body"
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(rawErr, context.DeadlineExceeded):
		category = "deadline"
	case errors.Is(ctx.Err(), context.Canceled) || errors.Is(rawErr, context.Canceled):
		category = "canceled"
	default:
		var status apierrors.APIStatus
		if rawErr != nil && !errors.As(rawErr, &status) {
			category = "transport"
		}
	}
	return &ownerProbeFailureDiagnostic{configurationSourceError(configurationSourceProbeDenialBody, cfg.ErrUnavailable), category, remaining}
}
