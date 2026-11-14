package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/domain/fleet"
)

type ownerDiagnosticAcceptedReader func(context.Context) (fleet.OwnerConfigurationObservation, error)

func (f ownerDiagnosticAcceptedReader) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	return f(ctx)
}

type ownerDiagnosticBridgeEffects struct {
	*rootPinEffectFixture
	after bool
	cause error
	calls int
}

func (s *ownerDiagnosticBridgeEffects) WithInitialRuntimeBridge(ctx context.Context, run func(context.Context) error) error {
	s.calls++
	if s.after {
		if err := run(ctx); err != nil {
			return err
		}
	}
	return s.cause
}

func (s *ownerDiagnosticBridgeEffects) WithInitialRuntimeOwnerBridge(ctx context.Context, _ fleet.Administration, run func(context.Context) error) error {
	return s.WithInitialRuntimeBridge(ctx, run)
}
