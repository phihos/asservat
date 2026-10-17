package native_test

import (
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
	"context"
)

func registerHandoffOperation(ctx context.Context, r *native.HubRouter, in evidence.NativeExchangeRegistration, before func(context.Context, evidence.NativeOrigin) error, check func(context.Context, evidence.NativeOrigin) (value.NativeLease, error), complete func(context.Context, value.NativeLease) error) (evidence.NativePendingExchange, error) {
	in.Complete = complete
	return r.RegisterNativeExchange(ctx, in, before, check)
}

// Only standalone protocol fixtures use this explicit synthetic SQL outcome.
// Production constructors receive the original NativeAttachment closure.
func syntheticNativeCompletion(ctx context.Context, _ value.NativeLease) error { return ctx.Err() }
