package bootstrap

import (
	"context"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/artifact"
)

type argumentSourceReader interface {
	AcceptedArgumentSource(context.Context, artifact.ContextExpectation) (artifact.ArgumentSourceProvenance, error)
}

// The source is read from the original immutable SQL reservation, never from
// the native header. Historical provenance is not renewed collection authority.
func publisherArgumentCheck(ctx context.Context, sources argumentSourceReader, e artifact.ContextExpectation) (objectstore.StreamCheck, error) {
	if ctx == nil || sources == nil || e.NativeType != artifact.SyscallArgumentsArtifact {
		return nil, artifact.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source, err := sources.AcceptedArgumentSource(ctx, e)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return syscalls.NewArgumentCheck(e, source)
}
