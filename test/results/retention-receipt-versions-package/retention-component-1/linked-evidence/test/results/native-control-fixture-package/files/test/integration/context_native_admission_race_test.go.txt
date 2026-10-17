package integration

import (
	"context"
	"errors"

	"asservat.local/asservat/internal/domain/artifact"
)

func nativeControlRaceError(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, artifact.ErrDownloadConflict):
		return "conflict"
	case errors.Is(err, artifact.ErrDownloadCapacity):
		return "capacity"
	case errors.Is(err, artifact.ErrDownloadExpired):
		return "expired"
	case errors.Is(err, artifact.ErrDownloadUnavailable):
		return "unavailable"
	default:
		return "other"
	}
}
