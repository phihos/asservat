//go:build !linux

package bootstrap

import "asservat.local/asservat/internal/domain/artifact"

func disableWorkerCoreDumps() error { return artifact.ErrDownloadUnavailable }
