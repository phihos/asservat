//go:build !linux

package bootstrap

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"context"
)

func nodeProcessAcquirer(string, collector.Facts) func(context.Context, collector.ProcessCapture) (artifact.ProcessInventory, error) {
	return nil
}
