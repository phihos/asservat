package bootstrap

import (
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/capture"
)

func captureHistoryBounds(v *contracts.CaptureHistoryLimits) (capture.HistoryLimits, error) {
	if v == nil {
		return capture.DefaultHistoryLimits(), nil
	}
	out := capture.HistoryLimits{PerSelector: v.PerSelector, PerInstallation: v.PerInstallation}
	if !out.Valid() {
		return capture.HistoryLimits{}, mounts.ErrUnavailable
	}
	return out, nil
}
