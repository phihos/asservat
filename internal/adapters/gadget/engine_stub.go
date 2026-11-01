//go:build !gadget || !linux

// Package gadget is the embedded observation engine adapter (ADR-246, plan
// S1, C-23). Only the collector image links Inspektor Gadget (build tag
// gadget); every other build, including the hub and connector, carries this
// stub, which reports the engine as not linked and captures nothing.
package gadget

import (
	"context"

	"asservat.local/asservat/internal/domain/collector"
)

func Initialize(collector.Facts) collector.Engine { return collector.Engine{} }

func CapturePackets(context.Context, string, int, func(Frame)) (CaptureStats, error) {
	return CaptureStats{}, ErrEngineUnavailable
}

func CaptureObservedPackets(context.Context, string, int, func(Frame), func(InputNotice)) (CaptureStats, error) {
	return CaptureStats{}, ErrEngineUnavailable
}
