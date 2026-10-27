//go:build !gadget || !linux

// Package gadget is the embedded observation engine adapter (ADR-246, plan
// S1, C-23). Only the collector image links Inspektor Gadget (build tag
// gadget); every other build, including the hub and connector, carries this
// stub, which reports the engine as not linked.
package gadget

import "asservat.local/asservat/internal/domain/collector"

func Initialize(collector.Facts) collector.Engine { return collector.Engine{} }
