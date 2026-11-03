package gadget

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/adapters/syscalls"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
)

const ArgumentObjectPath = "/usr/lib/asservat/gadgets/traceloop-arguments/program.bpf.o"

// Updated only with the pinned reproducible compiler output and native report.
const ArgumentObjectBytes = 694968
const ArgumentObjectSHA256 = "4c548b54bf9cc0850352d8a4e4cc23cc5ddc7d50cfbc4bfb96913f319ec1784d"

var ErrArgumentRequest = errors.New("argument engine request unsupported")
var ErrArgumentReplay = errors.New("argument engine attempt already consumed")

// ArgumentRequest is mechanism input from an already admitted immutable slice.
// It supplies no authority itself. The node composition must bind exact Pod,
// boot/process/session and original grant/deadline before constructing a recorder.
type ArgumentRequest struct {
	StartBy                                        time.Time
	PodUID                                         string
	AccountingRule                                 [32]byte
	Names                                          []string
	CaptureBuffers                                 bool
	MaxBytesPerEvent, MaxTrackedThreads            int
	Events, Bytes, EventsPerSecond, BytesPerSecond uint64
	Deadline                                       time.Time
}

type ArgumentBudget struct {
	Events, Bytes, Stopped, DeadlineBootNS, MaxProbeBytes uint64
	RateNextNS, RateIntervalNS, RateBurstNS               uint64
}

type ArgumentStats struct {
	AccountingKnown                                              bool
	ReservedEvents, ReservedBytes, ConsumedEvents, ConsumedBytes uint64
	LostSamples                                                  uint64
	Stopped                                                      bool // reason is intentionally unknown: no inferred zero loss
	CoverageUnknown                                              bool
}

func (r ArgumentRequest) definitions() ([]syscalls.ArgumentDefinition, error) {
	if r.AccountingRule != collector.ArgumentObservationAccountingRule() || !authorization.UUID(r.PodUID) || r.Events < 1 || r.Events > 1_000_000_000 || r.Bytes < 1 || r.Bytes > 1<<40 || r.EventsPerSecond < 1 || r.EventsPerSecond > 100000 || r.BytesPerSecond < 1 || r.BytesPerSecond > 1<<30 || r.MaxTrackedThreads < 1 || r.MaxTrackedThreads > 16384 || r.Deadline.IsZero() || r.StartBy.IsZero() || r.StartBy.After(r.Deadline) {
		return nil, ErrArgumentRequest
	}
	defs, err := syscalls.ArgumentDefinitions(r.Names, r.CaptureBuffers, r.MaxBytesPerEvent)
	if err != nil || r.BytesPerSecond/syscalls.ArgumentMaxProbeBytes(defs) == 0 {
		return nil, ErrArgumentRequest
	}
	return defs, nil
}

// ArgumentBudgetFor uses one conservative event-rate bucket for BOTH authored
// byte and event ceilings. Cheap probes can leave byte credit unused; rates and
// cumulative credit never increase to compensate. Boot time is sampled by loader.
func ArgumentBudgetFor(r ArgumentRequest, now time.Time, bootNS uint64) (ArgumentBudget, error) {
	defs, err := r.definitions()
	remaining := r.Deadline.Sub(now)
	if err != nil || !now.Before(r.StartBy) || bootNS == 0 || remaining <= 0 || remaining > time.Hour || uint64(remaining) > ^uint64(0)-bootNS {
		return ArgumentBudget{}, ErrArgumentRequest
	}
	maximum := syscalls.ArgumentMaxProbeBytes(defs)
	effective := min(r.EventsPerSecond, r.BytesPerSecond/maximum)
	interval := (uint64(time.Second) + effective - 1) / effective
	return ArgumentBudget{Events: r.Events, Bytes: r.Bytes, DeadlineBootNS: bootNS + uint64(remaining), MaxProbeBytes: maximum, RateIntervalNS: interval, RateBurstNS: (effective - 1) * interval}, nil
}

// ArgumentRecorder is process-local one-shot ownership, not grant issuance.
// A failed/unknown run consumes this instance; another process may not reconstruct
// it from historical output. Durable exact executor fencing belongs to admission.
type ArgumentRecorder struct {
	request ArgumentRequest
	used    atomic.Bool
}

func NewArgumentRecorder(r ArgumentRequest) (*ArgumentRecorder, error) {
	if _, err := r.definitions(); err != nil {
		return nil, err
	}
	r.Names = append([]string(nil), r.Names...)
	return &ArgumentRecorder{request: r}, nil
}
func (r *ArgumentRecorder) Capture(ctx context.Context, deliver func([]byte), notice func(InputNotice)) (ArgumentStats, error) {
	if r == nil || !r.used.CompareAndSwap(false, true) {
		return ArgumentStats{}, ErrArgumentReplay
	}
	if ctx == nil || ctx.Err() != nil || deliver == nil {
		return ArgumentStats{}, ErrArgumentRequest
	}
	return traceArguments(ctx, r.request, deliver, notice)
}
