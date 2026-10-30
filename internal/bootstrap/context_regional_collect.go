package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/contextstart"
)

// RegionalRecordingCollect is the hub half of the ADR-248 collect exchange.
// Every few seconds it lists started manual recordings whose recording time
// has passed and, for each, signs the capture's work for a short collect
// exchange on the ADR-171 pattern: the region answers with the held outcome
// (still recording, stored with its writer completion, or failed) and its
// current process observation; the hub records the stored completion (or
// failure) through the ordinary execution facet. No human request is needed:
// the recording was authorized at its start, and collecting acquires,
// discloses and spends nothing new.
type RegionalRecordingCollect struct {
	Runner     executionapp.APIContextRunner // Record, Recovery, Capabilities, Now
	Recordings executionapp.RecordingExecutions
	Signer     fleetapp.APIContextWorkSigner
	Router     *contextstart.Router
	Now        func() time.Time
	Report     func(string)
}

// collectInterval paces the loop; collectBatch bounds one pass.
const (
	collectInterval = 3 * time.Second
	collectBatch    = 16
	// collectMargin is how long after its recording time a capture is first
	// collected: the node's start (gadget load), upload and encryption.
	collectMargin = 2 * time.Second
)

func (s RegionalRecordingCollect) valid() bool {
	r := s.Runner
	return r.Record != nil && r.Recovery != nil && r.Capabilities != nil && s.Recordings != nil && s.Signer != nil && s.Router != nil && s.Now != nil
}

// Run collects until ctx ends.
func (s RegionalRecordingCollect) Run(ctx context.Context) error {
	if ctx == nil || !s.valid() {
		return execution.ErrInvalid
	}
	t := time.NewTicker(collectInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		ids, err := s.Recordings.StartedRecordings(ctx, s.Now().Add(-collectMargin), collectBatch)
		if err != nil {
			s.report("list", err)
			continue
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return nil
			}
			if _, err := s.Collect(ctx, id); err != nil {
				s.report("collect", err)
			}
		}
	}
}

func (s RegionalRecordingCollect) report(step string, err error) {
	if s.Report == nil {
		return
	}
	var fixed interface{ FixedStep() string }
	if errors.As(err, &fixed) {
		step += "/" + fixed.FixedStep()
	}
	s.Report(fmt.Sprintf("%s (%s)", step, regionalOutcome(err)))
}

// Collect runs one collect exchange for a started recording. A recording
// whose duration has not passed yet returns "Recording" without contacting
// the region.
func (s RegionalRecordingCollect) Collect(ctx context.Context, captureID string) (string, error) {
	if ctx == nil || !s.valid() || !authorization.UUID(captureID) {
		return "", execution.ErrInvalid
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	call, cancel := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer cancel()
	recovery, err := s.Runner.Recovery.RecoveryState(call)
	if err != nil || !recovery.Valid(s.Now()) {
		return "", execution.ErrUnavailable
	}
	w, exec, err := s.Recordings.ReadRecordingWork(call, captureID, recovery)
	if err != nil {
		return "", err
	}
	a := w.Accepted
	if a.CaptureID != captureID || a.State != capturevalue.IntentAudited || a.Expectation.Recording == nil && a.Expectation.Snapshot == nil {
		return "", execution.ErrDenied
	}
	readyAt := time.Time{}
	if a.Expectation.Snapshot != nil {
		readyAt = a.Expectation.Snapshot.T0.Add(a.Expectation.Snapshot.After)
	} else {
		readyAt = exec.StartedAt.Add(time.Duration(a.Expectation.Recording.DurationMillis) * time.Millisecond)
	}
	if s.Now().Before(readyAt) {
		return "Recording", nil
	}
	until := identity.Earlier(started.Add(5*time.Second), recovery.FreshUntil)
	target := authorization.Target{ClusterID: w.Target.ClusterID, NamespaceUID: w.Target.Namespace.UID, WorkloadUID: w.Target.Workload.UID, PodUID: w.Target.PodUID}
	capability, err := s.Runner.Capabilities.ContextCapability(call, target)
	if err != nil || !capability.Valid(s.Now()) {
		return "", execution.ErrUnavailable
	}
	until = identity.Earlier(until, capability.FreshUntil)
	attachment, err := s.Router.Attach(call, target.ClusterID, captureID)
	if err != nil {
		return "", execution.ErrUnavailable
	}
	defer attachment.Close()
	receiver, err := attachment.Receiver(call)
	if err != nil {
		return "", execution.ErrUnavailable
	}
	until = identity.Earlier(until, receiver.ValidUntil)
	if receiver.Channel.Connector.Binding.InstallationID != recovery.InstallationID || receiver.Channel.Connector.Binding.IssuerEpoch != recovery.IssuerEpoch {
		return "", execution.ErrDenied
	}
	work, err := executionapp.NewAPIContextWork(w, receiver.Channel, capability, started, until, s.Now())
	if err != nil {
		return "", err
	}
	signed, err := s.Signer.SignAPIContextWork(call, work)
	if err != nil {
		return "", err
	}
	defer clear(signed)
	state, err := attachment.Run(work, signed, func(ctx context.Context, ops *contextstart.HubOperations) (string, error) {
		r := s.Runner
		r.Process = ops
		result, err := r.CollectRecording(ctx, w, exec, ops)
		switch {
		case err == nil && (result.State == "Recording" || result.State == "StoredPendingVerification" || result.State == "Failed"):
			return result.State, nil
		}
		return "Unavailable", err
	})
	if err != nil && state == "" {
		return "", execution.ErrUnavailable
	}
	return state, err
}
