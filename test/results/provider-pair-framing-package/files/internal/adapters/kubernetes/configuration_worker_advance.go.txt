package kubernetes

import (
	"context"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/google/uuid"
)

// Only the concrete original PostgreSQL producer implements the installed
// composition. Its new method takes this adapter's opaque operation, never a
// caller-created source DTO or replacement legacy reader implementation.
type configurationWorkerAdvancementVerifier interface {
	WithConfigurationWorkerOperation(context.Context, *ConfigurationWorkerOperation) error
}

// Advance performs one explicit bounded configuration phase. A new claim may
// CREATE once and returns pending. An existing claim is lookup-only and may
// acknowledge that original immutable object under a new current observation.
// Every call retains its own original total five-second end, including provider
// inspection. No legacy Publish call is silently stretched across these phases.
func (s *ConfigurationWorkerInputs) Advance(ctx context.Context) (ConfigurationWorkerInputAdvance, error) {
	return s.advance(ctx, true, true)
}

func (s *ConfigurationWorkerInputs) advance(ctx context.Context, allowNew, allowReceipt bool) (result ConfigurationWorkerInputAdvance, err error) {
	call, finish, err := s.enter(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	verification, ok := s.verification.(configurationWorkerAdvancementVerifier)
	if !ok {
		return result, cfg.ErrUnavailable
	}
	if initialHandoverDeadline(call, s.resources.now, s.original.State.Until) != nil {
		return ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent}, cfg.ErrUnavailable
	}
	call, release, err := s.resources.borrowWorkerProjection(call)
	if err != nil {
		return result, err
	}
	defer release()
	// This outer scope owns the original native role root through every child.
	// Its legacy general reader is never invoked from retained values.
	err = s.roles.WithConfigurationRoleOperation(call, func(original context.Context) error {
		seed, err := s.readSeed(original)
		if err != nil {
			return err
		}
		operationID := uuid.NewString()
		if claim := seed.resources.State.WorkerInputs; claim != nil {
			operationID = claim.OperationID
			result = ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent, Snapshot: seed.resources}
		} else if !allowNew || s.attempted {
			return cfg.ErrUnavailable
		}
		input, digest, raw, err := s.resources.configurationWorkerInputMaterial(seed.resources, seed.roleMaterial(), operationID, s.resources.now())
		if err != nil {
			return err
		}
		if input.ProviderAuthentication == nil || input.ProviderInputs == nil {
			return cfg.ErrInvalid
		}
		// Actual external inspection is complete before ANY bridge/role lock.
		check, err := s.setup.VerifyConfiguration(original, input, *input.ProviderAuthentication)
		if err != nil {
			return err
		}
		bound, stop := context.WithDeadline(original, check.FreshUntil())
		defer stop()
		return s.bridge.operation(bound, func(bridgeCall context.Context) error {
			operation, err := newConfigurationWorkerOperation(s, bridgeCall)
			if err != nil {
				return err
			}
			defer func() {
				result.receiptUncertain = result.receiptUncertain || operation.receiptAttempted
				result.needsInspection = result.needsInspection || operation.intentUncertain || operation.effectAttempted || operation.receiptAttempted
				operation.close()
			}()
			operation.seed, operation.input, operation.digest, operation.raw, operation.setup = seed, input, digest, raw, check
			if err = operation.readInitial(operation.ctx); err != nil {
				return err
			}
			if err = operation.prepareIntent(operation.ctx, allowNew, allowReceipt); err != nil {
				if s.attempted || operation.retained.resources.State.WorkerInputs != nil {
					result = ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent, Snapshot: operation.retained.resources}
					result.needsInspection = operation.intentUncertain
				}
				return err
			}
			// From here even a role failure can leave a spent public intent.
			// It authorizes neither another CREATE nor an optimistic completion.
			result = ConfigurationWorkerInputAdvance{Progress: ConfigurationWorkerInputSpent, Snapshot: operation.retained.resources}
			if err = verification.WithConfigurationWorkerOperation(operation.ctx, operation); err != nil {
				result.receiptUncertain = operation.receiptAttempted
				result.needsInspection = operation.effectAttempted || operation.receiptAttempted
				return err
			}
			operation.mu.Lock()
			joined := operation.phase == configurationWorkerPhaseJoined && !operation.busy
			completed := operation.result
			operation.mu.Unlock()
			if !joined || initialHandoverDeadline(operation.ctx, s.resources.now, operation.until) != nil {
				return cfg.ErrUnavailable
			}
			result = completed
			result.receiptUncertain = operation.receiptAttempted
			result.needsInspection = operation.effectAttempted || operation.receiptAttempted
			return nil
		})
	})
	if err != nil || call.Err() != nil {
		if err == nil {
			err = cfg.ErrUnavailable
		}
		// The outer bridge may fail after a native write/final read. Do not return
		// its inner pending/complete value as successful current progress.
		if result.Progress != 0 {
			result.Progress = ConfigurationWorkerInputSpent
		}
		return result, err
	}
	return result, nil
}

// CompleteInputs is the fixed automatic driver, not an operator workflow or
// generic queue. At most one fresh advancement and two exact reconciliation
// calls are made with the same clients. It never sleeps to refill rate tokens,
// repeats CREATE, or extends the original journal/claim. A still-unknown result
// returns spent/unavailable; later explicit inspection remains lookup-only.
func (s *ConfigurationWorkerInputs) CompleteInputs(ctx context.Context) (ConfigurationWorkerInputAdvance, error) {
	var last ConfigurationWorkerInputAdvance
	run := configurationWorkerInputRun{}
	for {
		if ctx == nil || ctx.Err() != nil {
			return run.interrupted(), cfg.ErrUnavailable
		}
		var err error
		last, err = s.advance(ctx, run.calls == 0, !run.receiptUncertain)
		last = run.observed(last, err)
		if err == nil && last.Progress == ConfigurationWorkerInputAcknowledged {
			return last, nil
		}
		current := s != nil && s.resources != nil && s.resources.now().Before(s.original.State.Until)
		if !run.continueAfter(last, err, current) {
			if err == nil {
				err = cfg.ErrUnavailable
			}
			return last, err
		}
	}
}
