package kubernetes

import (
	"context"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

type configurationWorkerLaunchVerifier interface {
	WithConfigurationWorkerLaunchOperation(context.Context, *ConfigurationWorkerLaunchOperation) error
}

// AdvanceLaunch is the explicit fresh worker2 phase API. A successful first
// zero-to-one effect returns Pending, never a completed launch receipt. Later
// calls are exact historical observation/receipt only and cannot repeat PUT.
func (s *ConfigurationWorkerInputs) AdvanceLaunch(ctx context.Context) (ConfigurationWorkerLaunchAdvance, error) {
	return s.advanceLaunch(ctx, true, true)
}

func (s *ConfigurationWorkerInputs) advanceLaunch(ctx context.Context, allowNew, allowReceipt bool) (result ConfigurationWorkerLaunchAdvance, err error) {
	call, finish, err := s.enter(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	verification, ok := s.verification.(configurationWorkerLaunchVerifier)
	if !ok {
		return result, cfg.ErrUnavailable
	}
	if initialHandoverDeadline(call, s.resources.now, s.original.State.Until) != nil {
		return ConfigurationWorkerLaunchAdvance{Progress: ConfigurationWorkerLaunchSpent}, cfg.ErrUnavailable
	}
	call, release, err := s.resources.borrowWorkerProjection(call)
	if err != nil {
		return result, err
	}
	defer release()
	err = s.roles.WithConfigurationRoleOperation(call, func(original context.Context) error {
		seed, e := s.readSeed(original)
		if e != nil {
			return e
		}
		child := seed.resources.State.WorkerInputs
		if child == nil || child.Receipt == nil {
			return cfg.ErrUnavailable
		}
		if seed.roleState.Launch != nil {
			result = ConfigurationWorkerLaunchAdvance{Progress: ConfigurationWorkerLaunchSpent, Snapshot: seed.roleMaterial()}
		} else if !allowNew || s.launchAttempted {
			return cfg.ErrUnavailable
		}
		input, digest, raw, e := s.resources.configurationWorkerInputMaterial(seed.resources, seed.roleMaterial(), child.OperationID, s.resources.now())
		if e != nil {
			return e
		}
		if input.ProviderAuthentication == nil || input.ProviderInputs == nil || digest != child.PublicDigest {
			return cfg.ErrChanged
		}
		// Eight actual external GETs finish before either bridge or role SQL locks.
		// The enclosing call end already covers seed and all provider work.
		check, e := s.setup.VerifyConfiguration(original, input, *input.ProviderAuthentication)
		if e != nil {
			return e
		}
		bound, stop := context.WithDeadline(original, check.FreshUntil())
		defer stop()
		return s.bridge.operation(bound, func(bridgeCall context.Context) error {
			operation, e := newConfigurationWorkerLaunchOperation(s, bridgeCall)
			if e != nil {
				return e
			}
			defer func() {
				result.receiptUncertain = result.receiptUncertain || operation.receiptAttempted
				result.needsInspection = result.needsInspection || operation.intentUncertain || operation.effectAttempted || operation.receiptAttempted
				operation.close()
			}()
			w := operation.worker
			w.seed, w.input, w.digest, w.raw, w.setup = seed, input, digest, raw, check
			if e = operation.readInitial(w.ctx); e != nil {
				return e
			}
			if e = operation.prepareIntent(w.ctx, allowNew, allowReceipt); e != nil {
				if s.launchAttempted || w.roles.State.Launch != nil {
					result = ConfigurationWorkerLaunchAdvance{Progress: ConfigurationWorkerLaunchSpent, Snapshot: w.roles, needsInspection: operation.intentUncertain}
				}
				return e
			}
			result = ConfigurationWorkerLaunchAdvance{Progress: ConfigurationWorkerLaunchSpent, Snapshot: w.roles}
			if e = verification.WithConfigurationWorkerLaunchOperation(w.ctx, operation); e != nil {
				return e
			}
			w.mu.Lock()
			joined := w.phase == configurationWorkerPhaseJoined && !w.busy
			completed := operation.result
			w.mu.Unlock()
			if !joined || initialHandoverDeadline(w.ctx, s.resources.now, w.until) != nil {
				return cfg.ErrUnavailable
			}
			result = completed
			return nil
		})
	})
	if err != nil || call.Err() != nil {
		if err == nil {
			err = cfg.ErrUnavailable
		}
		if result.Progress != 0 {
			result.Progress = ConfigurationWorkerLaunchSpent
		}
	}
	return result, err
}

// CompleteLaunch is finite automatic configuration progress, not an unbounded
// retry loop. It keeps the same clients and never waits to refill a limiter.
// An uncertain receipt permits only one final inspection during this run.
func (s *ConfigurationWorkerInputs) CompleteLaunch(ctx context.Context) (ConfigurationWorkerLaunchAdvance, error) {
	var last ConfigurationWorkerLaunchAdvance
	run := configurationWorkerLaunchRun{}
	for {
		if ctx == nil || ctx.Err() != nil {
			return run.interrupted(), cfg.ErrUnavailable
		}
		var err error
		last, err = s.advanceLaunch(ctx, run.calls == 0, !run.receiptUncertain)
		last = run.observed(last, err)
		if err == nil && last.Progress == ConfigurationWorkerLaunchAcknowledged {
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
