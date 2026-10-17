package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// ConfigurationWorkerLaunchOperation belongs to exactly one fresh worker2
// launch or historical acknowledgement. Its only constructor is private to
// the original input producer. The concrete SQL adapter cannot replace its
// source/native phases with an interface or caller-created observation.
type ConfigurationWorkerLaunchOperation struct {
	self                                               *ConfigurationWorkerLaunchOperation
	worker                                             *ConfigurationWorkerOperation
	roleObject                                         *core.Secret
	plan                                               configurationWorkerLaunchPlan
	mode                                               configurationWorkerLaunchMode
	observed                                           contracts.ConfigurationRuntimeLaunchReceipt
	result                                             ConfigurationWorkerLaunchAdvance
	intentUncertain, effectAttempted, receiptAttempted bool
}

type ConfigurationWorkerLaunchProgress uint8

const (
	ConfigurationWorkerLaunchPending ConfigurationWorkerLaunchProgress = iota + 1
	ConfigurationWorkerLaunchAcknowledged
	ConfigurationWorkerLaunchSpent
)

type ConfigurationWorkerLaunchAdvance struct {
	Progress                          ConfigurationWorkerLaunchProgress
	Snapshot                          contracts.ConfigurationRuntimeRoleSnapshot
	receiptUncertain, needsInspection bool
}

type configurationWorkerLaunchMode uint8

const (
	configurationWorkerLaunchUpdate configurationWorkerLaunchMode = iota + 1
	configurationWorkerLaunchReceipt
	configurationWorkerLaunchInspect
	configurationWorkerLaunchObservePending
)

func newConfigurationWorkerLaunchOperation(owner *ConfigurationWorkerInputs, ctx context.Context) (*ConfigurationWorkerLaunchOperation, error) {
	worker, err := newConfigurationWorkerOperation(owner, ctx)
	if err != nil {
		return nil, err
	}
	operation := &ConfigurationWorkerLaunchOperation{worker: worker}
	operation.self = operation
	return operation, nil
}

func (p *ConfigurationWorkerLaunchOperation) enter(ctx context.Context, root *ConfigurationRuntimeRoleRoot, from, to configurationWorkerPhase) (context.Context, func(error), error) {
	if p == nil || p.self != p || p.worker == nil {
		return nil, nil, cfg.ErrUnavailable
	}
	return p.worker.enterPhase(ctx, root, from, to)
}

func (p *ConfigurationWorkerLaunchOperation) close() {
	if p == nil || p.worker == nil {
		return
	}
	p.worker.close() // Cancels and joins every admitted phase before local wiping.
	if p.roleObject != nil {
		clearRuntimeProjection(p.roleObject.Data)
		p.roleObject = nil
	}
}

// This is a positive observation of the exact original running body, not an
// assertion about when an unknown update committed. Old launch authority is
// never extended or reused by a new receipt observation.
func (p *ConfigurationWorkerLaunchOperation) observeRunning(native configurationWorkerNative, roles contracts.ConfigurationRuntimeRoleSnapshot) error {
	if _, ok := configurationWorkerOriginalLaunchSources(native.proof.observation, native.deployment, roles); !ok {
		return cfg.ErrChanged
	}
	child := p.worker.retained.resources.State.WorkerInputs
	launch := roles.State.Launch
	if child == nil || child.Receipt == nil || launch.Configuration != child.Receipt.Configuration || launch.Providers != child.AuditCredentials ||
		!configurationProviderLaunchMounts(native.deployment, p.worker.input, launch) {
		return cfg.ErrChanged
	}
	now := p.worker.owner.resources.now().UTC().Truncate(time.Microsecond)
	if now.Before(launch.ClaimedAt) || !now.Before(p.worker.retained.resources.State.Until) || !now.Before(roles.State.Until) {
		return cfg.ErrUnavailable
	}
	receipt := contracts.ConfigurationRuntimeLaunchReceipt{ResourceVersion: native.deployment.ResourceVersion, ObservedAt: now}
	if launch.Receipt != nil {
		// A controller status write can advance RV after the historical receipt.
		// The complete original launched spec/identity remains independently checked;
		// never overwrite the first receipt with that later metadata version.
		receipt = *launch.Receipt
	}
	p.observed = receipt
	return nil
}
