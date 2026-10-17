package kubernetes

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// ConfigurationWorkerInputProgress describes configuration progress, never
// runtime authority. Pending is a positively read original object awaiting an
// independent receipt phase. Spent means the original opportunity was retained
// without a positive recoverable result; it does not assert that no effect ran.
type ConfigurationWorkerInputProgress uint8

const (
	ConfigurationWorkerInputPending ConfigurationWorkerInputProgress = iota + 1
	ConfigurationWorkerInputAcknowledged
	ConfigurationWorkerInputSpent
)

type ConfigurationWorkerInputAdvance struct {
	Progress         ConfigurationWorkerInputProgress
	Snapshot         contracts.InitialRuntimeResourceSnapshot
	receiptUncertain bool
	needsInspection  bool
}

// ConfigurationWorkerOperation is made only by one live private Advance.
// Its zero value grants nothing. The concrete SQL verifier pins the original
// root and calls the named post-lock/effect/final methods, never a caller's
// authority callback. Fields and constructor remain private to this adapter.
// It cannot implement the legacy root/source reader from retained values.
type ConfigurationWorkerOperation struct {
	mu               sync.Mutex
	owner            *ConfigurationWorkerInputs
	ctx              context.Context
	cancel           context.CancelFunc
	until            time.Time
	phase            configurationWorkerPhase
	busy             bool
	changed          chan struct{}
	seed             configurationWorkerSeed
	input            contracts.HubWorkerDeployment
	digest           string
	raw              []byte
	setup            providerconfig.ConfigurationSetupCheck
	native           configurationWorkerNative
	retained         initialRuntimeRetainedResources
	roles            contracts.ConfigurationRuntimeRoleSnapshot
	ownerAccount     core.ServiceAccount
	audit            core.Secret
	mode             configurationWorkerEffect
	observedInput    contracts.ConfigurationWorkerInputReceipt
	result           ConfigurationWorkerInputAdvance
	receiptAttempted bool
	intentUncertain  bool
	effectAttempted  bool
}

// This key binds SQL-derived child contexts to the already concrete handle;
// it never selects a reader implementation or returns cached authority.
type configurationWorkerContextKey struct{}

func newConfigurationWorkerOperation(owner *ConfigurationWorkerInputs, ctx context.Context) (*ConfigurationWorkerOperation, error) {
	if owner == nil || owner.roles == nil || owner.resources == nil || ctx == nil || ctx.Err() != nil {
		return nil, cfg.ErrUnavailable
	}
	until, ok := ctx.Deadline()
	now := owner.resources.now()
	if !ok || !now.Before(until) || until.After(now.Add(5*time.Second)) {
		return nil, cfg.ErrUnavailable
	}
	owner.mu.Lock()
	owned := owner.busy && !owner.closed && owner.ctx != nil && owner.ctx.Err() == nil
	owner.mu.Unlock()
	if !owned {
		return nil, cfg.ErrUnavailable
	}
	live, cancel := context.WithCancel(ctx)
	p := &ConfigurationWorkerOperation{owner: owner, until: until, cancel: cancel, changed: make(chan struct{})}
	p.ctx = context.WithValue(live, configurationWorkerContextKey{}, p)
	return p, nil
}

type configurationWorkerEffect uint8

const (
	configurationWorkerEffectCreate configurationWorkerEffect = iota + 1
	configurationWorkerEffectReceipt
	configurationWorkerEffectInspect
	configurationWorkerEffectObservePending
)

type configurationWorkerPhase uint8

const (
	configurationWorkerPhaseUninitialized configurationWorkerPhase = iota
	configurationWorkerPhaseInitial
	configurationWorkerPhaseIntent
	configurationWorkerPhasePostLock
	configurationWorkerPhaseEffect
	configurationWorkerPhaseFinal
	configurationWorkerPhaseJoined
	configurationWorkerPhaseFailed
)

// phase enters one named phase under the original operation ownership. There
// is no timestamp supplied by a SQL caller and no new context deadline. A bad
// call poisons this handle permanently, including concurrent/out-of-order use.
func (p *ConfigurationWorkerOperation) enterPhase(ctx context.Context, root *ConfigurationRuntimeRoleRoot, from, to configurationWorkerPhase) (context.Context, func(error), error) {
	if p == nil || ctx == nil {
		return nil, nil, cfg.ErrUnavailable
	}
	p.mu.Lock()
	owned := false
	if p.owner != nil {
		// Admit under the same mutex as external producer Close. Cancellation
		// callbacks are joined, but their scheduling cannot admit another phase
		// after Close has already marked the actual owner closed.
		p.owner.mu.Lock()
		owned = p.owner.busy && !p.owner.closed && p.owner.ctx != nil && p.owner.ctx.Err() == nil
		p.owner.mu.Unlock()
	}
	valid := owned && p.owner.roles == root && root != nil && p.ctx != nil && p.ctx.Err() == nil && ctx.Err() == nil &&
		p.phase == from && !p.busy && p.changed != nil && p.cancel != nil && ctx.Value(configurationWorkerContextKey{}) == p && !p.until.IsZero() && p.owner.resources != nil && p.owner.resources.now().Before(p.until)
	if valid {
		// Admission after either ownership mutex may only shorten the original
		// operation. A later phase using the original longer context cannot
		// recover time surrendered by this actual SQL/native caller.
		if until, ok := ctx.Deadline(); ok && until.Before(p.until) {
			p.until = until
		}
		valid = ctx.Err() == nil && p.ctx.Err() == nil && p.owner.resources.now().Before(p.until)
	}
	if !valid {
		p.phase = configurationWorkerPhaseFailed
		if p.cancel != nil {
			p.cancel()
		}
		p.mu.Unlock()
		return nil, nil, cfg.ErrUnavailable
	}
	p.busy = true
	p.mu.Unlock()
	// The caller's earlier end now belongs to the entire operation. Original
	// cancellation is also joined; a detached caller cannot keep it alive.
	call, cancel := context.WithDeadline(ctx, p.until)
	joined := make(chan struct{})
	stop := context.AfterFunc(p.ctx, func() { cancel(); close(joined) })
	return call, func(err error) {
		cancel()
		if !stop() {
			<-joined
		}
		p.mu.Lock()
		if err != nil || p.ctx.Err() != nil || ctx.Err() != nil || !p.owner.resources.now().Before(p.until) || p.phase != from {
			p.phase = configurationWorkerPhaseFailed
			p.cancel()
		} else {
			p.phase = to
		}
		p.busy = false
		if p.changed != nil {
			close(p.changed)
			p.changed = make(chan struct{})
		}
		p.mu.Unlock()
	}, nil
}

func (p *ConfigurationWorkerOperation) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.phase = configurationWorkerPhaseFailed
	if p.cancel != nil {
		p.cancel()
	}
	for p.busy {
		changed := p.changed
		p.mu.Unlock()
		<-changed
		p.mu.Lock()
	}
	clearRuntimeProjection(p.audit.Data)
	p.audit = core.Secret{}
	p.seed.roleState = contracts.ConfigurationRuntimeRoleState{}
	p.roles = contracts.ConfigurationRuntimeRoleSnapshot{}
	clear(p.raw)
	p.raw = nil
	p.mu.Unlock()
}
