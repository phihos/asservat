package kubernetes

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The existing SQL producer implements both fixed read-only verifications.
// The second cannot issue roles or import a replacement credential after launch.
type ConfigurationWorkerRoleVerification interface {
	VerifyConfigurationRuntimeRoles(context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error)
	VerifyLaunchedConfigurationRuntimeRoles(context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error)
}

// ConfigurationWorkerInputs publishes one public ConfigMap under the original
// retained bridge and exposes the separate original launch/acknowledgement phases.
// It cannot qualify S3 backend capability or repair an uncertain launch.
// The externally owned roots/readers are borrowed through the complete call.
type ConfigurationWorkerInputs struct {
	bridge                  *InitialRuntimeBridge
	resources               *InitialRuntimeResources
	roles                   *ConfigurationRuntimeRoleRoot
	verification            ConfigurationWorkerRoleVerification
	setup                   *providerconfig.SetupReader
	original                contracts.InitialRuntimeResourceSnapshot
	ctx                     context.Context
	cancel                  context.CancelFunc
	mu                      sync.Mutex
	closed, busy, attempted bool
	launchAttempted         bool
	joined                  sync.WaitGroup
}

func NewConfigurationWorkerInputs(ctx context.Context, bridge *InitialRuntimeBridge, resources *InitialRuntimeResources, roles *ConfigurationRuntimeRoleRoot, verification ConfigurationWorkerRoleVerification, setup *providerconfig.SetupReader, original contracts.InitialRuntimeResourceSnapshot) (*ConfigurationWorkerInputs, error) {
	if ctx == nil || ctx.Err() != nil || bridge == nil || resources == nil || roles == nil || verification == nil || setup == nil ||
		resources.preparer != bridge.preparer || resources.rootUID != bridge.rootUID || !equalJSON(resources.initial, bridge.initial) ||
		roles.source != bridge.source || roles.input.InitialClaimID != bridge.record.Claim.ID ||
		!authorization.UUID(original.UID) || !resources.valid(original.State) || len(original.State.Objects) != contracts.InitialRuntimeResourceCount ||
		original.State.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || original.State.OwnerLayout != contracts.OwnerProviderInstalledLayout {
		return nil, cfg.ErrInvalid
	}
	for _, item := range original.State.Objects {
		if item.Receipt == nil {
			return nil, cfg.ErrInvalid
		}
	}
	// Copy only the original public parent facts. Child states may progress but
	// cannot change these values; no verified interval is retained across calls.
	var pinned contracts.InitialRuntimeResourceSnapshot
	raw, err := json.Marshal(original)
	if err != nil || len(raw) > contracts.InitialRuntimeResourcesMaxBytes+4096 || json.Unmarshal(raw, &pinned) != nil {
		return nil, cfg.ErrInvalid
	}
	life, cancel := context.WithCancel(ctx)
	return &ConfigurationWorkerInputs{bridge: bridge, resources: resources, roles: roles, verification: verification, setup: setup, original: pinned, ctx: life, cancel: cancel}, nil
}

func (s *ConfigurationWorkerInputs) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.joined.Wait()
}

func (s *ConfigurationWorkerInputs) enter(ctx context.Context) (context.Context, func(), error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, cfg.ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.busy || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, nil, cfg.ErrUnavailable
	}
	s.busy = true
	s.joined.Add(1)
	s.mu.Unlock()
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	joined := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { cancel(); close(joined) })
	return call, func() {
		cancel()
		if !stop() {
			<-joined
		}
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
		s.joined.Done()
	}, nil
}

// Publish never switches to a launched verifier after a failure. A persisted
// launch is inspection-only and is handled by ReadCompleted instead.
func (s *ConfigurationWorkerInputs) Publish(ctx context.Context) (contracts.InitialRuntimeResourceSnapshot, error) {
	return s.observe(ctx, false)
}

// ReadCompleted is passive: no provider inspection, claim, CREATE or receipt
// CAS. Existing launched SQL/native verification still checks the exact current
// mounted inputs. The positive original child is independently read again; this
// path cannot repair pending publication or bootstrap a missing input.
func (s *ConfigurationWorkerInputs) ReadCompleted(ctx context.Context) (contracts.InitialRuntimeResourceSnapshot, error) {
	return s.observe(ctx, true)
}
