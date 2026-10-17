package kubernetes

import (
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"github.com/google/uuid"
	"time"
)

func (s *ConfigurationWorkerInputs) observe(ctx context.Context, completed bool) (contracts.InitialRuntimeResourceSnapshot, error) {
	var out contracts.InitialRuntimeResourceSnapshot
	call, finish, err := s.enter(ctx)
	if err != nil {
		return out, err
	}
	defer finish()
	call, release, err := s.resources.borrowWorkerProjection(call)
	if err != nil {
		return out, err
	}
	defer release()
	err = s.roles.WithConfigurationRoleOperation(call, func(live context.Context) error {
		var verified contracts.ConfigurationRuntimeRoleSnapshot
		var e error
		if completed {
			verified, e = s.verification.VerifyLaunchedConfigurationRuntimeRoles(live)
		} else {
			verified, e = s.verification.VerifyConfigurationRuntimeRoles(live)
		}
		if e != nil {
			return e
		}
		if verified.State.Input != s.roles.input || !s.resources.now().Before(verified.ValidUntil) {
			return cfg.ErrUnavailable
		}
		live, end := context.WithDeadline(live, verified.ValidUntil)
		defer end()
		// Provisional public bytes confer no authority. Read them outside the SQL
		// bridge callback so external Bao inspection never holds its recovery locks.
		provisional, _, e := s.resources.read(live)
		if e != nil {
			return e
		}
		operation := uuid.NewString()
		if provisional.State.WorkerInputs != nil {
			operation = provisional.State.WorkerInputs.OperationID
		}
		input, digest, raw, e := s.resources.configurationWorkerInputMaterial(provisional, verified, operation, s.resources.now())
		if e != nil {
			return e
		}
		var check providerconfig.ConfigurationSetupCheck
		if !completed {
			check, e = s.setup.VerifyConfiguration(live, input, *input.ProviderAuthentication)
			if e != nil {
				return e
			}
			var narrow context.CancelFunc
			live, narrow = context.WithDeadline(live, check.FreshUntil())
			defer narrow()
		}
		// Both external inspection and SQL role verification have returned before
		// the bridge obtains its independent recovery/activation locks. The original
		// provider interval is never refreshed inside or after this callback.
		return s.bridge.operation(live, func(bound context.Context) error {
			current, object, e := s.readResources(bound)
			if e != nil {
				return e
			}
			if current.UID != provisional.UID || !equalJSON(current.State, provisional.State) {
				return cfg.ErrChanged
			}
			if e = s.currentRoles(bound, verified, completed); e != nil {
				return e
			}
			actualInput, actualDigest, _, e := s.resources.configurationWorkerInputMaterial(current, verified, operation, s.resources.now())
			if e != nil {
				return e
			}
			if actualDigest != digest || !equalJSON(actualInput, input) {
				return cfg.ErrChanged
			}
			p := current.State.WorkerInputs
			if completed && (p == nil || p.Receipt == nil) {
				return cfg.ErrUnavailable
			}
			if p != nil && (p.PublicDigest != digest || !equalJSON(input.ProviderInputs, configurationWorkerInputProvenance(p)) || p.AuditCredentials != input.ProviderAuthentication.AuditCredentials) {
				return cfg.ErrChanged
			}
			if completed {
				if _, e = s.readInput(bound, current, raw); e != nil {
					return e
				}
				after, _, e := s.readResources(bound)
				if e != nil {
					return e
				}
				if !equalJSON(after.State.WorkerInputs, p) {
					return cfg.ErrChanged
				}
				if e = s.currentRoles(bound, verified, true); e != nil {
					return e
				}
				out = after
				return nil
			}
			if e = s.currentAuditCredentials(bound, input); e != nil {
				return e
			}
			if !check.Matches(input, *input.ProviderAuthentication, s.resources.now()) {
				return cfg.ErrUnavailable
			}
			fresh := p == nil
			if fresh {
				if s.attempted || verified.State.Launch != nil {
					return cfg.ErrUnavailable
				}
				now := s.resources.now().UTC().Truncate(time.Microsecond)
				until, _ := bound.Deadline()
				until = identity.Earlier(until, current.State.Until).UTC().Truncate(time.Microsecond)
				if !now.Before(until) {
					return cfg.ErrUnavailable
				}
				next := current.State
				next.WorkerInputs = &contracts.ConfigurationWorkerInputClaim{OperationID: operation, PublicDigest: digest,
					ConfigurationRoot: input.ProviderInputs.ConfigurationRoot, ConfigurationSetupID: input.ProviderInputs.ConfigurationSetupID,
					SQLProjection: input.ProviderInputs.SQLProjection, AuditCredentials: input.ProviderAuthentication.AuditCredentials, ClaimedAt: now, Until: until}
				// Set before I/O. Even an unknown CAS cannot authorize a second claim in
				// this instance; reopening can only observe the same persisted attempt.
				s.attempted = true
				current, e = s.write(bound, current, object, next, until)
				if e != nil {
					return e
				}
				p = current.State.WorkerInputs
				var narrow context.CancelFunc
				bound, narrow = context.WithDeadline(bound, p.Until)
				defer narrow()
				if e = s.currentRoles(bound, verified, false); e != nil {
					return e
				}
				if !check.Matches(input, *input.ProviderAuthentication, s.resources.now()) {
					return cfg.ErrUnavailable
				}
				if e = s.createInput(bound, current, raw); e != nil {
					return e
				}
			}
			receipt, e := s.readInput(bound, current, raw)
			if e != nil {
				return e
			}
			after, obj, e := s.readResources(bound)
			if e != nil {
				return e
			}
			if !equalJSON(after.State.WorkerInputs, p) {
				return cfg.ErrChanged
			}
			if e = s.currentRoles(bound, verified, false); e != nil {
				return e
			}
			if e = s.currentAuditCredentials(bound, input); e != nil {
				return e
			}
			if !check.Matches(input, *input.ProviderAuthentication, s.resources.now()) {
				return cfg.ErrUnavailable
			}
			if p.Receipt == nil {
				next := after.State
				copied := *p
				copied.Receipt = &receipt
				next.WorkerInputs = &copied
				until, _ := bound.Deadline()
				after, e = s.write(bound, after, obj, next, identity.Earlier(until, after.State.Until))
				if e != nil {
					return e
				}
			}
			// Post-effect current source/bridge and SQL identity checks remain required.
			last, _, e := s.readResources(bound)
			if e != nil {
				return e
			}
			if !equalJSON(last.State.WorkerInputs, after.State.WorkerInputs) {
				return cfg.ErrChanged
			}
			if e = s.currentRoles(bound, verified, false); e != nil {
				return e
			}
			if !check.Matches(input, *input.ProviderAuthentication, s.resources.now()) {
				return cfg.ErrUnavailable
			}
			out = last
			return nil
		})
	})
	if err != nil || call.Err() != nil {
		if err == nil {
			err = cfg.ErrUnavailable
		}
		return contracts.InitialRuntimeResourceSnapshot{}, err
	}
	return out, nil
}
