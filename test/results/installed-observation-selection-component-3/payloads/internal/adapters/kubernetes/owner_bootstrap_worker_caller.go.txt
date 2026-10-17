package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerBootstrapWorkerCaller is public installation provenance, not runtime
// authorization. The observation backend must persist this exact pin with its
// own original receipt and independently verify every current caller. No Pod or
// ReplicaSet identity exists here: the original Deployment is their controller
// anchor, and their actual identities belong to online runtime observation.
type OwnerBootstrapWorkerCaller struct {
	Pin                                                    fleet.ClusterObservationCallerPin
	Resources, Selection, ConfigurationRoot                contracts.WorkerObjectReference
	ResourceSetupID, ResourceBinding                       string
	SelectionOperationID, SelectionPublicDigest            string
	ConfigurationSetupID, WorkerInputID, LaunchOperationID string
	ObservedAt, FreshUntil                                 time.Time
}

// OwnerBootstrapObservationParticipants retains the independently checked original
// owner and HWORK provenance under one native operation. It is deliberately an
// ephemeral value: the complete backend producer must bind it with its regional
// configuration before publishing its own immutable projection and receipt.
// Neither pin includes an invented Pod/ReplicaSet or grants runtime authority.
type OwnerBootstrapObservationParticipants struct {
	Caller OwnerBootstrapWorkerCaller
	Owner  fleet.OwnerObservationPin
}

// ReadObservationParticipants is selected only by the original v2 resource root.
// It uses the same two real native brackets as ReadWorkerCaller, not a subsequent
// observation that could replace or renew either participant's original facts.
func (s *OwnerBootstrapSelectionProducer) ReadObservationParticipants(ctx context.Context) (OwnerBootstrapObservationParticipants, error) {
	if s == nil || s.root == nil || s.root.resources == nil || s.root.resources.observationFormat != contracts.OwnerObservationOperationFormat {
		return OwnerBootstrapObservationParticipants{}, cfg.ErrUnavailable
	}
	return s.readWorkerCallerParticipants(ctx, true)
}

// ReadWorkerCaller derives the sole installed HWORK caller from acknowledged
// original resources, selection and launch. It does not create or acknowledge
// anything. Both native brackets are genuine; the private configuration journal
// and public selection child are read once in each bracket. Credentials from
// that administrator-only journal never enter the returned public value.
func (s *OwnerBootstrapSelectionProducer) ReadWorkerCaller(ctx context.Context) (OwnerBootstrapWorkerCaller, error) {
	out, err := s.readWorkerCallerParticipants(ctx, false)
	return out.Caller, err
}

func (s *OwnerBootstrapSelectionProducer) readWorkerCallerParticipants(ctx context.Context, includeOwner bool) (OwnerBootstrapObservationParticipants, error) {
	var zero, out OwnerBootstrapObservationParticipants
	call, release, err := s.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer release()
	started := s.root.resources.now()
	err = s.root.providerOperation(call, false, func(bounded context.Context) (ownerIdentityOperationNative, error) {
		return s.root.readOwnerIdentityOperationNative(bounded, s.root.input.LayoutDigest, false)
	}, func(bounded context.Context, first ownerIdentityOperationNative) error {
		current, stop := context.WithDeadline(bounded, first.until)
		defer stop()
		firstPin, firstRoles, err := s.readWorkerCallerParticipantsOriginals(current, first, includeOwner)
		if err != nil {
			return err
		}
		last, err := s.root.readOwnerIdentityOperationNative(current, s.root.input.LayoutDigest, false)
		if err != nil {
			if initialHandoverDeadline(current, s.root.resources.now, first.until) != nil {
				return cfg.ErrUnavailable
			}
			return err
		}
		until := identity.Earlier(first.until, last.until)
		if initialHandoverDeadline(current, s.root.resources.now, until) != nil {
			return cfg.ErrUnavailable
		}
		if !ownerIdentityOperationOriginalsEqual(first, last) {
			return cfg.ErrChanged
		}
		final, end := context.WithDeadline(current, until)
		defer end()
		lastPin, lastRoles, err := s.readWorkerCallerParticipantsOriginals(final, last, includeOwner)
		if initialHandoverDeadline(final, s.root.resources.now, until) != nil {
			return cfg.ErrUnavailable
		}
		if err != nil {
			return err
		}
		if firstPin != lastPin || firstRoles.UID != lastRoles.UID || firstRoles.ResourceVersion != lastRoles.ResourceVersion || !equalJSON(firstRoles.State, lastRoles.State) {
			return cfg.ErrChanged
		}
		lastPin.Caller.ObservedAt, lastPin.Caller.FreshUntil = started, until
		out = lastPin
		return nil
	})
	if err != nil || initialHandoverDeadline(call, s.root.resources.now, out.Caller.FreshUntil) != nil {
		if err == nil {
			err = cfg.ErrUnavailable
		}
		return zero, err
	}
	return out, nil
}

func (s *OwnerBootstrapSelectionProducer) readWorkerCallerOriginals(ctx context.Context, current ownerIdentityOperationNative) (OwnerBootstrapWorkerCaller, contracts.ConfigurationRuntimeRoleSnapshot, error) {
	var zero OwnerBootstrapWorkerCaller
	var noRoles contracts.ConfigurationRuntimeRoleSnapshot
	state := current.retained.resources.State
	p := state.OwnerBootstrap
	if p == nil || p.Child == nil || p.Child.Receipt == nil || state.WorkerInputs == nil || state.WorkerInputs.Receipt == nil || !s.originalAttempt(p) {
		return zero, noRoles, cfg.ErrUnavailable
	}
	body, err := ownerBootstrapBody(s.root, p, s.plan)
	if err != nil || !ownerBootstrapBodyBound(s.root, p, body) {
		return zero, noRoles, cfg.ErrChanged
	}
	phase := &ownerBootstrapPhase{producer: s, initial: current, snapshot: current.retained.resources, body: body, until: current.until}
	if _, err = phase.readChild(ctx); err != nil {
		return zero, noRoles, err
	}
	roles, err := s.root.readOwnerWorkerCallerRoles(ctx, current)
	if err != nil {
		return zero, noRoles, err
	}
	pin, err := s.root.ownerWorkerCallerOriginals(ctx, current, roles, body)
	if err != nil {
		return zero, noRoles, err
	}
	return pin, roles, nil
}

// The v2 owner derivation consumes responses from this exact admitted bracket;
// it makes no API call, no SQL query and no clock sample of its own.
func (s *OwnerBootstrapSelectionProducer) readWorkerCallerParticipantsOriginals(ctx context.Context, current ownerIdentityOperationNative, includeOwner bool) (OwnerBootstrapObservationParticipants, contracts.ConfigurationRuntimeRoleSnapshot, error) {
	var zero OwnerBootstrapObservationParticipants
	caller, roles, err := s.readWorkerCallerOriginals(ctx, current)
	if err != nil {
		return zero, roles, err
	}
	out := OwnerBootstrapObservationParticipants{Caller: caller}
	if includeOwner {
		out.Owner, err = s.root.ownerObservationParticipant(current, caller)
		if err != nil {
			return zero, roles, err
		}
	}
	return out, roles, nil
}
