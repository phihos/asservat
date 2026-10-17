package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// InitialPreparedInputs is public provenance plus its original current read
// bound. It cannot activate SQL or substitute for the independent final guards.
type InitialPreparedInputs struct {
	Configuration contracts.InitialInstaller
	Input         contracts.WorkerObjectReference
	ValidUntil    time.Time
}

// ReadPreparedInputs performs only exact reads of the acknowledged original
// nine inputs and gated Pod. It never completes a pending CREATE, chooses a new
// identity or extends an earlier observation's deadline.
func (s *InitialPreparer) ReadPreparedInputs(ctx context.Context) (InitialPreparedInputs, error) {
	var zero InitialPreparedInputs
	if s == nil || s.services == nil || ctx == nil {
		return zero, cfg.ErrInvalid
	}
	ctx, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return zero, e
	}
	defer joined()
	until, e := s.current(ctx)
	if e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	root, _, e := s.originalPrivateScope(ctx)
	if e != nil {
		return zero, e
	}
	if root.Activation.Inputs == nil || root.Activation.Inputs.IntentDigest != preparationDigest(*s.services) || len(root.Activation.Inputs.Creates) != 9 {
		return zero, cfg.ErrChanged
	}
	for i, entry := range root.Activation.Inputs.Creates {
		if entry.Receipt == nil {
			return zero, cfg.ErrUnavailable
		}
		object, e := s.publicInputResource(root, i)
		if e != nil || entry.SpecDigest != object.digest {
			return zero, cfg.ErrChanged
		}
		raw, e := s.creator.raw(ctx, object.path+"/"+entry.Name, nil)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		if _, e = s.verifyPublicInput(raw, object, entry); e != nil {
			return zero, e
		}
	}
	config, e := s.inputConfiguration(root)
	if e != nil {
		return zero, e
	}
	// Return an independent public value; provider roots must not alias the
	// constructor-owned immutable desired services through a returned slice.
	raw, e := json.Marshal(config)
	if e != nil {
		return zero, cfg.ErrInvalid
	}
	var independent contracts.InitialInstaller
	if json.Unmarshal(raw, &independent) != nil {
		return zero, cfg.ErrInvalid
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	input := root.Activation.Inputs.Creates[8]
	return InitialPreparedInputs{Configuration: independent, Input: contracts.WorkerObjectReference{Name: input.Name, UID: input.Receipt.UID}, ValidUntil: until}, nil
}
