package kms

import (
	"context"
	"net/http"
	"time"
)

// The fixed pair shares the existing lease transport, never an owner credential
// or PKI effect. Effect calls cannot trigger login or renew their borrowed token.
type configurationProviderEffects struct {
	wrap, unwrap *ownerProviderLifetime
	cleanup      [4]*ownerProviderLifetime
	seal         *Sealer
	open         *Opener
	cancel       context.CancelFunc
}

func newConfigurationProviderEffects(ctx context.Context, in ConfigurationProviderInput, jwt TokenSource, proof ownerProviderCurrent, client *http.Client, now func() time.Time) (*configurationProviderEffects, error) {
	if ctx == nil || ctx.Err() != nil || jwt == nil || proof == nil || now == nil {
		return nil, ErrKeyService
	}
	root, cancel := context.WithCancel(ctx)
	out := &configurationProviderEffects{cancel: cancel}
	complete := false
	defer func() {
		if !complete {
			_ = out.close(context.Background())
		}
	}()
	// One serialized audit operation per worker purpose. Two retained processes
	// and the independently scoped SQL1 pools remain the installed envelope.
	for _, fixed := range []struct {
		purpose string
		target  **ownerProviderLifetime
		role    string
	}{{"audit-wrap", &out.wrap, in.Roles.AuditWrap}, {"audit-unwrap", &out.unwrap, in.Roles.AuditUnwrap}} {
		control, err := newConfigurationProviderControl(in, fixed.role, client, now)
		if err != nil {
			return nil, err
		}
		slot, err := newOwnerProviderLifetime(root, control, jwt, proof, 1)
		if err != nil {
			control.close()
			return nil, err
		}
		*fixed.target = slot
	}
	if in.cleanup() {
		for i, role := range []string{in.Roles.CleanupWrap, in.Roles.CleanupOpen, in.Roles.CleanupVerify, in.Roles.CleanupSign} {
			control, err := newConfigurationProviderControl(in, role, client, now)
			if err != nil {
				return nil, err
			}
			slot, err := newOwnerProviderLifetime(root, control, jwt, proof, 1)
			if err != nil {
				control.close()
				return nil, err
			}
			out.cleanup[i] = slot
		}
	}
	wrap, err := newOwnerProviderEffectClient(out.wrap, in.AuditMount+"/encrypt/"+in.AuditKey)
	if err != nil {
		return nil, err
	}
	out.seal = &Sealer{client: wrap, mount: in.AuditMount, key: in.AuditKey, reference: in.AuditMount + "/" + in.AuditKey}
	unwrap, err := newOwnerProviderEffectClient(out.unwrap, in.AuditMount+"/decrypt/"+in.AuditKey)
	if err != nil {
		return nil, err
	}
	out.open = &Opener{client: unwrap, mount: in.AuditMount, key: in.AuditKey, reference: in.AuditMount + "/" + in.AuditKey}
	complete = true
	return out, nil
}

func (s *configurationProviderEffects) close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrKeyService
	}
	s.cancel()
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	var result error
	for _, slot := range s.slots() {
		if slot != nil {
			if err := slot.close(call); err != nil {
				result = ErrKeyService
			}
		}
	}
	if result != nil {
		return result
	} // outstanding ownership remains retained
	if s.seal != nil {
		s.seal.Close()
	}
	if s.open != nil {
		s.open.Close()
	}
	return nil
}

// joinClosed uses the shared purpose-owned lifetime finalizer. It joins local
// control/body ownership without issuing another provider revocation request.
func (s *configurationProviderEffects) joinClosed() {
	if s == nil {
		return
	}
	s.cancel()
	for _, slot := range s.slots() {
		if slot != nil {
			slot.joinClosed()
		}
	}
	if s.seal != nil {
		s.seal.Close()
	}
	if s.open != nil {
		s.open.Close()
	}
}

func (s *configurationProviderEffects) slots() []*ownerProviderLifetime {
	return append([]*ownerProviderLifetime{s.wrap, s.unwrap}, s.cleanup[:]...)
}
func (s *configurationProviderEffects) cleanupSlot(slot *ownerProviderLifetime) bool {
	if slot == nil {
		return false
	}
	for _, candidate := range s.cleanup {
		if candidate == slot {
			return true
		}
	}
	return false
}
