package kms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	bao "github.com/openbao/openbao/api/v2"

	"asservat.local/asservat/internal/contracts"
)

// RefreshCleanup is called only by the existing serial cleanup child, before
// entering its effect operation. Healthy credentials cost no native admission.
// Each login/renewal uses the same original native/recovery brackets as the
// configuration purposes; no periodic cleanup credential task is introduced.
func (s *InstalledConfigurationProviderEffects) RefreshCleanup(ctx context.Context) error {
	if s == nil || s.effects == nil || s.admission == nil || s.input.ProviderAuthentication == nil || s.input.ProviderAuthentication.CleanupAudit == (contracts.OwnerPublicTransit{}) {
		return ErrKeyService
	}
	for _, slot := range s.effects.cleanup {
		if slot == nil {
			return ErrKeyService
		}
		slot.mu.Lock()
		now := slot.control.now()
		old := slot.current
		healthy := old != nil && !slot.uncertain && now.Before(old.value.until) && now.Before(old.value.reauthenticateAt()) && now.Before(old.value.renewAt())
		blocked := slot.closed || slot.root.Err() != nil || slot.active
		backoff := now.Before(slot.next)
		slot.mu.Unlock()
		if healthy && !blocked {
			continue
		}
		if blocked || backoff {
			return ErrKeyService
		}
		lease, err := s.admission.WaitCleanup(ctx)
		if err != nil {
			return ErrKeyService
		}
		if err = lease.AwaitFleetObservation(); err == nil {
			err = slot.refreshOwned(lease.Context(), s)
		}
		lease.Release()
		if err != nil {
			return err
		}
	}
	return nil
}

// CleanupKeys accepts only the original selected audit and signer. The two
// decrypt clients borrow different credentials, preserving independent proof.
func (s *InstalledConfigurationProviderEffects) CleanupKeys(mount, key, signMount, signKey string, version int, public ed25519.PublicKey) (*Sealer, *Opener, *Opener, *SigningKey, error) {
	if s == nil || s.effects == nil || s.input.ProviderAuthentication == nil ||
		s.input.ProviderAuthentication.CleanupAudit != (contracts.OwnerPublicTransit{Mount: mount, Key: key}) ||
		s.input.ProviderAuthentication.ContextDeletionSigning != (contracts.OwnerPublicTransit{Mount: signMount, Key: signKey}) ||
		version < 1 || version > 2147483647 || len(public) != ed25519.PublicKeySize {
		return nil, nil, nil, nil, ErrKeyService
	}
	paths := []string{mount + "/encrypt/" + key, mount + "/decrypt/" + key, mount + "/decrypt/" + key, signMount + "/sign/" + signKey}
	clients := make([]*bao.Client, 0, 4)
	for i, path := range paths {
		c, err := newOwnerProviderEffectClient(s.effects.cleanup[i], path)
		if err != nil {
			for _, opened := range clients {
				opened.CloneConfig().HttpClient.CloseIdleConnections()
			}
			return nil, nil, nil, nil, err
		}
		clients = append(clients, c)
	}
	return &Sealer{client: clients[0], mount: mount, key: key, reference: mount + "/" + key},
		&Opener{client: clients[1], mount: mount, key: key, reference: mount + "/" + key},
		&Opener{client: clients[2], mount: mount, key: key, reference: mount + "/" + key},
		&SigningKey{client: clients[3], mount: signMount, name: signKey, version: version, public: bytes.Clone(public)}, nil
}
