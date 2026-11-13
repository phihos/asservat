package kms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	bao "github.com/openbao/openbao/api/v2"

	"asservat.local/asservat/internal/contracts"
)

// RefreshCleanup is called only by the existing serial cleanup child, before
// entering its effect operation. Healthy credentials cost no native admission.
// Each login/renewal uses the same recovery brackets as the
// configuration purposes; no periodic cleanup credential task is introduced.
func (s *InstalledConfigurationProviderEffects) RefreshCleanup(ctx context.Context) error {
	if s == nil || s.effects == nil || s.admission == nil || !s.input.cleanup() {
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
	if s == nil || s.effects == nil || !s.input.cleanup() || mount != s.input.AuditMount || key != s.input.AuditKey ||
		s.input.ContextDeletionSigning != (contracts.OwnerPublicTransit{Mount: signMount, Key: signKey}) ||
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

// CleanupSigningPublicKeys reads the context deletion signing key's latest
// version and the public key of every listed version with the cleanup-sign
// credential (capability `read` on `<mount>/keys/<key>`). Call it after
// RefreshCleanup; it holds no admission ticket and writes nothing.
func (s *InstalledConfigurationProviderEffects) CleanupSigningPublicKeys(ctx context.Context) (int, map[int]ed25519.PublicKey, error) {
	if s == nil || s.effects == nil || !s.input.cleanup() || ctx == nil || ctx.Err() != nil {
		return 0, nil, ErrKeyService
	}
	sign := s.input.ContextDeletionSigning
	if !keyName.MatchString(sign.Mount) || !keyName.MatchString(sign.Key) {
		return 0, nil, ErrKeyService
	}
	c, err := newOwnerProviderReadClient(s.effects.cleanup[3], sign.Mount+"/keys/"+sign.Key)
	if err != nil {
		return 0, nil, err
	}
	defer c.CloneConfig().HttpClient.CloseIdleConnections()
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	response, err := c.RawRequestWithContext(call, c.NewRequest(http.MethodGet, "/v1/"+sign.Mount+"/keys/"+sign.Key))
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.Body == nil || response.StatusCode != http.StatusOK {
		return 0, nil, ErrKeyService
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil || len(b) > 64<<10 {
		return 0, nil, ErrKeyService
	}
	return parseTransitSigningKey(b, sign.Key)
}

// parseTransitSigningKey accepts a nonexportable Ed25519 Transit key read
// response with 1..32 versions, each with a 32-byte public key.
func parseTransitSigningKey(b []byte, name string) (int, map[int]ed25519.PublicKey, error) {
	var result struct {
		Data struct {
			Name          string `json:"name"`
			Type          string `json:"type"`
			Exportable    bool   `json:"exportable"`
			LatestVersion int    `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &result) != nil {
		return 0, nil, ErrKeyService
	}
	d := result.Data
	if d.Name != name || d.Type != "ed25519" || d.Exportable || d.LatestVersion < 1 || d.LatestVersion > 2147483647 || len(d.Keys) < 1 || len(d.Keys) > 32 {
		return 0, nil, ErrKeyService
	}
	out := make(map[int]ed25519.PublicKey, len(d.Keys))
	for v, k := range d.Keys {
		version, err := strconv.Atoi(v)
		key, decodeErr := base64.StdEncoding.Strict().DecodeString(k.PublicKey)
		if err != nil || strconv.Itoa(version) != v || version < 1 || version > d.LatestVersion || decodeErr != nil || len(key) != ed25519.PublicKeySize {
			return 0, nil, ErrKeyService
		}
		out[version] = key
	}
	if out[d.LatestVersion] == nil {
		return 0, nil, ErrKeyService
	}
	return d.LatestVersion, out, nil
}
