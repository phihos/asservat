package kms

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ContextDeletionSigningPublicKeys reads the context deletion signing key's
// latest version and every version's public key (ADR-205 decision 6) with the
// audit-wrap credential, which also signs with it: the audit-wrap policy needs
// capability `read` on `<mount>/keys/<key>`. The permission child calls it at
// startup instead of an installer-pinned readback. It writes nothing and
// cannot export a private key (the key is nonexportable).
func (s *InstalledConfigurationProviderEffects) ContextDeletionSigningPublicKeys(ctx context.Context) (int, map[int]ed25519.PublicKey, error) {
	if s == nil || s.effects == nil || s.effects.wrap == nil || ctx == nil || ctx.Err() != nil {
		return 0, nil, ErrKeyService
	}
	sign := s.input.ContextDeletionSigning
	if !keyName.MatchString(sign.Mount) || !keyName.MatchString(sign.Key) || sign.Mount == s.input.AuditMount && sign.Key == s.input.AuditKey {
		return 0, nil, ErrKeyService
	}
	path := sign.Mount + "/keys/" + sign.Key
	c, err := newOwnerProviderReadClient(s.effects.wrap, path)
	if err != nil {
		return 0, nil, err
	}
	defer c.CloneConfig().HttpClient.CloseIdleConnections()
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	response, err := c.RawRequestWithContext(call, c.NewRequest(http.MethodGet, "/v1/"+path))
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
