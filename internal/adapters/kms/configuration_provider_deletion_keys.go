package kms

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
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
