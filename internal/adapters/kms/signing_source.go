package kms

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
)

// NewSigningKeyWithTokenSource retains the existing exact Transit key/version
// and public-key check while reading the independently projected token for each
// original request. It cannot create/export a key or fall back to an old token.
func NewSigningKeyWithTokenSource(endpoint, mount, name string, version int, public ed25519.PublicKey, source TokenSource, h *http.Client) (*SigningKey, error) {
	if source == nil || !keyName.MatchString(mount) || !keyName.MatchString(name) || version < 1 || version > 2147483647 || len(public) != ed25519.PublicKeySize {
		return nil, ErrKeyService
	}
	c, err := clientWithSource(endpoint, "", source, h)
	if err != nil {
		return nil, err
	}
	return &SigningKey{c, mount, name, version, bytes.Clone(public)}, nil
}

// Runtime owns cancellation/join before releasing the cloned idle transport.
func (s *SigningKey) Close() {
	if s != nil && s.client != nil {
		s.client.CloneConfig().HttpClient.CloseIdleConnections()
	}
}
