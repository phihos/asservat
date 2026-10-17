package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	bao "github.com/openbao/openbao/api/v2"
)

// SigningKey uses a dedicated Transit Ed25519 key and an explicitly pinned
// version/public key. No private key, key-management, export or evidence-key
// permission is needed by this facet. Bootstrap supplies the protected pins.
type SigningKey struct {
	client      *bao.Client
	mount, name string
	version     int
	public      ed25519.PublicKey
}

func NewSigningKey(endpoint, token, mount, name string, version int, public ed25519.PublicKey, h *http.Client) (*SigningKey, error) {
	if !keyName.MatchString(mount) || !keyName.MatchString(name) || version < 1 || version > 2147483647 || len(public) != ed25519.PublicKeySize {
		return nil, ErrKeyService
	}
	c, e := client(endpoint, token, h)
	if e != nil {
		return nil, e
	}
	return &SigningKey{c, mount, name, version, bytes.Clone(public)}, nil
}

type requestSigner struct {
	key *SigningKey
	ctx context.Context
}

var _ crypto.Signer = (*requestSigner)(nil)

// ForContext gives the JWS library a standard signer while preserving the
// request cancellation/deadline through its synchronous crypto.Signer API.
func (s *SigningKey) ForContext(ctx context.Context) crypto.Signer {
	if s == nil || ctx == nil {
		return nil
	}
	return &requestSigner{s, ctx}
}
func (s *requestSigner) Public() crypto.PublicKey {
	return ed25519.PublicKey(bytes.Clone(s.key.public))
}
func (s *requestSigner) Sign(_ io.Reader, input []byte, options crypto.SignerOpts) ([]byte, error) {
	if s.key == nil || s.ctx == nil || !plainEd25519Options(options) || len(input) < 1 || len(input) > 16384 {
		return nil, ErrKeyService
	}
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return nil, ErrKeyService
	}
	r := s.key.client.NewRequest(http.MethodPost, "/v1/"+s.key.mount+"/sign/"+s.key.name)
	if e := r.SetJSONBody(map[string]any{"input": base64.StdEncoding.EncodeToString(input), "key_version": s.key.version, "prehashed": false}); e != nil {
		return nil, ErrKeyService
	}
	response, e := s.key.client.RawRequestWithContext(ctx, r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if e != nil || response == nil || response.Body == nil || response.StatusCode != http.StatusOK {
		return nil, ErrKeyService
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(b)
	if e != nil || len(b) > 32768 {
		return nil, ErrKeyService
	}
	var result struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &result) != nil {
		return nil, ErrKeyService
	}
	prefix := "vault:v" + strconv.Itoa(s.key.version) + ":"
	if !strings.HasPrefix(result.Data.Signature, prefix) {
		return nil, ErrKeyService
	}
	encoded := strings.TrimPrefix(result.Data.Signature, prefix)
	sig, e := base64.StdEncoding.Strict().DecodeString(encoded)
	if e != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != encoded || ctx.Err() != nil || !ed25519.Verify(s.key.public, input, sig) {
		clear(sig)
		return nil, ErrKeyService
	}
	return sig, nil
}

func plainEd25519Options(options crypto.SignerOpts) bool {
	if options == nil {
		return false
	}
	// An interface containing a nil *Options is not itself nil. Check before
	// HashFunc dereferences it, and exclude context/prehash signature variants.
	if o, ok := options.(*ed25519.Options); ok {
		return o != nil && o.Context == "" && o.Hash == 0
	}
	return options.HashFunc() == crypto.Hash(0)
}
