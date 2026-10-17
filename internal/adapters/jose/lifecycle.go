package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"strings"

	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const LifecycleType = "asservat-retention-lifecycle+jws"

// LifecycleSignatures is a frozen, installation-scoped key snapshot. Bootstrap
// supplies dedicated protected keys, with old public keys retained for journal
// verification. It does not discover keys or confer policy/restore authority.
type LifecycleSignatures struct {
	root, active string
	private      ed25519.PrivateKey
	public       map[string]ed25519.PublicKey
	// signer, when set, signs remotely (a pinned Transit key, ADR-195)
	// instead of private; its public key is public[active].
	signer func(context.Context) crypto.Signer
}

// NewRemoteLifecycleSignatures signs with a context-bound remote signer, such
// as a pinned OpenBao Transit Ed25519 key (ADR-195 step 5b). No private key
// enters the process.
func NewRemoteLifecycleSignatures(root, active string, public map[string]ed25519.PublicKey, signer func(context.Context) crypto.Signer) (*LifecycleSignatures, error) {
	if signer == nil || !identity.Text(active, 128) {
		return nil, value.ErrInvalid
	}
	r, err := NewLifecycleSignatures(root, "", nil, public)
	if err != nil || len(r.public[active]) != ed25519.PublicKeySize {
		return nil, value.ErrInvalid
	}
	r.active, r.signer = active, signer
	return r, nil
}

var _ app.LifecycleSigner = (*LifecycleSignatures)(nil)
var _ app.LifecycleVerifier = (*LifecycleSignatures)(nil)

func NewLifecycleSignatures(root, active string, private ed25519.PrivateKey, public map[string]ed25519.PublicKey) (*LifecycleSignatures, error) {
	if !authorization.UUID(root) || len(public) < 1 || len(public) > 32 {
		return nil, value.ErrInvalid
	}
	r := &LifecycleSignatures{root: root, active: active, public: map[string]ed25519.PublicKey{}}
	for id, key := range public {
		if !identity.Text(id, 128) || len(key) != ed25519.PublicKeySize {
			return nil, value.ErrInvalid
		}
		r.public[id] = bytes.Clone(key)
	}
	if len(private) > 0 {
		if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) || !bytes.Equal(private.Public().(ed25519.PublicKey), r.public[active]) {
			return nil, value.ErrInvalid
		}
		r.private = bytes.Clone(private)
	} else if active != "" {
		return nil, value.ErrInvalid
	}
	return r, nil
}
func lifecyclePayload(r value.LifecycleDecision) ([]byte, error) {
	if !r.Valid() {
		return nil, value.ErrInvalid
	}
	b, err := json.Marshal(struct {
		Format   string
		Decision value.LifecycleDecision
	}{"asservat-retention-lifecycle/v1", r})
	if err != nil || len(b) > 32<<10 {
		return nil, value.ErrInvalid
	}
	canonical := jsontext.Value(b)
	if canonical.Canonicalize() != nil {
		return nil, value.ErrInvalid
	}
	return canonical, nil
}
func (s *LifecycleSignatures) SignLifecycle(ctx context.Context, r value.LifecycleDecision) ([]byte, error) {
	if s == nil || ctx.Err() != nil || s.root != r.RootID || len(s.private) != ed25519.PrivateKeySize && s.signer == nil {
		return nil, value.ErrUnavailable
	}
	var key any = s.private
	if s.signer != nil {
		signer := s.signer(ctx)
		if signer == nil {
			return nil, value.ErrUnavailable
		}
		key = signer
	}
	payload, err := lifecyclePayload(r)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	h := jws.NewHeaders()
	_ = h.Set(jws.TypeKey, LifecycleType)
	_ = h.Set(jws.KeyIDKey, s.active)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), key, jws.WithProtectedHeaders(h)))
	if err != nil {
		return nil, value.ErrUnavailable
	}
	defer clear(signed)
	parts := bytes.Split(signed, []byte("."))
	if len(parts) != 3 {
		return nil, value.ErrUnavailable
	}
	// Standard detached compact JWS: the encrypted record supplies the payload.
	return append(append(bytes.Clone(parts[0]), '.', '.'), parts[2]...), nil
}
func (s *LifecycleSignatures) VerifyLifecycle(ctx context.Context, r value.LifecycleDecision, detached []byte) error {
	if s == nil || ctx.Err() != nil || s.root != r.RootID || len(detached) > 2048 {
		return value.ErrUnavailable
	}
	parts := strings.Split(string(detached), ".")
	if len(parts) != 3 || parts[1] != "" {
		return value.ErrInvalid
	}
	header, ok := rawURL(parts[0], 1024)
	if !ok || !strictJSON(header, 1024, 32) {
		return value.ErrInvalid
	}
	var h map[string]string
	if json.Unmarshal(header, &h) != nil || len(h) != 3 || h["alg"] != "Ed25519" || h["typ"] != LifecycleType || !identity.Text(h["kid"], 128) {
		return value.ErrInvalid
	}
	key := s.public[h["kid"]]
	sig, ok := rawURL(parts[2], ed25519.SignatureSize)
	if len(key) != ed25519.PublicKeySize || !ok || len(sig) != ed25519.SignatureSize {
		return value.ErrInvalid
	}
	payload, err := lifecyclePayload(r)
	if err != nil {
		return err
	}
	defer clear(payload)
	compact := []byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2])
	defer clear(compact)
	verified, err := jws.Verify(compact, jws.WithKey(jwa.EdDSAEd25519(), key))
	defer clear(verified)
	if err != nil || !bytes.Equal(verified, payload) {
		return value.ErrInvalid
	}
	return nil
}
