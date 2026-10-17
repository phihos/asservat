package jose

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"strings"

	app "asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const DownloadStopRetirementType = "asservat-download-stop-retirement+jws"

// DownloadStopRetirementSignatures is a frozen, installation-scoped key snapshot. Bootstrap
// supplies explicitly accepted Stop-retirement signing purpose (which may share
// an accepted lifecycle key), with old public keys retained for journal
// verification. It does not discover keys or confer policy/restore authority.
type DownloadStopRetirementSignatures struct {
	root, active string
	private      ed25519.PrivateKey
	public       map[string]ed25519.PublicKey
}

var _ app.DownloadStopRetirementSigner = (*DownloadStopRetirementSignatures)(nil)
var _ app.DownloadStopRetirementVerifier = (*DownloadStopRetirementSignatures)(nil)

func NewDownloadStopRetirementSignatures(root, active string, private ed25519.PrivateKey, public map[string]ed25519.PublicKey) (*DownloadStopRetirementSignatures, error) {
	if !authorization.UUID(root) || len(public) < 1 || len(public) > 32 {
		return nil, artifact.ErrDownloadUnavailable
	}
	r := &DownloadStopRetirementSignatures{root: root, active: active, public: map[string]ed25519.PublicKey{}}
	for id, key := range public {
		if !identity.Text(id, 128) || len(key) != ed25519.PublicKeySize {
			return nil, artifact.ErrDownloadUnavailable
		}
		r.public[id] = bytes.Clone(key)
	}
	if len(private) > 0 {
		if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) || !bytes.Equal(private.Public().(ed25519.PublicKey), r.public[active]) {
			return nil, artifact.ErrDownloadUnavailable
		}
		r.private = bytes.Clone(private)
	} else if active != "" {
		return nil, artifact.ErrDownloadUnavailable
	}
	return r, nil
}
func downloadStopRetirementPayload(r value.DownloadStopRetirement) ([]byte, error) {
	if !r.Valid() {
		return nil, artifact.ErrDownloadUnavailable
	}
	b, err := json.Marshal(struct {
		Format   string
		Decision value.DownloadStopRetirement
	}{"asservat-download-stop-retirement/v1", r})
	if err != nil || len(b) > 8<<10 {
		return nil, artifact.ErrDownloadUnavailable
	}
	canonical := jsontext.Value(b)
	if canonical.Canonicalize() != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return canonical, nil
}
func (s *DownloadStopRetirementSignatures) SignDownloadStopRetirement(ctx context.Context, r value.DownloadStopRetirement) ([]byte, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root != r.RootID || len(s.private) != ed25519.PrivateKeySize {
		return nil, artifact.ErrDownloadUnavailable
	}
	payload, err := downloadStopRetirementPayload(r)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	h := jws.NewHeaders()
	_ = h.Set(jws.TypeKey, DownloadStopRetirementType)
	_ = h.Set(jws.KeyIDKey, s.active)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), s.private, jws.WithProtectedHeaders(h)))
	if err != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	defer clear(signed)
	parts := bytes.Split(signed, []byte("."))
	if len(parts) != 3 {
		return nil, artifact.ErrDownloadUnavailable
	}
	// Standard detached compact JWS: the encrypted record supplies the payload.
	return append(append(bytes.Clone(parts[0]), '.', '.'), parts[2]...), nil
}
func (s *DownloadStopRetirementSignatures) VerifyDownloadStopRetirement(ctx context.Context, r value.DownloadStopRetirement, detached []byte) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root != r.RootID || len(detached) > 2048 {
		return artifact.ErrDownloadUnavailable
	}
	parts := strings.Split(string(detached), ".")
	if len(parts) != 3 || parts[1] != "" {
		return artifact.ErrDownloadUnavailable
	}
	header, ok := rawURL(parts[0], 1024)
	if !ok || !strictJSON(header, 1024, 32) {
		return artifact.ErrDownloadUnavailable
	}
	var h map[string]string
	if json.Unmarshal(header, &h) != nil || len(h) != 3 || h["alg"] != "Ed25519" || h["typ"] != DownloadStopRetirementType || !identity.Text(h["kid"], 128) {
		return artifact.ErrDownloadUnavailable
	}
	key := s.public[h["kid"]]
	sig, ok := rawURL(parts[2], ed25519.SignatureSize)
	if len(key) != ed25519.PublicKeySize || !ok || len(sig) != ed25519.SignatureSize {
		return artifact.ErrDownloadUnavailable
	}
	payload, err := downloadStopRetirementPayload(r)
	if err != nil {
		return err
	}
	defer clear(payload)
	compact := []byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2])
	defer clear(compact)
	verified, err := jws.Verify(compact, jws.WithKey(jwa.EdDSAEd25519(), key))
	defer clear(verified)
	if err != nil || !bytes.Equal(verified, payload) {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
