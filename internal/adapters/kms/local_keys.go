package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"strconv"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	localSecretFormat = "asservat-local-keys/v1"
	localWrapFormat   = "asservat-local-keyset/v1"
	maxLocalSecret    = 16 << 10
	maxLocalVersions  = 16
)

// LocalKeyScope is independently supplied by protected installation wiring.
// A Secret cannot select its own installation or promote its purpose.
type LocalKeyScope struct {
	InstallationID string
	Purpose        string
	KeyID          string
}

func (s LocalKeyScope) valid() bool {
	return authorization.UUID(s.InstallationID) && keyName.MatchString(s.KeyID) &&
		(s.Purpose == "artifact" || s.Purpose == "audit" || s.Purpose == "browser-credentials" || s.Purpose == "policy-submission")
}

type localKeyVersion struct {
	Version  int    `json:"version"`
	Material []byte `json:"material"`
}

// This is a Secret payload, never a Helm value, logging DTO or public API.
type localKeySecret struct {
	Format         string            `json:"format"`
	InstallationID string            `json:"installationID"`
	Purpose        string            `json:"purpose"`
	KeyID          string            `json:"keyID"`
	ActiveVersion  int               `json:"activeVersion"`
	Keys           []localKeyVersion `json:"keys"`
}

func (s *localKeySecret) clear() {
	for i := range s.Keys {
		clear(s.Keys[i].Material)
	}
}

func readLocalKeys(scope LocalKeyScope, source io.Reader) (localKeySecret, error) {
	var s localKeySecret
	if !scope.valid() || source == nil {
		return s, artifact.ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(source, maxLocalSecret+1))
	defer clear(b)
	if err != nil || len(b) == 0 || len(b) > maxLocalSecret || !jsontext.Value(b).IsValid() {
		return s, ErrKeyService
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		s.clear()
		return localKeySecret{}, ErrKeyService
	}
	// Reject duplicates, aliases, missing fields, noncanonical base64 and
	// unexpected numeric spelling; harmless whitespace/member order is allowed.
	expected, err := json.Marshal(s)
	defer clear(expected)
	actualJSON, expectedJSON := jsontext.Value(b), jsontext.Value(expected)
	valid := err == nil && actualJSON.Canonicalize() == nil && expectedJSON.Canonicalize() == nil && bytes.Equal(actualJSON, expectedJSON)
	valid = valid && s.Format == localSecretFormat && s.InstallationID == scope.InstallationID && s.Purpose == scope.Purpose && s.KeyID == scope.KeyID &&
		s.ActiveVersion >= 1 && s.ActiveVersion <= 2147483647 && len(s.Keys) >= 1 && len(s.Keys) <= maxLocalVersions
	versions := make(map[int]bool, len(s.Keys))
	materials := make(map[[32]byte]bool, len(s.Keys))
	var zero [32]byte
	for _, k := range s.Keys {
		var material [32]byte
		copy(material[:], k.Material)
		digest := sha256.Sum256(k.Material)
		valid = valid && k.Version >= 1 && k.Version <= 2147483647 && len(k.Material) == 32 && material != zero && !versions[k.Version] && !materials[digest]
		versions[k.Version], materials[digest] = true, true
		clear(material[:])
	}
	if !valid || !versions[s.ActiveVersion] {
		s.clear()
		return localKeySecret{}, ErrKeyService
	}
	return s, nil
}

// LocalKeyBackend holds root key material. Instantiate ONLY inside an isolated
// key-service role, never the hub, collector, publisher or acquisition process.
// It is a cryptographic backend, not an authorizer. A separate authenticated
// service must enforce current per-operation authority before invoking it.
// No production listener or role composition is enabled by this constructor.
type LocalKeyBackend struct {
	active string
	keys   map[string]tink.AEAD
}

func NewLocalKeyBackend(scope LocalKeyScope, secret io.Reader) (*LocalKeyBackend, error) {
	if scope.Purpose == "policy-submission" {
		return nil, artifact.ErrInvalid
	}
	s, err := readLocalKeys(scope, secret)
	if err != nil {
		return nil, err
	}
	defer s.clear()
	out := &LocalKeyBackend{keys: make(map[string]tink.AEAD, len(s.Keys))}
	for _, k := range s.Keys {
		a, err := subtle.NewXChaCha20Poly1305(k.Material)
		if err != nil {
			return nil, ErrKeyService
		}
		ref := localWrapFormat + "/" + scope.InstallationID + "/" + scope.Purpose + "/" + scope.KeyID + "/" + strconv.Itoa(k.Version)
		out.keys[ref] = a
		if k.Version == s.ActiveVersion {
			out.active = ref
		}
	}
	return out, nil
}

func localAssociated(reference string, binding []byte) []byte {
	bound := sha256.Sum256(binding)
	b, _ := json.Marshal(struct {
		Format        string `json:"format"`
		Reference     string `json:"reference"`
		BindingSHA256 string `json:"bindingSHA256"`
	}{localWrapFormat, reference, hex.EncodeToString(bound[:])})
	c := jsontext.Value(b)
	if c.Canonicalize() != nil {
		panic("invalid internal key binding")
	}
	return c
}

func (s *LocalKeyBackend) Seal(ctx context.Context, keyset, binding []byte) (artifact.SealedKey, error) {
	if s == nil || ctx == nil || len(keyset) < 1 || len(keyset) > 4096 || len(binding) < 1 || len(binding) > 2048 {
		return artifact.SealedKey{}, artifact.ErrInvalid
	}
	a := s.keys[s.active]
	if a == nil || ctx.Err() != nil {
		return artifact.SealedKey{}, ErrKeyService
	}
	c, err := a.Encrypt(keyset, localAssociated(s.active, binding))
	defer clear(c)
	if err != nil || ctx.Err() != nil {
		return artifact.SealedKey{}, ErrKeyService
	}
	return artifact.SealedKey{Reference: s.active, Ciphertext: base64.StdEncoding.EncodeToString(c)}, nil
}

func (s *LocalKeyBackend) Open(ctx context.Context, sealed artifact.SealedKey, binding []byte) ([]byte, error) {
	if s == nil || ctx == nil || len(sealed.Reference) > 256 || len(sealed.Ciphertext) < 1 || len(sealed.Ciphertext) > base64.StdEncoding.EncodedLen(4096+40) || len(binding) < 1 || len(binding) > 2048 {
		return nil, artifact.ErrInvalid
	}
	a := s.keys[sealed.Reference]
	if a == nil || ctx.Err() != nil {
		return nil, ErrKeyService
	}
	c, err := base64.StdEncoding.Strict().DecodeString(sealed.Ciphertext)
	defer clear(c)
	if err != nil || base64.StdEncoding.EncodeToString(c) != sealed.Ciphertext || len(c) < 41 || len(c) > 4096+40 {
		return nil, artifact.ErrIntegrity
	}
	plain, err := a.Decrypt(c, localAssociated(sealed.Reference, binding))
	if err != nil || len(plain) < 1 || len(plain) > 4096 {
		clear(plain)
		return nil, artifact.ErrIntegrity
	}
	if ctx.Err() != nil {
		clear(plain)
		return nil, ErrKeyService
	}
	return plain, nil
}
