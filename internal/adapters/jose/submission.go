package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const PolicySubmissionType = "asservat-policy-submission+jws"

// SigningKey is a per-request context-bound standard crypto.Signer, normally
// provided by OpenBao. The verifier needs no private/signing credential.
type PolicySubmissions struct {
	root, installation, epoch, keyID string
	trust                            app.SubmissionTrustReader
	signer                           func(context.Context) crypto.Signer
	now                              func() time.Time
}

var _ app.PolicySubmissionSigner = (*PolicySubmissions)(nil)
var _ app.PolicySubmissionVerifier = (*PolicySubmissions)(nil)

func NewPolicySubmissions(root, installation, epoch, keyID string, trust app.SubmissionTrustReader, signer func(context.Context) crypto.Signer, now func() time.Time) (*PolicySubmissions, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) || !authorization.UUID(epoch) || trust == nil || now == nil || (signer == nil && keyID != "") || (signer != nil && !identity.Text(keyID, 128)) {
		return nil, value.ErrInvalid
	}
	return &PolicySubmissions{root, installation, epoch, keyID, trust, signer, now}, nil
}

// The private versioned envelope deliberately contains no bearer token,
// remembered group list, authored recipe body or user-supplied public key.
func policySubmissionPayload(s value.PolicySubmissionIntent) ([]byte, error) {
	if !s.Valid(s.IssuedAt) {
		return nil, value.ErrInvalid
	}
	s.IssuedAt, s.ExpiresAt = s.IssuedAt.UTC(), s.ExpiresAt.UTC()
	b, e := json.Marshal(struct {
		Format string                       `json:"format"`
		Intent value.PolicySubmissionIntent `json:"intent"`
	}{"asservat-policy-submission/v1", s})
	if e != nil || len(b) > 8192 {
		return nil, value.ErrInvalid
	}
	canonical := jsontext.Value(b)
	if canonical.Canonicalize() != nil {
		return nil, value.ErrInvalid
	}
	return canonical, nil
}

func (s *PolicySubmissions) current(ctx context.Context, intent value.PolicySubmissionIntent, kid string) (value.SubmissionTrust, value.SubmissionKey, error) {
	var trust value.SubmissionTrust
	var key value.SubmissionKey
	if s == nil || s.now == nil || s.trust == nil || ctx.Err() != nil || intent.RootID != s.root || intent.InstallationID != s.installation || intent.IssuerEpoch != s.epoch || !intent.Valid(s.now()) {
		return trust, key, value.ErrDenied
	}
	trust, e := s.trust.SubmissionTrust(ctx)
	now := s.now()
	if e != nil || !trust.Valid(now) || trust.RootID != s.root || trust.InstallationID != s.installation || trust.IssuerEpoch != s.epoch || !intent.Valid(now) {
		return trust, key, value.ErrUnavailable
	}
	for _, candidate := range trust.Keys {
		if candidate.ID == kid {
			key = candidate
			break
		}
	}
	if len(key.PublicKey) != ed25519.PublicKeySize || intent.IssuedAt.Before(key.NotBefore) || intent.ExpiresAt.After(key.NotAfter) || now.Before(key.NotBefore) || !now.Before(key.NotAfter) {
		return trust, key, value.ErrDenied
	}
	return trust, key, nil
}

func (s *PolicySubmissions) SignPolicySubmission(ctx context.Context, intent value.PolicySubmissionIntent) ([]byte, error) {
	if s == nil || s.signer == nil {
		return nil, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	trust, key, e := s.current(ctx, intent, s.keyID)
	if e != nil {
		return nil, e
	}
	payload, e := policySubmissionPayload(intent)
	if e != nil {
		return nil, e
	}
	defer clear(payload)
	keyHandle := s.signer(ctx)
	if keyHandle == nil {
		return nil, value.ErrUnavailable
	}
	pub, ok := keyHandle.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, key.PublicKey) {
		return nil, value.ErrDenied
	}
	h := jws.NewHeaders()
	_ = h.Set(jws.TypeKey, PolicySubmissionType)
	_ = h.Set(jws.KeyIDKey, s.keyID)
	signed, e := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), keyHandle, jws.WithProtectedHeaders(h)))
	if e != nil || len(signed) > 16384 || ctx.Err() != nil || !trust.Valid(s.now()) || !intent.Valid(s.now()) {
		clear(signed)
		return nil, value.ErrUnavailable
	}
	// A provider response is not trusted just because the signing call returned.
	verified, e := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), ed25519.PublicKey(key.PublicKey)))
	defer clear(verified)
	if e != nil || !bytes.Equal(verified, payload) || ctx.Err() != nil || !trust.Valid(s.now()) || !intent.Valid(s.now()) {
		clear(signed)
		return nil, value.ErrDenied
	}
	return signed, nil
}

func (s *PolicySubmissions) VerifyPolicySubmission(ctx context.Context, encoded []byte, expected value.PolicySubmissionIntent) (value.SubmissionCheck, error) {
	var out value.SubmissionCheck
	if len(encoded) == 0 || len(encoded) > 16384 {
		return out, value.ErrInvalid
	}
	parts := strings.Split(string(encoded), ".")
	if len(parts) != 3 {
		return out, value.ErrInvalid
	}
	h, ok := rawURL(parts[0], 1024)
	if !ok || !strictJSON(h, 1024, 32) {
		return out, value.ErrInvalid
	}
	var header map[string]string
	if json.Unmarshal(h, &header) != nil || len(header) != 3 || header["alg"] != "Ed25519" || header["typ"] != PolicySubmissionType || !identity.Text(header["kid"], 128) {
		return out, value.ErrInvalid
	}
	payload, ok := rawURL(parts[1], 8192)
	if !ok {
		return out, value.ErrInvalid
	}
	defer clear(payload)
	sig, ok := rawURL(parts[2], 64)
	if !ok || len(sig) != 64 {
		return out, value.ErrInvalid
	}
	want, e := policySubmissionPayload(expected)
	if e != nil {
		return out, e
	}
	defer clear(want)
	// Comparing the exact canonical payload to independently supplied facts
	// rejects unknown fields, aliases and every actor/source/scope substitution.
	if !bytes.Equal(payload, want) {
		return out, value.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	trust, key, e := s.current(ctx, expected, header["kid"])
	if e != nil {
		return out, e
	}
	verified, e := jws.Verify(encoded, jws.WithKey(jwa.EdDSAEd25519(), ed25519.PublicKey(key.PublicKey)))
	defer clear(verified)
	now := s.now().UTC()
	if e != nil || !bytes.Equal(verified, want) || ctx.Err() != nil || !trust.Valid(now) || !expected.Valid(now) {
		return out, value.ErrDenied
	}
	proof := value.VerifiedPolicySubmission{ReplacesID: expected.ReplacesID, Nonce: expected.Nonce, Actor: expected.Actor, Source: expected.Source, ClusterID: expected.ClusterID, NamespaceUID: expected.NamespaceUID, Name: expected.Name, ScopeDigest: expected.ScopeDigest, EnvelopeDigest: artifact.Digest(sha256.Sum256(want)), IssuedAt: expected.IssuedAt.UTC(), ExpiresAt: expected.ExpiresAt.UTC()}
	out = value.SubmissionCheck{Submission: proof, RootID: s.root, InstallationID: s.installation, IssuerEpoch: s.epoch, KeyID: key.ID, TrustRevision: trust.Revision, VerifiedAt: now, ValidUntil: identity.Earlier(trust.FreshUntil, identity.Earlier(expected.ExpiresAt, key.NotAfter))}
	if !out.Valid(now) {
		return value.SubmissionCheck{}, value.ErrDenied
	}
	return out, nil
}
