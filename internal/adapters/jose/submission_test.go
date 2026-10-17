package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

type submissionTrustFixture struct {
	trust value.SubmissionTrust
	err   error
	reads int
}

func (f *submissionTrustFixture) SubmissionTrust(context.Context) (value.SubmissionTrust, error) {
	f.reads++
	return f.trust, f.err
}

type deferredSigner struct {
	key   ed25519.PrivateKey
	after func()
}

func (s deferredSigner) Public() crypto.PublicKey { return s.key.Public() }
func (s deferredSigner) Sign(r io.Reader, b []byte, o crypto.SignerOpts) ([]byte, error) {
	v, e := s.key.Sign(r, b, o)
	if s.after != nil {
		s.after()
	}
	return v, e
}

func TestPolicySubmissionSignVerifyAndCurrentTrust(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	intent := value.PolicySubmissionIntent{RootID: "75000000-0000-4000-8000-000000000001", InstallationID: "75000000-0000-4000-8000-000000000002", IssuerEpoch: "75000000-0000-4000-8000-000000000003", Nonce: "75000000-0000-4000-8000-000000000004", Actor: identity.Principal{Issuer: "https://id.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Source: identity.Revision{UID: "policy-uid", Generation: 2, Digest: artifact.Digest{1}}, ClusterID: "75000000-0000-4000-8000-000000000005", NamespaceUID: "namespace-uid", Name: "policy", ScopeDigest: artifact.Digest{2}, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	trust := value.SubmissionTrust{RootID: intent.RootID, InstallationID: intent.InstallationID, IssuerEpoch: intent.IssuerEpoch, Revision: identity.Revision{UID: "trust", Generation: 1, Digest: artifact.Digest{3}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Keys: []value.SubmissionKey{{ID: "submission-key", PublicKey: pub, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}}}
	f := &submissionTrustFixture{trust: trust}
	s, e := NewPolicySubmissions(intent.RootID, intent.InstallationID, intent.IssuerEpoch, "submission-key", f, func(context.Context) crypto.Signer { return deferredSigner{key: key} }, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	v, e := NewPolicySubmissions(intent.RootID, intent.InstallationID, intent.IssuerEpoch, "", f, nil, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := s.SignPolicySubmission(context.Background(), intent)
	if e != nil {
		t.Fatal(e)
	}
	checked, e := v.VerifyPolicySubmission(context.Background(), encoded, intent)
	if e != nil || !checked.Valid(now) || checked.Submission.Actor != intent.Actor || checked.Submission.Source != intent.Source || checked.ValidUntil != trust.FreshUntil {
		t.Fatalf("submission not verified: %v", e)
	}
	if _, e := v.SignPolicySubmission(context.Background(), intent); e == nil {
		t.Fatal("read-only verifier signed")
	}
	for _, mode := range []string{"actor", "client", "source", "generation", "spec", "namespace", "name", "scope", "nonce", "epoch", "installation", "root", "replacement", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			bad := intent
			switch mode {
			case "actor":
				bad.Actor.Subject = "admin"
			case "client":
				bad.Actor.ClientID = "another"
			case "source":
				bad.Source.UID = "replacement"
			case "generation":
				bad.Source.Generation++
			case "spec":
				bad.Source.Digest[0]++
			case "namespace":
				bad.NamespaceUID = "other"
			case "name":
				bad.Name = "other"
			case "scope":
				bad.ScopeDigest[0]++
			case "nonce":
				bad.Nonce = "75000000-0000-4000-8000-000000000099"
			case "epoch":
				bad.IssuerEpoch = bad.Nonce
			case "installation":
				bad.InstallationID = bad.Nonce
			case "root":
				bad.RootID = bad.Nonce
			case "replacement":
				bad.ReplacesID = bad.Nonce
			case "expiry":
				bad.ExpiresAt = bad.ExpiresAt.Add(time.Second)
			}
			if _, e := v.VerifyPolicySubmission(context.Background(), encoded, bad); e == nil {
				t.Fatal("scope substitution accepted")
			}
		})
	}
	for _, mode := range []string{"missing-key", "expired-trust", "future-trust", "wrong-epoch", "wrong-root", "outage"} {
		t.Run(mode, func(t *testing.T) {
			f.trust = trust
			f.err = nil
			switch mode {
			case "missing-key":
				f.trust.Keys = nil
			case "expired-trust":
				f.trust.ObservedAt = now.Add(-6 * time.Second)
				f.trust.FreshUntil = now.Add(-time.Second)
			case "future-trust":
				f.trust.ObservedAt = now.Add(time.Second)
			case "wrong-epoch":
				f.trust.IssuerEpoch = intent.Nonce
			case "wrong-root":
				f.trust.RootID = intent.Nonce
			case "outage":
				f.err = errors.New("synthetic key source outage")
			}
			if _, e := v.VerifyPolicySubmission(context.Background(), encoded, intent); e == nil {
				t.Fatal("stale/untrusted key accepted")
			}
		})
	}
	f.trust = trust
	f.err = nil
	payload, e := policySubmissionPayload(intent)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"wrong-purpose", "extra-header", "unknown-key", "old-eddsa", "payload-space", "bad-signature", "padding", "too-large"} {
		t.Run(mode, func(t *testing.T) {
			h := jws.NewHeaders()
			_ = h.Set(jws.TypeKey, PolicySubmissionType)
			_ = h.Set(jws.KeyIDKey, "submission-key")
			body := payload
			switch mode {
			case "wrong-purpose":
				_ = h.Set(jws.TypeKey, LifecycleType)
			case "extra-header":
				_ = h.Set("jku", "https://untrusted.invalid")
			case "unknown-key":
				_ = h.Set(jws.KeyIDKey, "other")
			case "payload-space":
				body = append(bytes.Clone(payload), ' ')
			}
			b, e := jws.Sign(body, jws.WithKey(jwa.EdDSAEd25519(), key, jws.WithProtectedHeaders(h)))
			if e != nil {
				t.Fatal(e)
			}
			parts := strings.Split(string(b), ".")
			switch mode {
			case "old-eddsa":
				header, _ := base64.RawURLEncoding.DecodeString(parts[0])
				parts[0] = base64.RawURLEncoding.EncodeToString(bytes.ReplaceAll(header, []byte("Ed25519"), []byte("EdDSA")))
				b = []byte(strings.Join(parts, "."))
			case "bad-signature":
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				b = []byte(strings.Join(parts, "."))
			case "padding":
				parts[0] += "="
				b = []byte(strings.Join(parts, "."))
			case "too-large":
				b = bytes.Repeat([]byte{'x'}, 16385)
			}
			if _, e := v.VerifyPolicySubmission(context.Background(), b, intent); e == nil {
				t.Fatal("protocol confusion accepted")
			}
		})
	}
	// No response from a blocking signing provider may outlive original trust.
	s.signer = func(context.Context) crypto.Signer {
		return deferredSigner{key: key, after: func() { now = now.Add(5 * time.Second) }}
	}
	if _, e := s.SignPolicySubmission(context.Background(), intent); e == nil {
		t.Fatal("provider extended signing freshness")
	}
}
