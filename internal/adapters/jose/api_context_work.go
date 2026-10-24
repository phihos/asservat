package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	wire "asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const APIContextWorkType = "asservat-api-context-work+jws"

// APIContextWorkSignatures has a fixed installed key purpose. The verifier has
// no signing dependency; TLS, accepted references and live identity are separate.
type APIContextWorkSignatures struct {
	trust  app.APIContextWorkTrustReader
	keyID  string
	signer func(context.Context) crypto.Signer
	now    func() time.Time
}

func NewAPIContextWorkSignatures(trust app.APIContextWorkTrustReader, keyID string, signer func(context.Context) crypto.Signer, now func() time.Time) (*APIContextWorkSignatures, error) {
	if trust == nil || now == nil || (signer == nil && keyID != "") || (signer != nil && !identity.Text(keyID, 128)) {
		return nil, value.ErrInvalid
	}
	return &APIContextWorkSignatures{trust, keyID, signer, now}, nil
}

var _ app.APIContextWorkSigner = (*APIContextWorkSignatures)(nil)
var _ app.APIContextWorkVerifier = (*APIContextWorkSignatures)(nil)

func apiContextDigest(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
func apiContextWire(w value.APIContextWork) wire.APIContextWork {
	c, p, e := w.Channel, w.Channel.Connector, w.Channel.Executor
	h := c.Hub
	return wire.APIContextWork{Format: wire.APIContextWorkFormat, Purpose: "runAction", ExecutionClass: string(artifact.ContextAPIExecution), ActionID: "pod-status", NativeBytes: artifact.MaxContextBytes,
		Channel: wire.APIContextChannel{RootID: c.RootID, ExchangeID: c.ExchangeID, Challenge: c.Challenge,
			Hub:       wire.APIContextOwner{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
			Connector: wire.APIContextConnector{InstallationID: p.Binding.InstallationID, ClusterID: p.Binding.ClusterID, IssuerEpoch: p.Binding.IssuerEpoch, PeerID: p.Binding.PeerID, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch, LeafDigest: apiContextDigest(c.ConnectorLeaf)},
			Executor:  wire.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: apiContextDigest(e.StartupDigest), ImageDigest: apiContextDigest(e.ImageDigest)}},
		CaptureID: w.CaptureID, AttemptID: w.AttemptID, Actor: wire.APIContextActor{Issuer: w.Actor.Issuer, Subject: w.Actor.Subject, ClientID: w.Actor.ClientID, Kind: string(w.Actor.Kind)},
		Target:      wire.APIContextTarget{ClusterID: w.Target.ClusterID, NamespaceUID: w.Target.NamespaceUID, WorkloadUID: w.Target.WorkloadUID, PodUID: w.Target.PodUID},
		ScopeDigest: apiContextDigest(w.ScopeDigest), ExpectationDigest: apiContextDigest(w.ExpectationDigest), IntentDigest: apiContextDigest(w.IntentDigest), BudgetDigest: apiContextDigest(w.BudgetDigest),
		Capability: wire.APIContextRevision{UID: w.Capability.UID, Generation: w.Capability.Generation, Digest: apiContextDigest(w.Capability.Digest)}, ProjectionDigest: apiContextDigest(w.ProjectionDigest), IssuedAt: w.IssuedAt.Format(time.RFC3339Nano), NotAfter: w.NotAfter.Format(time.RFC3339Nano)}
}
func apiContextValue(d wire.APIContextWork) (value.APIContextWork, error) {
	if !canonicalInstant(d.IssuedAt) || !canonicalInstant(d.NotAfter) {
		return value.APIContextWork{}, value.ErrInvalid
	}
	c, p, e, h := d.Channel, d.Channel.Connector, d.Channel.Executor, d.Channel.Hub
	w := value.APIContextWork{Channel: value.APIContextChannel{RootID: c.RootID, ExchangeID: c.ExchangeID, Challenge: c.Challenge,
		Hub:       value.OwnerBinding{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
		Connector: value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PeerID: p.PeerID, Role: value.ConnectorPeer}, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch}, ConnectorLeaf: digestValue(p.LeafDigest),
		Executor: value.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: digestValue(e.StartupDigest), ImageDigest: digestValue(e.ImageDigest)}},
		CaptureID: d.CaptureID, AttemptID: d.AttemptID, Actor: identity.Principal{Issuer: d.Actor.Issuer, Subject: d.Actor.Subject, ClientID: d.Actor.ClientID, Kind: identity.Kind(d.Actor.Kind)},
		Target: authorization.Target{ClusterID: d.Target.ClusterID, NamespaceUID: d.Target.NamespaceUID, WorkloadUID: d.Target.WorkloadUID, PodUID: d.Target.PodUID}, ScopeDigest: digestValue(d.ScopeDigest), ExpectationDigest: digestValue(d.ExpectationDigest), IntentDigest: digestValue(d.IntentDigest), BudgetDigest: digestValue(d.BudgetDigest),
		Capability: identity.Revision{UID: d.Capability.UID, Generation: d.Capability.Generation, Digest: digestValue(d.Capability.Digest)}, ProjectionDigest: digestValue(d.ProjectionDigest), IssuedAt: instant(d.IssuedAt).UTC(), NotAfter: instant(d.NotAfter).UTC()}
	return w, nil
}
func (s *APIContextWorkSignatures) current(ctx context.Context, w value.APIContextWork, kid string) (value.APIContextWorkTrust, value.WorkKey, error) {
	var zero value.APIContextWorkTrust
	var key value.WorkKey
	if s == nil || s.trust == nil || s.now == nil || ctx == nil || ctx.Err() != nil || !w.Valid(s.now()) {
		return zero, key, value.ErrDenied
	}
	call, stop := context.WithDeadline(ctx, w.NotAfter)
	defer stop()
	t, e := s.trust.APIContextWorkTrust(call)
	if e != nil || call.Err() != nil || !w.Valid(s.now()) || !t.Valid(s.now()) || !t.Matches(w) {
		return zero, key, value.ErrUnavailable
	}
	for _, k := range t.Trust.Keys {
		if k.ID == kid {
			key = k
			key.PublicKey = bytes.Clone(k.PublicKey)
			break
		}
	}
	if len(key.PublicKey) != ed25519.PublicKeySize || w.IssuedAt.Before(key.NotBefore) || w.NotAfter.After(key.NotAfter) || s.now().Before(key.NotBefore) || !s.now().Before(key.NotAfter) {
		return zero, value.WorkKey{}, value.ErrDenied
	}
	return t, key, nil
}
func apiContextUntil(ctx context.Context, w value.APIContextWork, t value.APIContextWorkTrust) time.Time {
	until := identity.Earlier(w.NotAfter, t.Trust.FreshUntil)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	return until
}
func (s *APIContextWorkSignatures) SignAPIContextWork(ctx context.Context, w value.APIContextWork) ([]byte, error) {
	if s == nil || s.signer == nil || ctx == nil {
		return nil, value.ErrUnavailable
	}
	first, key, e := s.current(ctx, w, s.keyID)
	if e != nil {
		return nil, e
	}
	until := apiContextUntil(ctx, w, first)
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	payload, e := wire.EncodeAPIContextWork(apiContextWire(w))
	if e != nil {
		return nil, value.ErrInvalid
	}
	defer clear(payload)
	signer := s.signer(call)
	if signer == nil {
		return nil, value.ErrUnavailable
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, key.PublicKey) {
		return nil, value.ErrDenied
	}
	headers := jws.NewHeaders()
	_ = headers.Set(jws.TypeKey, APIContextWorkType)
	_ = headers.Set(jws.KeyIDKey, s.keyID)
	signed, e := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), signer, jws.WithProtectedHeaders(headers)))
	if e != nil || len(signed) > wire.APIContextSignedWorkBytes || call.Err() != nil || !s.now().Before(until) {
		clear(signed)
		return nil, value.ErrUnavailable
	}
	actual, e := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub))
	defer clear(actual)
	if e != nil || !bytes.Equal(actual, payload) {
		clear(signed)
		return nil, value.ErrDenied
	}
	last, current, e := s.current(call, w, s.keyID)
	until = identity.Earlier(until, last.Trust.FreshUntil)
	if e != nil || last.Trust.Revision != first.Trust.Revision || !bytes.Equal(current.PublicKey, key.PublicKey) || !current.NotBefore.Equal(key.NotBefore) || !current.NotAfter.Equal(key.NotAfter) || call.Err() != nil || !s.now().Before(until) {
		clear(signed)
		return nil, value.ErrUnavailable
	}
	return signed, nil
}
func (s *APIContextWorkSignatures) VerifyAPIContextWork(ctx context.Context, encoded []byte, receiver value.APIContextReceiver) (value.AuthenticatedAPIContextWork, error) {
	var out value.AuthenticatedAPIContextWork
	if s == nil || s.now == nil || s.trust == nil || ctx == nil || ctx.Err() != nil || !receiver.Valid(s.now()) || len(encoded) == 0 || len(encoded) > wire.APIContextSignedWorkBytes {
		return out, value.ErrInvalid
	}
	parts := strings.Split(string(encoded), ".")
	if len(parts) != 3 {
		return out, value.ErrInvalid
	}
	header, ok := rawURL(parts[0], 1024)
	if !ok || !strictJSON(header, 1024, 32) {
		return out, value.ErrInvalid
	}
	var h map[string]string
	if json.Unmarshal(header, &h) != nil || len(h) != 3 || h["alg"] != "Ed25519" || h["typ"] != APIContextWorkType || !identity.Text(h["kid"], 128) {
		return out, workStep{"header", value.ErrDenied}
	}
	payload, ok := rawURL(parts[1], wire.APIContextWorkBytes)
	if !ok {
		return out, value.ErrInvalid
	}
	defer clear(payload)
	signature, ok := rawURL(parts[2], ed25519.SignatureSize)
	if !ok || len(signature) != ed25519.SignatureSize {
		return out, value.ErrInvalid
	}
	d, e := wire.DecodeAPIContextWork(payload)
	if e != nil {
		return out, value.ErrInvalid
	}
	w, e := apiContextValue(d)
	if e != nil {
		return out, workStep{"value", value.ErrDenied}
	}
	if !w.Matches(receiver, s.now()) {
		return out, workStep{"receiver-" + w.MismatchStep(receiver, s.now()), value.ErrDenied}
	}
	canonical, e := wire.EncodeAPIContextWork(apiContextWire(w))
	defer clear(canonical)
	// This also rejects noncanonical digest/time spelling and omitted, aliased,
	// unknown or mismatching fixed profile fields after the strict typed decode.
	if e != nil || !jsontext.Value(payload).IsValid() || !bytes.Equal(canonical, payload) {
		return out, value.ErrInvalid
	}
	call, stop := context.WithDeadline(ctx, identity.Earlier(w.NotAfter, receiver.ValidUntil))
	defer stop()
	first, key, e := s.current(call, w, h["kid"])
	if e != nil {
		return out, workStep{"trust", e}
	}
	until := apiContextUntil(call, w, first)
	bounded, cancel := context.WithDeadline(call, until)
	defer cancel()
	actual, e := jws.Verify(encoded, jws.WithKey(jwa.EdDSAEd25519(), ed25519.PublicKey(key.PublicKey)))
	defer clear(actual)
	if e != nil || !bytes.Equal(actual, payload) {
		return out, workStep{"signature", value.ErrDenied}
	}
	last, current, e := s.current(bounded, w, h["kid"])
	until = identity.Earlier(until, last.Trust.FreshUntil)
	if e != nil || last.Trust.Revision != first.Trust.Revision || !bytes.Equal(current.PublicKey, key.PublicKey) || !current.NotBefore.Equal(key.NotBefore) || !current.NotAfter.Equal(key.NotAfter) || bounded.Err() != nil || !s.now().Before(until) || !w.Matches(receiver, s.now()) {
		return out, value.ErrUnavailable
	}
	out = value.AuthenticatedAPIContextWork{Work: w, KeyID: key.ID, TrustRevision: first.Trust.Revision, VerifiedAt: s.now().UTC(), ValidUntil: until}
	if !out.Valid(s.now()) {
		return value.AuthenticatedAPIContextWork{}, value.ErrUnavailable
	}
	return out, nil
}

// workStep names where a work verification stopped, for operator
// diagnostics; its class is the wrapped error.
type workStep struct {
	step string
	err  error
}

func (e workStep) Error() string     { return "api context work " + e.step }
func (e workStep) Unwrap() error     { return e.err }
func (e workStep) FixedStep() string { return e.step }
