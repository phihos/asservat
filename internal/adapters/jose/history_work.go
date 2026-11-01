package jose

import (
	app "asservat.local/asservat/internal/application/fleet"
	wire "asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"strings"
)

const HistoryWorkType = "asservat-history-work+jws"

var _ app.HistoryWorkSigner = (*APIContextWorkSignatures)(nil)
var _ app.HistoryWorkVerifier = (*APIContextWorkSignatures)(nil)

func historyChannelWire(c value.APIContextChannel) wire.APIContextChannel {
	p, e, h := c.Connector, c.Executor, c.Hub
	return wire.APIContextChannel{RootID: c.RootID, ExchangeID: c.ExchangeID, Challenge: c.Challenge,
		Hub:       wire.APIContextOwner{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
		Connector: wire.APIContextConnector{InstallationID: p.Binding.InstallationID, ClusterID: p.Binding.ClusterID, IssuerEpoch: p.Binding.IssuerEpoch, PeerID: p.Binding.PeerID, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch, LeafDigest: apiContextDigest(c.ConnectorLeaf)},
		Executor:  wire.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: apiContextDigest(e.StartupDigest), ImageDigest: apiContextDigest(e.ImageDigest)}}
}
func historyChannelValue(c wire.APIContextChannel) value.APIContextChannel {
	p, e, h := c.Connector, c.Executor, c.Hub
	return value.APIContextChannel{RootID: c.RootID, ExchangeID: c.ExchangeID, Challenge: c.Challenge,
		Hub:       value.OwnerBinding{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
		Connector: value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PeerID: p.PeerID, Role: value.ConnectorPeer}, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch}, ConnectorLeaf: digestValue(p.LeafDigest),
		Executor: value.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: digestValue(e.StartupDigest), ImageDigest: digestValue(e.ImageDigest)}}
}
func historyWorkBytes(w app.HistoryWork) ([]byte, error) {
	a, e := json.Marshal(w.Authority)
	if e != nil {
		return nil, value.ErrInvalid
	}
	return wire.EncodeHistoryWork(wire.HistoryWork{Format: wire.HistoryWorkFormat, Channel: historyChannelWire(w.Channel), Authority: a})
}
func historyWorkValue(b []byte) (app.HistoryWork, error) {
	d, e := wire.DecodeHistoryWork(b)
	if e != nil {
		return app.HistoryWork{}, e
	}
	var a capture.HistoryOperationAuthority
	dec := json.NewDecoder(bytes.NewReader(d.Authority))
	dec.DisallowUnknownFields()
	if dec.Decode(&a) != nil {
		return app.HistoryWork{}, value.ErrInvalid
	}
	w := app.HistoryWork{Channel: historyChannelValue(d.Channel), Authority: a}
	canonical, e := historyWorkBytes(w)
	if e != nil || !bytes.Equal(canonical, b) {
		return app.HistoryWork{}, value.ErrInvalid
	}
	return w, nil
}
func (s *APIContextWorkSignatures) historyCurrent(ctx context.Context, w app.HistoryWork, kid string) (value.APIContextWorkTrust, value.WorkKey, error) {
	var zero value.APIContextWorkTrust
	var key value.WorkKey
	if s == nil || s.trust == nil || s.now == nil || ctx == nil || ctx.Err() != nil || !w.Valid(s.now()) {
		return zero, key, value.ErrDenied
	}
	t, e := s.trust.APIContextWorkTrust(ctx)
	c := w.Channel
	if e != nil || ctx.Err() != nil || !w.Valid(s.now()) || !t.Valid(s.now()) || t.RootID != c.RootID || t.InstallationID != c.Connector.Binding.InstallationID || t.ClusterID != c.Connector.Binding.ClusterID || t.IssuerEpoch != c.Connector.Binding.IssuerEpoch {
		return zero, key, value.ErrUnavailable
	}
	for _, k := range t.Trust.Keys {
		if k.ID == kid {
			key = k
			key.PublicKey = bytes.Clone(k.PublicKey)
			break
		}
	}
	if len(key.PublicKey) != ed25519.PublicKeySize || w.Authority.StartedAt.Before(key.NotBefore) || w.Authority.NotAfter.After(key.NotAfter) || s.now().Before(key.NotBefore) || !s.now().Before(key.NotAfter) {
		return zero, value.WorkKey{}, value.ErrDenied
	}
	return t, key, nil
}
func (s *APIContextWorkSignatures) SignHistoryWork(ctx context.Context, w app.HistoryWork) ([]byte, error) {
	if s == nil || s.signer == nil || ctx == nil || s.now == nil {
		return nil, value.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, w.Authority.NotAfter)
	defer stop()
	first, key, e := s.historyCurrent(call, w, s.keyID)
	if e != nil {
		return nil, e
	}
	until := identity.Earlier(w.Authority.NotAfter, first.Trust.FreshUntil)
	bounded, cancel := context.WithDeadline(call, until)
	defer cancel()
	payload, e := historyWorkBytes(w)
	if e != nil {
		return nil, e
	}
	defer clear(payload)
	signer := s.signer(bounded)
	if signer == nil {
		return nil, value.ErrUnavailable
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, key.PublicKey) {
		return nil, value.ErrDenied
	}
	h := jws.NewHeaders()
	_ = h.Set(jws.TypeKey, HistoryWorkType)
	_ = h.Set(jws.KeyIDKey, s.keyID)
	signed, e := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), signer, jws.WithProtectedHeaders(h)))
	if e != nil || len(signed) > wire.APIContextSignedWorkBytes {
		clear(signed)
		return nil, value.ErrUnavailable
	}
	actual, verifyErr := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub))
	defer clear(actual)
	if verifyErr != nil || !bytes.Equal(actual, payload) {
		clear(signed)
		return nil, value.ErrDenied
	}
	last, current, e := s.historyCurrent(bounded, w, s.keyID)
	if e != nil || last.Trust.Revision != first.Trust.Revision || !bytes.Equal(current.PublicKey, key.PublicKey) || !current.NotBefore.Equal(key.NotBefore) || !current.NotAfter.Equal(key.NotAfter) || bounded.Err() != nil || !s.now().Before(identity.Earlier(until, last.Trust.FreshUntil)) {
		clear(signed)
		return nil, value.ErrUnavailable
	}
	return signed, nil
}
func (s *APIContextWorkSignatures) VerifyHistoryWork(ctx context.Context, encoded []byte, r value.APIContextReceiver) (app.AuthenticatedHistoryWork, error) {
	var out app.AuthenticatedHistoryWork
	if s == nil || s.now == nil || s.trust == nil || ctx == nil || ctx.Err() != nil || !r.Valid(s.now()) || len(encoded) == 0 || len(encoded) > wire.APIContextSignedWorkBytes {
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
	if json.Unmarshal(header, &h) != nil || len(h) != 3 || h["alg"] != "Ed25519" || h["typ"] != HistoryWorkType || !identity.Text(h["kid"], 128) {
		return out, value.ErrDenied
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
	w, e := historyWorkValue(payload)
	if e != nil || !w.Matches(r, s.now()) {
		return out, value.ErrDenied
	}
	call, stop := context.WithDeadline(ctx, identity.Earlier(w.Authority.NotAfter, r.ValidUntil))
	defer stop()
	first, key, e := s.historyCurrent(call, w, h["kid"])
	if e != nil {
		return out, e
	}
	until := identity.Earlier(w.Authority.NotAfter, identity.Earlier(r.ValidUntil, first.Trust.FreshUntil))
	bounded, cancel := context.WithDeadline(call, until)
	defer cancel()
	actual, e := jws.Verify(encoded, jws.WithKey(jwa.EdDSAEd25519(), ed25519.PublicKey(key.PublicKey)))
	defer clear(actual)
	if e != nil || !bytes.Equal(actual, payload) {
		return out, value.ErrDenied
	}
	last, current, e := s.historyCurrent(bounded, w, h["kid"])
	until = identity.Earlier(until, last.Trust.FreshUntil)
	if e != nil || last.Trust.Revision != first.Trust.Revision || !bytes.Equal(current.PublicKey, key.PublicKey) || !current.NotBefore.Equal(key.NotBefore) || !current.NotAfter.Equal(key.NotAfter) || bounded.Err() != nil || !s.now().Before(until) || !w.Matches(r, s.now()) {
		return out, value.ErrUnavailable
	}
	out = app.AuthenticatedHistoryWork{Work: w, KeyID: key.ID, TrustRevision: first.Trust.Revision, VerifiedAt: s.now().UTC(), ValidUntil: until}
	if !out.Valid(s.now()) {
		return app.AuthenticatedHistoryWork{}, value.ErrUnavailable
	}
	return out, nil
}
