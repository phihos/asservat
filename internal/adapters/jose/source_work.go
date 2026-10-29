package jose

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	app "asservat.local/asservat/internal/application/fleet"
	wire "asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"strings"
)

const SourceWorkType = "asservat-ordinary-packet-source-work+jws"

var _ app.SourceWorkSigner = (*APIContextWorkSignatures)(nil)
var _ app.SourceWorkVerifier = (*APIContextWorkSignatures)(nil)

func sourceWorkBytes(w app.SourceWork) ([]byte, error) {
	if !w.Stop && deliveryapp.SourceResourcesDigest(w.Source.Resources) != w.Source.Permit.Binding.ResourceDigest {
		return nil, value.ErrInvalid
	}
	program := make([]byte, 8*len(w.Source.Program))
	for i, ins := range w.Source.Program {
		at := program[i*8:]
		binary.LittleEndian.PutUint16(at, ins.Code)
		at[2], at[3] = ins.Jt, ins.Jf
		binary.LittleEndian.PutUint32(at[4:], ins.K)
	}
	if len(program) > 0 && sha256.Sum256(program) != w.Source.Permit.Binding.ProgramDigest {
		return nil, value.ErrInvalid
	}
	target, _ := json.Marshal(w.Target)
	node, _ := json.Marshal(w.Node)
	metadata := w.Source
	metadata.Program = nil
	source, _ := json.Marshal(metadata)
	return wire.EncodeSourceWork(wire.SourceWork{Format: wire.SourceWorkFormat, Channel: historyChannelWire(w.Channel), Target: target, Node: node, Source: source, ProgramLE: program, NotAfter: w.NotAfter, Stop: w.Stop, StopIssuedAt: w.StopIssuedAt})
}
func sourceWorkValue(b []byte) (app.SourceWork, error) {
	d, e := wire.DecodeSourceWork(b)
	if e != nil {
		return app.SourceWork{}, e
	}
	var target targets.PodResolution
	var node targets.PacketSourceObservation
	var source collector.PacketSource
	for _, entry := range []struct {
		raw   []byte
		value any
	}{{d.Target, &target}, {d.Node, &node}, {d.Source, &source}} {
		dec := json.NewDecoder(bytes.NewReader(entry.raw))
		dec.DisallowUnknownFields()
		if dec.Decode(entry.value) != nil {
			return app.SourceWork{}, value.ErrInvalid
		}
	}
	if len(d.ProgramLE)%8 != 0 || len(d.ProgramLE)/8 > planning.MaxFilterInstructions {
		return app.SourceWork{}, value.ErrInvalid
	}
	if len(source.Program) != 0 {
		return app.SourceWork{}, value.ErrInvalid
	}
	source.Program = make([]planning.BPFInstruction, len(d.ProgramLE)/8)
	for i := range source.Program {
		at := d.ProgramLE[i*8:]
		source.Program[i] = planning.BPFInstruction{Code: binary.LittleEndian.Uint16(at), Jt: at[2], Jf: at[3], K: binary.LittleEndian.Uint32(at[4:])}
	}
	w := app.SourceWork{Channel: historyChannelValue(d.Channel), Target: target, Node: node, Source: source, NotAfter: d.NotAfter, Stop: d.Stop, StopIssuedAt: d.StopIssuedAt}
	canonical, e := sourceWorkBytes(w)
	if e != nil || !bytes.Equal(canonical, b) {
		return app.SourceWork{}, value.ErrInvalid
	}
	return w, nil
}

func (s *APIContextWorkSignatures) sourceCurrent(ctx context.Context, w app.SourceWork, kid string) (value.APIContextWorkTrust, value.WorkKey, error) {
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
	if len(key.PublicKey) != ed25519.PublicKeySize || w.IssuedAt().Before(key.NotBefore) || w.NotAfter.After(key.NotAfter) || s.now().Before(key.NotBefore) || !s.now().Before(key.NotAfter) {
		return zero, value.WorkKey{}, value.ErrDenied
	}
	return t, key, nil
}
func (s *APIContextWorkSignatures) SignSourceWork(ctx context.Context, w app.SourceWork) ([]byte, error) {
	if s == nil || s.signer == nil || ctx == nil || s.now == nil {
		return nil, value.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, w.NotAfter)
	defer stop()
	first, key, e := s.sourceCurrent(call, w, s.keyID)
	if e != nil {
		return nil, e
	}
	until := identity.Earlier(w.NotAfter, first.Trust.FreshUntil)
	bounded, cancel := context.WithDeadline(call, until)
	defer cancel()
	payload, e := sourceWorkBytes(w)
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
	_ = h.Set(jws.TypeKey, SourceWorkType)
	_ = h.Set(jws.KeyIDKey, s.keyID)
	signed, e := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd25519(), signer, jws.WithProtectedHeaders(h)))
	if e != nil || len(signed) > wire.SourceSignedWorkBytes {
		clear(signed)
		return nil, value.ErrUnavailable
	}
	actual, verifyErr := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd25519(), pub))
	defer clear(actual)
	if verifyErr != nil || !bytes.Equal(actual, payload) {
		clear(signed)
		return nil, value.ErrDenied
	}
	last, current, e := s.sourceCurrent(bounded, w, s.keyID)
	if e != nil || last.Trust.Revision != first.Trust.Revision || !bytes.Equal(current.PublicKey, key.PublicKey) || !current.NotBefore.Equal(key.NotBefore) || !current.NotAfter.Equal(key.NotAfter) || bounded.Err() != nil || !s.now().Before(identity.Earlier(until, last.Trust.FreshUntil)) {
		clear(signed)
		return nil, value.ErrUnavailable
	}
	return signed, nil
}
func (s *APIContextWorkSignatures) VerifySourceWork(ctx context.Context, encoded []byte, r value.APIContextReceiver) (app.AuthenticatedSourceWork, error) {
	var out app.AuthenticatedSourceWork
	if s == nil || s.now == nil || s.trust == nil || ctx == nil || ctx.Err() != nil || !r.Valid(s.now()) || len(encoded) == 0 || len(encoded) > wire.SourceSignedWorkBytes {
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
	if json.Unmarshal(header, &h) != nil || len(h) != 3 || h["alg"] != "Ed25519" || h["typ"] != SourceWorkType || !identity.Text(h["kid"], 128) {
		return out, value.ErrDenied
	}
	payload, ok := rawURL(parts[1], wire.SourceWorkBytes)
	if !ok {
		return out, value.ErrInvalid
	}
	defer clear(payload)
	signature, ok := rawURL(parts[2], ed25519.SignatureSize)
	if !ok || len(signature) != ed25519.SignatureSize {
		return out, value.ErrInvalid
	}
	w, e := sourceWorkValue(payload)
	if e != nil || !w.Matches(r, s.now()) {
		return out, value.ErrDenied
	}
	call, stop := context.WithDeadline(ctx, identity.Earlier(w.NotAfter, r.ValidUntil))
	defer stop()
	first, key, e := s.sourceCurrent(call, w, h["kid"])
	if e != nil {
		return out, e
	}
	until := identity.Earlier(w.NotAfter, identity.Earlier(r.ValidUntil, first.Trust.FreshUntil))
	bounded, cancel := context.WithDeadline(call, until)
	defer cancel()
	actual, e := jws.Verify(encoded, jws.WithKey(jwa.EdDSAEd25519(), ed25519.PublicKey(key.PublicKey)))
	defer clear(actual)
	if e != nil || !bytes.Equal(actual, payload) {
		return out, value.ErrDenied
	}
	last, current, e := s.sourceCurrent(bounded, w, h["kid"])
	until = identity.Earlier(until, last.Trust.FreshUntil)
	if e != nil || last.Trust.Revision != first.Trust.Revision || !bytes.Equal(current.PublicKey, key.PublicKey) || !current.NotBefore.Equal(key.NotBefore) || !current.NotAfter.Equal(key.NotAfter) || bounded.Err() != nil || !s.now().Before(until) || !w.Matches(r, s.now()) {
		return out, value.ErrUnavailable
	}
	out = app.AuthenticatedSourceWork{Work: w, KeyID: key.ID, TrustRevision: first.Trust.Revision, VerifiedAt: s.now().UTC(), ValidUntil: until}
	if !out.Valid(s.now()) {
		return app.AuthenticatedSourceWork{}, value.ErrUnavailable
	}
	return out, nil
}
