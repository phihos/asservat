package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"io"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

// The four-object format is reused as control-data custody, never published as
// evidence. Explicit per-role bounds cap the finite transfer before decoding:
// 192 KiB data, 4 KiB one-frame index, 128 KiB encrypted metadata, 32 KiB commit.
// Their base64 expansion plus a closed JSON envelope fits 512 KiB. Registration
// retains its existing, larger reservation limits; these do not refund charge.
const HistoryBundleMaxBytes = value.HistoryBundleMaxBytes

var historyObjectLimits = value.HistoryCiphertextLimits()

type HistoryBundle = value.HistoryCiphertexts

func EncodeHistoryBundle(b HistoryBundle) ([]byte, error) { return value.EncodeHistoryCiphertexts(b) }
func DecodeHistoryBundle(b []byte) (HistoryBundle, error) { return value.DecodeHistoryCiphertexts(b) }

type historyManifest struct {
	Format      string
	Expectation value.HistoryExpectation
	Layout      json.RawMessage
}

// SealHistoryParameters receives independently authorized metadata; it confers
// no admission or disclosure rights. The sealer must be the hub's control-key
// facet, never an artifact unwrap credential. Payload bytes never enter KMS.
func SealHistoryParameters(ctx context.Context, e value.HistoryExpectation, p value.HistoryParameters, keys evidence.KeySealer, mac app.HistoryKeys) (HistoryBundle, error) {
	var out HistoryBundle
	if ctx == nil || ctx.Err() != nil || keys == nil || mac == nil || !e.Matches(p) || e.MACVersion != mac.AccountVersion() {
		return out, artifact.ErrInvalid
	}
	s, k, err := app.HistoryParameterKeys(mac, e.RootID, p)
	if err != nil || s != e.SelectorKey || k != e.SettingsKey {
		return out, artifact.ErrIntegrity
	}
	plain, err := value.CanonicalHistoryParameters(p)
	if err != nil {
		return out, err
	}
	defer clear(plain)
	encoder, err := framed.Prepare(ctx, e.Binding(), keys)
	if err != nil {
		return out, err
	}
	metadata, err := framed.PrepareManifest(ctx, e.Binding(), keys)
	if err != nil {
		return out, err
	}
	var data, index bytes.Buffer
	l, err := encoder.Encode(ctx, bytes.NewReader(plain), &data, &index, value.MaxHistoryParameters)
	if err != nil {
		return out, err
	}
	layout, err := framed.MarshalLayout(l)
	if err != nil {
		return out, err
	}
	defer clear(layout)
	m, err := json.Marshal(historyManifest{"capture-parameters-manifest/v1", e, layout})
	if err != nil || len(m) > value.MaxHistoryManifest {
		clear(m)
		return out, artifact.ErrLimit
	}
	defer clear(m)
	cipher, key, err := metadata.Seal(ctx, m)
	if err != nil {
		return out, err
	}
	// Commit identity comes from the subsequent version-pinned PUT receipt;
	// it is completed by BindHistoryCommit, not invented by this encoder.
	out[0], out[1], out[2] = bytes.Clone(data.Bytes()), bytes.Clone(index.Bytes()), cipher
	commit, err := json.Marshal(key)
	if err != nil {
		out.Clear()
		return HistoryBundle{}, err
	}
	out[3] = commit
	if !out.Valid() {
		out.Clear()
		return HistoryBundle{}, artifact.ErrLimit
	}
	return out, nil
}

// BindHistoryCommit runs on the region only after the acknowledged immutable
// manifest write. SQL retains the final four ciphertext receipts, not keys.
func BindHistoryCommit(e value.HistoryExpectation, b HistoryBundle, m artifact.CopyReceipt) ([]byte, error) {
	if !e.Valid() || !b.Valid() || m.Bytes != int64(len(b[2])) || m.SHA256 != artifact.Digest(sha256.Sum256(b[2])) {
		return nil, artifact.ErrIntegrity
	}
	var key artifact.SealedKey
	if json.Unmarshal(b[3], &key) != nil {
		return nil, artifact.ErrInvalid
	}
	v, err := manifest.New()
	if err != nil {
		return nil, err
	}
	return v.MarshalCommit(e.Registration.Location, m, key)
}

type historyMemorySource []byte

func (s historyMemorySource) ReadRange(ctx context.Context, off, n int64) ([]byte, error) {
	if ctx.Err() != nil || off < 0 || n < 0 || off > int64(len(s)) || n > int64(len(s))-off {
		return nil, artifact.ErrIntegrity
	}
	return bytes.Clone(s[off : off+n]), nil
}

type historyDelivery struct{ bytes.Buffer }

func (d *historyDelivery) Send(ctx context.Context, b []byte) error {
	if ctx.Err() != nil || d.Len()+len(b) > value.MaxHistoryParameters {
		return artifact.ErrLimit
	}
	_, err := d.Write(b)
	return err
}

// OpenHistoryParameters follows exact retained ciphertext receipts. Authorization
// precedes fetching, and the caller must recheck it before disclosing plaintext.
func OpenHistoryParameters(ctx context.Context, e value.HistoryExpectation, c artifact.Copies, b HistoryBundle, keys evidence.KeyOpener, mac app.HistoryKeys) (value.HistoryParameters, error) {
	var zero value.HistoryParameters
	if ctx == nil || ctx.Err() != nil || !e.Valid() || !b.Valid() || c.Validate(e.Registration) != nil || keys == nil || mac == nil || mac.AccountVersion() != e.MACVersion {
		return zero, artifact.ErrInvalid
	}
	for i, v := range b {
		if c[i].Bytes != int64(len(v)) || c[i].SHA256 != artifact.Digest(sha256.Sum256(v)) {
			return zero, artifact.ErrIntegrity
		}
	}
	v, err := manifest.New()
	if err != nil {
		return zero, err
	}
	key, err := v.ParseCommit(b[3], e.Registration.Location, c[2])
	if err != nil {
		return zero, err
	}
	plain, err := framed.OpenManifest(ctx, e.Binding(), keys, key, b[2], c[2].SHA256)
	if err != nil {
		return zero, err
	}
	defer clear(plain)
	if len(plain) > value.MaxHistoryManifest {
		return zero, artifact.ErrLimit
	}
	var m historyManifest
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || m.Format != "capture-parameters-manifest/v1" {
		return zero, artifact.ErrIntegrity
	}
	want, _ := json.Marshal(e)
	got, _ := json.Marshal(m.Expectation)
	w, g := jsontext.Value(want), jsontext.Value(got)
	if w.Canonicalize() != nil || g.Canonicalize() != nil || !bytes.Equal(w, g) {
		return zero, artifact.ErrIntegrity
	}
	l, err := framed.ParseLayout(m.Layout, e.Binding())
	if err != nil || l.NativeBytes > value.MaxHistoryParameters || l.DataSHA256 != c[0].SHA256 || l.IndexSHA256 != c[1].SHA256 {
		return zero, artifact.ErrIntegrity
	}
	r, err := framed.Open(ctx, l, keys, historyMemorySource(b[0]), historyMemorySource(b[1]))
	if err != nil {
		return zero, err
	}
	var delivery historyDelivery
	defer func() { clear(delivery.Bytes()) }()
	if err = r.Read(ctx, 0, l.NativeBytes, &delivery); err != nil {
		return zero, err
	}
	p, err := value.ParseHistoryParameters(delivery.Bytes())
	if err != nil || !e.Matches(p) {
		return zero, artifact.ErrIntegrity
	}
	s, k, err := app.HistoryParameterKeys(mac, e.RootID, p)
	if err != nil || s != e.SelectorKey || k != e.SettingsKey || ctx.Err() != nil {
		return zero, artifact.ErrIntegrity
	}
	return p, nil
}

// HistoryObjects has only parameter-prefix storage credentials. It never uses
// evidence-store credentials or audit objects' nondeletion policy.
type HistoryObjects struct {
	Store   *Store
	StoreID string
}

func historyPrefix(e value.HistoryExpectation) string {
	return "history/v1/" + e.RootID + "/" + e.Registration.Location.ClusterID + "/" + e.Registration.Location.ArtifactID + "/" + e.Registration.Location.AttemptID + "/"
}
func (s HistoryObjects) Write(ctx context.Context, e value.HistoryExpectation, b HistoryBundle) (artifact.Copies, error) {
	var out artifact.Copies
	if s.Store == nil || e.Registration.StoreID != s.StoreID || !e.Valid() || !b.Valid() {
		return out, artifact.ErrInvalid
	}
	call, cancel := context.WithDeadline(ctx, e.Registration.WriteUntil)
	defer cancel()
	for i, body := range b {
		if i == 3 {
			var err error
			body, err = BindHistoryCommit(e, b, out[2])
			if err != nil {
				return out, err
			}
		}
		o, err := s.Store.PutSmall(call, historyPrefix(e)+artifact.Role(i), body)
		if err != nil {
			return out, err
		}
		out[i] = artifact.CopyReceipt{VersionID: o.VersionID, ETag: o.ETag, Bytes: o.Bytes, SHA256: o.SHA256}
	}
	if call.Err() != nil || out.Validate(e.Registration) != nil {
		return out, artifact.ErrIntegrity
	}
	return out, nil
}
func (s HistoryObjects) Read(ctx context.Context, e value.HistoryExpectation, c artifact.Copies) (HistoryBundle, error) {
	var out HistoryBundle
	if s.Store == nil || e.Registration.StoreID != s.StoreID || !e.Valid() || c.Validate(e.Registration) != nil {
		return out, artifact.ErrInvalid
	}
	call, cancel := context.WithDeadline(ctx, e.Registration.ExpiresAt)
	defer cancel()
	for i, r := range c {
		_, b, err := s.Store.readAcknowledgedControlAudit(call, Object{Key: historyPrefix(e) + artifact.Role(i), VersionID: r.VersionID, ETag: r.ETag, Bytes: r.Bytes, SHA256: r.SHA256}, historyObjectLimits[i])
		if err != nil {
			out.Clear()
			return HistoryBundle{}, err
		}
		out[i] = b
	}
	if !out.Valid() {
		out.Clear()
		return HistoryBundle{}, artifact.ErrLimit
	}
	return out, nil
}

// Purge requires independently established writer quiescence and a deletion
// lease. Time alone is deliberately insufficient; the ledger owns that proof.
func (s HistoryObjects) Purge(ctx context.Context, e value.HistoryExpectation) error {
	if s.Store == nil || !e.Valid() || e.Registration.StoreID != s.StoreID {
		return artifact.ErrInvalid
	}
	return s.Store.purgePrefix(ctx, historyPrefix(e))
}

// HistoryCodec is composed only with the protected control-data key facets.
// Regional transport receives ciphertext and never this key opener.
type HistoryCodec struct {
	Sealer evidence.KeySealer
	Opener evidence.KeyOpener
	Keys   app.HistoryKeys
}

func (c HistoryCodec) SealHistory(ctx context.Context, e value.HistoryExpectation, p value.HistoryParameters) (value.HistoryCiphertexts, error) {
	return SealHistoryParameters(ctx, e, p, c.Sealer, c.Keys)
}
func (c HistoryCodec) OpenHistory(ctx context.Context, e value.HistoryExpectation, copies artifact.Copies, b value.HistoryCiphertexts) (value.HistoryParameters, error) {
	return OpenHistoryParameters(ctx, e, copies, b, c.Opener, c.Keys)
}

var _ app.HistoryParameterCodec = HistoryCodec{}
