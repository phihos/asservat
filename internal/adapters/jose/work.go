// Package jose implements the pinned RFC 9864 Ed25519 work-signature profile.
// It is not peer enrollment, effect admission or an execution dispatcher.
package jose

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	wire "asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const WorkType = "asservat-internal-work+jws"
const MaxSignedWork = 128 << 10

//go:embed schemas/*.json
var schemas embed.FS

type denyLoader struct{}

func (denyLoader) Load(string) (any, error) { return nil, value.ErrInvalid }

type WorkVerifier struct {
	trust  app.WorkTrustReader
	now    func() time.Time
	schema *jsonschema.Schema
}

var _ app.RunActionVerifier = (*WorkVerifier)(nil)

func NewWorkVerifier(trust app.WorkTrustReader, now func() time.Time) (*WorkVerifier, error) {
	if trust == nil || now == nil {
		return nil, value.ErrInvalid
	}
	b, err := schemas.ReadFile("schemas/internal-work.schema.json")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	var doc any
	if json.Unmarshal(b, &doc) != nil {
		return nil, value.ErrUnavailable
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	c.AssertFormat()
	name := "https://asservat.io/spec/v1/internal-work.schema.json"
	if c.AddResource(name, doc) != nil {
		return nil, value.ErrUnavailable
	}
	schema, err := c.Compile(name + "#/$defs/work")
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &WorkVerifier{trust: trust, now: now, schema: schema}, nil
}

func strictJSON(b []byte, maximum, tokens int) bool {
	if len(b) == 0 || len(b) > maximum {
		return false
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	for i := 0; ; i++ {
		token, err := d.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil || i >= tokens || d.StackDepth() > 32 {
			return false
		}
		if token.Kind() == '0' {
			n, err := strconv.ParseInt(token.String(), 10, 64)
			if err != nil || n > 9007199254740991 || n < -9007199254740991 {
				return false
			}
		}
	}
	return json.Valid(b)
}
func rawURL(s string, max int) ([]byte, bool) {
	if len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) <= max && base64.RawURLEncoding.EncodeToString(b) == s
}
func digestValue(s string) artifact.Digest {
	var d artifact.Digest
	b, _ := hex.DecodeString(s)
	copy(d[:], b)
	return d
}
func instant(s string) time.Time { t, _ := time.Parse(time.RFC3339Nano, s); return t }
func canonicalInstant(s string) bool {
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && t.UTC().Format(time.RFC3339Nano) == s
}
func reference(r wire.WorkReference) value.Reference {
	return value.Reference{ID: r.ID, Region: r.Region, Digest: digestValue(r.Digest), ExpiresAt: instant(r.ExpiresAt)}
}

func (v *WorkVerifier) VerifyRunAction(ctx context.Context, encoded []byte, receiver value.Receiver) (value.AuthenticatedAction, error) {
	var out value.AuthenticatedAction
	if v == nil || v.trust == nil || v.now == nil || ctx.Err() != nil || !receiver.Valid(v.now()) {
		return out, value.ErrUnavailable
	}
	if len(encoded) == 0 || len(encoded) > MaxSignedWork {
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
	if json.Unmarshal(header, &h) != nil || len(h) != 3 || h["alg"] != "Ed25519" || h["typ"] != WorkType || !identity.Text(h["kid"], 128) {
		return out, value.ErrDenied
	}
	payload, ok := rawURL(parts[1], 64<<10)
	if !ok {
		return out, value.ErrInvalid
	}
	signature, ok := rawURL(parts[2], ed25519.SignatureSize)
	if !ok || len(signature) != ed25519.SignatureSize {
		return out, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	trust, err := v.trust.WorkTrust(ctx, receiver)
	if err != nil || ctx.Err() != nil || !trust.Valid(v.now()) {
		return out, value.ErrUnavailable
	}
	var selected *value.WorkKey
	for _, k := range trust.Keys {
		if k.ID == h["kid"] {
			cloned := k
			cloned.PublicKey = bytes.Clone(k.PublicKey)
			selected = &cloned
			break
		}
	}
	if selected == nil || selected.ClusterID != receiver.ClusterID || selected.IssuerEpoch != receiver.IssuerEpoch || v.now().Before(selected.NotBefore) || !v.now().Before(selected.NotAfter) {
		return out, value.ErrDenied
	}
	// The library constructs/verifies standard JWS framing. No algorithm
	// inference, incoming key set, remote key URL or custom signature plugin.
	verified, err := jws.Verify(encoded, jws.WithKey(jwa.EdDSAEd25519(), ed25519.PublicKey(selected.PublicKey)))
	if err != nil || !bytes.Equal(verified, payload) {
		return out, value.ErrDenied
	}
	if !strictJSON(payload, 64<<10, 16384) {
		return out, value.ErrInvalid
	}
	canonical := jsontext.Value(bytes.Clone(payload))
	if canonical.Canonicalize() != nil || !bytes.Equal(canonical, payload) {
		return out, value.ErrInvalid
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil || v.schema.Validate(doc) != nil {
		return out, value.ErrInvalid
	}
	var dto wire.RunActionWork
	if json.Unmarshal(payload, &dto) != nil || dto.Purpose != "runAction" || dto.Recipient != "node" {
		return out, value.ErrUnsupported
	}
	for _, stamp := range []string{dto.IssuedAt, dto.NotAfter, dto.ScopeRef.ExpiresAt, dto.AuthorityRef.ExpiresAt, dto.BudgetRef.ExpiresAt, dto.AuditRef.ExpiresAt} {
		if !canonicalInstant(stamp) {
			return out, value.ErrInvalid
		}
	}
	work := value.RunAction{WorkID: dto.WorkID, OperationID: dto.OperationID, ClusterID: dto.ClusterID, IssuerEpoch: dto.IssuerEpoch, DeliveryFence: dto.DeliveryFence, IssuedAt: instant(dto.IssuedAt), NotAfter: instant(dto.NotAfter), ScopeDigest: digestValue(dto.ScopeDigest), Scope: reference(dto.ScopeRef), Authority: reference(dto.AuthorityRef), Budget: reference(dto.BudgetRef), Audit: reference(dto.AuditRef), RequiredCapabilities: slices.Clone(dto.RequiredCapabilities), PodUID: dto.Target.PodUID, NodeUID: dto.Target.NodeUID, NodeBootID: dto.Target.NodeBootID, CaptureID: dto.Payload.CaptureID, ActionID: dto.Payload.ActionID, AttemptID: dto.Payload.AttemptID}
	now := v.now()
	if err = work.Validate(receiver, now); err != nil {
		return out, err
	}
	if ctx.Err() != nil || !trust.Valid(now) {
		return out, value.ErrUnavailable
	}
	if work.IssuedAt.Before(selected.NotBefore) || work.NotAfter.After(selected.NotAfter) {
		return out, value.ErrDenied
	}
	until := identity.Earlier(work.NotAfter, trust.FreshUntil)
	until = identity.Earlier(until, receiver.ValidUntil)
	return value.AuthenticatedAction{Work: work, KeyID: selected.ID, TrustRevision: trust.Revision, VerifiedAt: now, ValidUntil: until}, nil
}
