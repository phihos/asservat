// Package kms supplies role-scoped OpenBao key wrapping. Evidence never passes
// through Transit; only small Tink keysets do.
package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	bao "github.com/openbao/openbao/api/v2"
)

var ErrKeyService = errors.New("key service refused or unavailable")
var keyName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// Sealer and Opener intentionally have disjoint method sets and credentials.
type Sealer struct {
	client                *bao.Client
	mount, key, reference string
}
type Opener struct {
	client                *bao.Client
	mount, key, reference string
}

var _ evidence.KeySealer = (*Sealer)(nil)
var _ evidence.KeyOpener = (*Opener)(nil)

type limitedBody struct {
	io.Reader
	io.Closer
}
type boundedTransport struct {
	http.RoundTripper
	source TokenSource
}

func (t boundedTransport) CloseIdleConnections() {
	if c, ok := t.RoundTripper.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.source != nil {
		token, err := t.source(r.Context())
		defer clear(token)
		if err != nil || r.Context().Err() != nil || !ValidProviderToken(token) {
			return nil, ErrKeyService
		}
		r = r.Clone(r.Context())
		r.Header.Set("X-Vault-Token", string(token))
	}
	v, err := t.RoundTripper.RoundTrip(r)
	if v != nil && v.Body != nil {
		v.Body = limitedBody{io.LimitReader(v.Body, 32769), v.Body}
	}
	return v, err
}

func client(endpoint, token string, h *http.Client) (*bao.Client, error) {
	return clientWithSource(endpoint, token, nil, h)
}
func clientWithSource(endpoint, token string, source TokenSource, h *http.Client) (*bao.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (token == "" && source == nil) || (token != "" && source != nil) || h == nil {
		return nil, artifact.ErrInvalid
	}
	c := bao.NewConfig() // does not inherit BAO_*/VAULT_* token/namespace/proxy flags
	c.Address, c.Timeout, c.MaxRetries = endpoint, 10*time.Second, 0
	copyClient := *h
	base := h.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	t, ok := base.(*http.Transport)
	if !ok || (t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify) {
		return nil, artifact.ErrInvalid
	}
	t = t.Clone()
	t.Proxy = nil // no ambient HTTP(S)_PROXY for key material
	copyClient.Transport = boundedTransport{t, source}
	copyClient.Timeout = 10 * time.Second
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.HttpClient = &copyClient
	b, err := bao.NewClient(c)
	if err != nil {
		return nil, ErrKeyService
	}
	b.SetToken(token)
	b.SetCheckRedirect(func(*http.Request, []*http.Request) error { return errors.New("KMS redirects disabled") })
	return b, nil
}

func NewSealer(endpoint, token, mount, key string, h *http.Client) (*Sealer, error) {
	if !keyName.MatchString(mount) || !keyName.MatchString(key) {
		return nil, artifact.ErrInvalid
	}
	c, err := client(endpoint, token, h)
	if err != nil {
		return nil, err
	}
	return &Sealer{c, mount, key, mount + "/" + key}, nil
}

func NewOpener(endpoint, token, mount, key string, h *http.Client) (*Opener, error) {
	if !keyName.MatchString(mount) || !keyName.MatchString(key) {
		return nil, artifact.ErrInvalid
	}
	c, err := client(endpoint, token, h)
	if err != nil {
		return nil, err
	}
	return &Opener{c, mount, key, mount + "/" + key}, nil
}

type wrappedPayload struct {
	Format        string `json:"format"`
	BindingSHA256 string `json:"bindingSHA256"`
	Keyset        []byte `json:"keyset"`
}

func bindingHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// call uses the maintained client's request/signaling code, with a bounded
// response and sanitized error. Library errors may include secret response text.
func call(ctx context.Context, c *bao.Client, path, field, value string) (string, error) {
	r := c.NewRequest(http.MethodPost, "/v1/"+path)
	if err := r.SetJSONBody(map[string]string{field: value}); err != nil {
		return "", ErrKeyService
	}
	response, err := c.RawRequestWithContext(ctx, r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		return "", ErrKeyService
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(b)
	if err != nil || len(b) > 32768 {
		return "", ErrKeyService
	}
	var v struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			Plaintext  string `json:"plaintext"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &v) != nil {
		return "", ErrKeyService
	}
	if field == "plaintext" {
		if len(v.Data.Ciphertext) < 1 || len(v.Data.Ciphertext) > 16384 {
			return "", ErrKeyService
		}
		return v.Data.Ciphertext, nil
	}
	if len(v.Data.Plaintext) < 1 || len(v.Data.Plaintext) > 16384 {
		return "", ErrKeyService
	}
	return v.Data.Plaintext, nil
}

func (s *Sealer) Seal(ctx context.Context, keyset, binding []byte) (artifact.SealedKey, error) {
	if s == nil || s.client == nil || ctx == nil || len(keyset) < 1 || len(keyset) > 4096 || len(binding) < 1 || len(binding) > 2048 {
		return artifact.SealedKey{}, artifact.ErrInvalid
	}
	p, err := json.Marshal(wrappedPayload{"asservat-keyset/v1", bindingHash(binding), keyset})
	if err != nil {
		return artifact.SealedKey{}, ErrKeyService
	}
	defer clear(p)
	c, err := call(ctx, s.client, s.mount+"/encrypt/"+s.key, "plaintext", base64.StdEncoding.EncodeToString(p))
	if err != nil {
		return artifact.SealedKey{}, err
	}
	return artifact.SealedKey{Reference: s.reference, Ciphertext: c}, nil
}

func (o *Opener) Open(ctx context.Context, sealed artifact.SealedKey, binding []byte) ([]byte, error) {
	if o == nil || o.client == nil || ctx == nil || sealed.Reference != o.reference || len(sealed.Ciphertext) < 1 || len(sealed.Ciphertext) > 16384 || len(binding) < 1 || len(binding) > 2048 {
		return nil, artifact.ErrInvalid
	}
	p, err := call(ctx, o.client, o.mount+"/decrypt/"+o.key, "ciphertext", sealed.Ciphertext)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.Strict().DecodeString(p)
	if err != nil {
		return nil, ErrKeyService
	}
	defer clear(b)
	var v wrappedPayload
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || v.Format != "asservat-keyset/v1" || v.BindingSHA256 != bindingHash(binding) || len(v.Keyset) < 1 || len(v.Keyset) > 4096 {
		clear(v.Keyset)
		return nil, artifact.ErrIntegrity
	}
	return v.Keyset, nil
}
