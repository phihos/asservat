package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type remoteKeyClient struct {
	endpoint, authority string
	scope               value.KeyScope
	client              *http.Client
}

// Each facet holds only a short-lived client TLS credential and an authority
// reference. It never loads a wrapping key or exposes a second operation.
type RemoteSealer struct{ client *remoteKeyClient }
type RemoteOpener struct{ client *remoteKeyClient }
type RemoteSigner struct {
	client  *remoteKeyClient
	version int
	public  ed25519.PublicKey
}

var _ evidence.KeySealer = (*RemoteSealer)(nil)
var _ evidence.KeyOpener = (*RemoteOpener)(nil)

func remoteClient(endpoint string, scope value.KeyScope, authority string, h *http.Client) (*remoteKeyClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || !scope.Valid() || !value.UUID(authority) || h == nil {
		return nil, ErrKeyService
	}
	t, ok := h.Transport.(*http.Transport)
	if !ok || t == nil || t.TLSClientConfig == nil || t.TLSClientConfig.InsecureSkipVerify || (len(t.TLSClientConfig.Certificates) == 0 && t.TLSClientConfig.GetClientCertificate == nil) || t.TLSClientConfig.MaxVersion != 0 && t.TLSClientConfig.MaxVersion < tls.VersionTLS13 {
		return nil, ErrKeyService
	}
	t = t.Clone()
	t.Proxy = nil
	t.DisableCompression = true
	t.MaxResponseHeaderBytes = 4096
	t.MaxConnsPerHost = 8
	t.TLSClientConfig.MinVersion = tls.VersionTLS13
	client := &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u.Path = contracts.KeyServicePath
	return &remoteKeyClient{u.String(), authority, scope, client}, nil
}

func NewRemoteSealer(endpoint string, scope value.KeyScope, authority string, h *http.Client) (*RemoteSealer, error) {
	if scope.Purpose == "policy-submission" {
		return nil, ErrKeyService
	}
	c, err := remoteClient(endpoint, scope, authority, h)
	if err != nil {
		return nil, err
	}
	return &RemoteSealer{c}, nil
}
func NewRemoteOpener(endpoint string, scope value.KeyScope, authority string, h *http.Client) (*RemoteOpener, error) {
	if scope.Purpose == "policy-submission" {
		return nil, ErrKeyService
	}
	c, err := remoteClient(endpoint, scope, authority, h)
	if err != nil {
		return nil, err
	}
	return &RemoteOpener{c}, nil
}
func NewRemoteSigner(endpoint string, scope value.KeyScope, authority string, version int, public ed25519.PublicKey, h *http.Client) (*RemoteSigner, error) {
	if scope.Purpose != "policy-submission" || version < 1 || version > 2147483647 || len(public) != ed25519.PublicKeySize {
		return nil, ErrKeyService
	}
	c, err := remoteClient(endpoint, scope, authority, h)
	if err != nil {
		return nil, err
	}
	return &RemoteSigner{c, version, bytes.Clone(public)}, nil
}

func (c *remoteKeyClient) call(ctx context.Context, r value.KeyRequest) (value.KeyResult, error) {
	var result value.KeyResult
	if c == nil || c.client == nil || ctx == nil || ctx.Err() != nil {
		return result, ErrKeyService
	}
	r.Scope, r.AuthorityID = c.scope, c.authority
	info, err := app.DescribeKeyRequest(r)
	if err != nil {
		return result, ErrKeyService
	}
	wire := contracts.KeyServiceRequest{Format: contracts.KeyServiceFormat, Scope: contracts.KeyScope{InstallationID: r.Scope.InstallationID, Purpose: r.Scope.Purpose, KeyID: r.Scope.KeyID}, AuthorityID: r.AuthorityID, Operation: r.Operation, Binding: r.Binding, Input: r.Input, Version: r.Version}
	if r.Operation == "unwrap" {
		wire.Sealed = &contracts.SealedLocalKey{Reference: r.Sealed.Reference, Ciphertext: r.Sealed.Ciphertext}
	}
	b, err := json.Marshal(wire)
	defer clear(b)
	if err != nil || len(b) > contracts.KeyServiceMaxBody {
		return result, ErrKeyService
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// net/http may finish closing a request body after Do returns. Give the
	// transport its own immutable copy rather than clearing a buffer it reads.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, io.NopCloser(bytes.NewReader(bytes.Clone(b))))
	if err != nil {
		return result, ErrKeyService
	}
	req.ContentLength = int64(len(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil || resp == nil || resp.Body == nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Content-Encoding") != "" {
		return result, ErrKeyService
	}
	out, err := contracts.DecodeKeyResponse(resp.Body)
	if err != nil {
		clear(out.Output)
		return result, ErrKeyService
	}
	until, err := time.Parse(time.RFC3339Nano, out.ValidUntil)
	if err != nil || until.UTC().Format(time.RFC3339Nano) != out.ValidUntil || !time.Now().Before(until) || until.After(time.Now().Add(5*time.Second)) || out.Format != contracts.KeyServiceFormat || out.Operation != r.Operation || out.RequestSHA256 != hex.EncodeToString(info.RequestDigest[:]) || ctx.Err() != nil {
		clear(out.Output)
		return result, ErrKeyService
	}
	result = value.KeyResult{Output: out.Output, RequestDigest: info.RequestDigest, ValidUntil: until}
	if out.Sealed != nil {
		result.Sealed = artifact.SealedKey{Reference: out.Sealed.Reference, Ciphertext: out.Sealed.Ciphertext}
	}
	if !result.Valid(r.Operation) || (r.Operation == "wrap") != (out.Sealed != nil) {
		clear(result.Output)
		return value.KeyResult{}, ErrKeyService
	}
	if r.Operation == "wrap" {
		check := value.KeyRequest{Scope: c.scope, AuthorityID: c.authority, Operation: "unwrap", Binding: r.Binding, Sealed: result.Sealed}
		if !check.Valid() {
			return value.KeyResult{}, ErrKeyService
		}
	}
	return result, nil
}

func (s *RemoteSealer) Seal(ctx context.Context, keyset, binding []byte) (artifact.SealedKey, error) {
	if s == nil {
		return artifact.SealedKey{}, ErrKeyService
	}
	r, err := s.client.call(ctx, value.KeyRequest{Operation: "wrap", Binding: binding, Input: keyset})
	return r.Sealed, err
}
func (s *RemoteOpener) Open(ctx context.Context, sealed artifact.SealedKey, binding []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrKeyService
	}
	r, err := s.client.call(ctx, value.KeyRequest{Operation: "unwrap", Binding: binding, Sealed: sealed})
	return r.Output, err
}

// Close releases this bounded operation's private transport pool. It neither
// revokes the original authority nor permits callers to extend its deadline.
func (s *RemoteOpener) Close() {
	if s != nil && s.client != nil && s.client.client != nil {
		s.client.client.CloseIdleConnections()
	}
}
func (s *RemoteSigner) ForContext(ctx context.Context) crypto.Signer {
	if s == nil || s.client == nil || ctx == nil {
		return nil
	}
	return &remoteRequestSigner{s, ctx}
}

type remoteRequestSigner struct {
	key *RemoteSigner
	ctx context.Context
}

func (s *remoteRequestSigner) Public() crypto.PublicKey {
	return ed25519.PublicKey(bytes.Clone(s.key.public))
}
func (s *remoteRequestSigner) Sign(_ io.Reader, input []byte, options crypto.SignerOpts) ([]byte, error) {
	if !plainEd25519Options(options) {
		return nil, ErrKeyService
	}
	r, err := s.key.client.call(s.ctx, value.KeyRequest{Operation: "sign", Input: input, Version: s.key.version})
	if err != nil || !ed25519.Verify(s.key.public, input, r.Output) {
		clear(r.Output)
		return nil, ErrKeyService
	}
	return r.Output, nil
}
