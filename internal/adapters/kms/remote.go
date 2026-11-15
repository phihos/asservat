package kms

import (
	"bytes"
	"context"
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
	// token, when set, authenticates a connector by its ServiceAccount token
	// instead of a client certificate (ADR-334).
	token func() ([]byte, error)
}

// Each facet holds only a short-lived client TLS credential and an authority
// reference. It never loads a wrapping key or exposes a second operation.
type RemoteSealer struct{ client *remoteKeyClient }
type RemoteOpener struct{ client *remoteKeyClient }

var _ evidence.KeySealer = (*RemoteSealer)(nil)
var _ evidence.KeyOpener = (*RemoteOpener)(nil)

func remoteClient(endpoint string, scope value.KeyScope, authority string, h *http.Client, token ...func() ([]byte, error)) (*remoteKeyClient, error) {
	var bearer func() ([]byte, error)
	if len(token) == 1 {
		bearer = token[0]
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || !scope.Valid() || !value.UUID(authority) || h == nil {
		return nil, ErrKeyService
	}
	t, ok := h.Transport.(*http.Transport)
	if !ok || t == nil || t.TLSClientConfig == nil || t.TLSClientConfig.InsecureSkipVerify || (bearer == nil) == (len(t.TLSClientConfig.Certificates) == 0 && t.TLSClientConfig.GetClientCertificate == nil) || t.TLSClientConfig.MaxVersion != 0 && t.TLSClientConfig.MaxVersion < tls.VersionTLS13 {
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
	return &remoteKeyClient{u.String(), authority, scope, client, bearer}, nil
}

// NewRemoteSealer authenticates with h's client certificate or, when token is
// given, with a connector's ServiceAccount token (ADR-334).
func NewRemoteSealer(endpoint string, scope value.KeyScope, authority string, h *http.Client, token ...func() ([]byte, error)) (*RemoteSealer, error) {
	if len(token) > 1 {
		return nil, ErrKeyService
	}
	c, err := remoteClient(endpoint, scope, authority, h, token...)
	if err != nil {
		return nil, err
	}
	return &RemoteSealer{c}, nil
}
func NewRemoteOpener(endpoint string, scope value.KeyScope, authority string, h *http.Client) (*RemoteOpener, error) {
	c, err := remoteClient(endpoint, scope, authority, h)
	if err != nil {
		return nil, err
	}
	return &RemoteOpener{c}, nil
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
	wire := contracts.KeyServiceRequest{Format: contracts.KeyServiceFormat, Scope: contracts.KeyScope{InstallationID: r.Scope.InstallationID, Purpose: r.Scope.Purpose, KeyID: r.Scope.KeyID}, AuthorityID: r.AuthorityID, Operation: r.Operation, Binding: r.Binding, Input: r.Input}
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
	if c.token != nil {
		token, err := c.token()
		if err != nil || len(token) == 0 {
			return result, ErrKeyService
		}
		req.Header.Set("Authorization", "Bearer "+string(token))
		clear(token)
	}
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
