package kms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Startup reads of provider-produced public values (Helm-native
// installation, field class J): the hub reads PKI CA certificates and its
// work-signing public key from OpenBao instead of an installer input.

func startupClient(roots [][]byte) (*http.Client, error) {
	pool := x509.NewCertPool()
	for _, der := range roots {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrKeyService
		}
		pool.AddCert(c)
	}
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, DisableCompression: true, MaxIdleConns: 1, IdleConnTimeout: time.Second}}, nil
}

func startupURL(endpoint, path string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || !strings.HasPrefix(path, "/v1/") {
		return "", ErrKeyService
	}
	u.Path = path
	return u.String(), nil
}

func startupCall(ctx context.Context, h *http.Client, method, endpoint, path, token string, body any, limit int64) ([]byte, error) {
	target, err := startupURL(endpoint, path)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, ErrKeyService
		}
		defer clear(b)
		reader = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, ErrKeyService
	}
	if token != "" {
		r.Header.Set("X-Vault-Token", token)
	}
	response, err := h.Do(r)
	if err != nil {
		return nil, errors.Join(ErrKeyService, err)
	}
	defer response.Body.Close()
	out, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(out)) > limit || response.StatusCode/100 != 2 {
		clear(out)
		return nil, ErrKeyService
	}
	return out, nil
}

// ReadPKIRoots returns the DER CA certificate(s) of an OpenBao PKI mount
// (`GET /v1/<mount>/ca/pem`, unauthenticated).
func ReadPKIRoots(ctx context.Context, endpoint string, roots [][]byte, mount string) ([][]byte, error) {
	if ctx == nil || !keyName.MatchString(mount) {
		return nil, ErrKeyService
	}
	h, err := startupClient(roots)
	if err != nil {
		return nil, err
	}
	defer h.CloseIdleConnections()
	raw, err := startupCall(ctx, h, http.MethodGet, endpoint, "/v1/"+mount+"/ca/pem", "", nil, 64<<10)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, ErrKeyService
		}
		if _, e := x509.ParseCertificate(block.Bytes); e != nil {
			return nil, ErrKeyService
		}
		out = append(out, block.Bytes)
	}
	if len(out) < 1 || len(out) > 8 {
		return nil, ErrKeyService
	}
	return out, nil
}

// ReadSigningPublicKey logs in once with the Pod's projected provider token
// to the given Kubernetes auth role, reads the transit key's latest version
// and public key, and revokes the token. The role's policy grants read on
// `<mount>/keys/<name>`.
func ReadSigningPublicKey(ctx context.Context, endpoint string, roots [][]byte, authMount, role string, jwt []byte, mount, name string) (int, ed25519.PublicKey, error) {
	if ctx == nil || !keyName.MatchString(authMount) || !keyName.MatchString(mount) || !keyName.MatchString(name) || role == "" || len(jwt) == 0 {
		return 0, nil, ErrKeyService
	}
	h, err := startupClient(roots)
	if err != nil {
		return 0, nil, err
	}
	defer h.CloseIdleConnections()
	raw, err := startupCall(ctx, h, http.MethodPost, endpoint, "/v1/auth/"+authMount+"/login", "", map[string]string{"role": role, "jwt": string(jwt)}, 64<<10)
	if err != nil {
		return 0, nil, err
	}
	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	err = json.Unmarshal(raw, &login)
	clear(raw)
	token := login.Auth.ClientToken
	if err != nil || !ValidProviderToken([]byte(token)) {
		return 0, nil, ErrKeyService
	}
	defer func() {
		revoke, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer end()
		_, _ = startupCall(revoke, h, http.MethodPost, endpoint, "/v1/auth/token/revoke-self", token, nil, 4096)
	}()
	raw, err = startupCall(ctx, h, http.MethodGet, endpoint, "/v1/"+mount+"/keys/"+name, token, nil, 256<<10)
	if err != nil {
		return 0, nil, err
	}
	var key struct {
		Data struct {
			Type          string `json:"type"`
			LatestVersion int    `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &key) != nil || key.Data.Type != "ed25519" || key.Data.LatestVersion < 1 || key.Data.LatestVersion > 2147483647 {
		return 0, nil, ErrKeyService
	}
	public, err := base64.StdEncoding.Strict().DecodeString(key.Data.Keys[strconv.Itoa(key.Data.LatestVersion)].PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return 0, nil, ErrKeyService
	}
	return key.Data.LatestVersion, public, nil
}
