package kms

import (
	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	bao "github.com/openbao/openbao/api/v2"
	"io"
	"net/http"
	"time"
)

type OwnerCertificateIssuer struct {
	client                                    *bao.Client
	path, installation, cluster, epoch, usage string
	verify                                    *mtls.OwnerPeerVerifier
	now                                       func() time.Time
	pool                                      value.OwnerPool
}

var _ app.OwnerCertificateIssuer = (*OwnerCertificateIssuer)(nil)

// One fixed role/leaf purpose; no provider-selected private keys, alternate
// endpoint, root/role management, registration or automatic POST retry.
func NewOwnerCertificateIssuer(endpoint, token, mount, role, installation, cluster, epoch, usage string, roots *x509.CertPool, h *http.Client, now func() time.Time) (*OwnerCertificateIssuer, error) {
	return newOwnerCertificateIssuer(endpoint, token, mount, role, installation, cluster, epoch, usage, roots, nil, h, now)
}
func newOwnerCertificateIssuer(endpoint, token, mount, role, installation, cluster, epoch, usage string, roots *x509.CertPool, source TokenSource, h *http.Client, now func() time.Time) (*OwnerCertificateIssuer, error) {
	if !keyName.MatchString(mount) || !keyName.MatchString(role) || (usage != "server" && usage != "client") {
		return nil, value.ErrInvalid
	}
	v, e := mtls.NewOwnerPeerVerifier(roots, installation, cluster, epoch, now)
	if e != nil {
		return nil, e
	}
	c, e := clientWithSource(endpoint, token, source, h)
	if e != nil {
		return nil, e
	}
	return &OwnerCertificateIssuer{client: c, path: mount + "/sign/" + role, installation: installation, cluster: cluster, epoch: epoch, usage: usage, verify: v, now: now}, nil
}

func (s *OwnerCertificateIssuer) SignOwnerCertificate(ctx context.Context, p value.OwnerCertificatePermit, csr []byte) (value.IssuedOwnerCertificate, error) {
	var zero value.IssuedOwnerCertificate
	if s == nil || ctx == nil || s.client == nil || s.now == nil || !p.Valid(s.now()) || p.Binding.InstallationID != s.installation || p.Binding.ClusterID != s.cluster || p.Binding.IssuerEpoch != s.epoch || p.Usage != s.usage || !s.matchesPool(p.Configuration.Configuration.Pool) {
		return zero, value.ErrInvalid
	}
	key, e := mtls.EnrollmentKey(csr)
	if e != nil || key != p.PublicKeyDigest {
		return zero, value.ErrDenied
	}
	uri, e := mtls.OwnerURI(p.Binding)
	if e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, p.SignBefore)
	defer end()
	input := map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "uri_sans": []string{uri.String()}, "not_after": p.CertificateNotAfter.Format(time.RFC3339), "exclude_cn_from_sans": true, "format": "pem"}
	if p.Usage == "server" {
		name, e := mtls.OwnerServerName(p.Binding)
		if e != nil {
			return zero, e
		}
		if s.pool.NativeBootstrap != "" {
			common, err := mtls.OwnerBootstrapServerName(p.Configuration.Configuration.Pool)
			if err != nil {
				return zero, err
			}
			name += "," + common
		}
		input["alt_names"] = name
	}
	r := s.client.NewRequest(http.MethodPost, "/v1/"+s.path)
	if e = r.SetJSONBody(input); e != nil {
		return zero, value.ErrInvalid
	}
	response, e := s.client.RawRequestWithContext(ctx, r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if e != nil || response == nil || response.StatusCode != http.StatusOK {
		return zero, ErrKeyService
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(body)
	if e != nil || len(body) > 32768 {
		return zero, ErrKeyService
	}
	var wire struct {
		Data struct {
			Certificate string   `json:"certificate"`
			Chain       []string `json:"ca_chain"`
			Private     string   `json:"private_key"`
		}
	}
	if json.Unmarshal(body, &wire) != nil || wire.Data.Private != "" || len(wire.Data.Chain) > 3 {
		return zero, ErrKeyService
	}
	decode := func(s string) ([]byte, error) {
		b, rest := pem.Decode([]byte(s))
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(rest) != 0 || len(b.Bytes) < 1 || len(b.Bytes) > 16<<10 {
			return nil, value.ErrInvalid
		}
		return b.Bytes, nil
	}
	der, e := decode(wire.Data.Certificate)
	if e != nil {
		return zero, e
	}
	var chain [][]byte
	for _, raw := range wire.Data.Chain {
		d, e := decode(raw)
		if e != nil {
			return zero, e
		}
		chain = append(chain, d)
	}
	if ctx.Err() != nil || !p.Valid(s.now()) {
		return zero, value.ErrUnavailable
	}
	return s.verify.CheckOwnerCertificate(p, csr, der, chain)
}
