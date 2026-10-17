package kms

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	port "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	bao "github.com/openbao/openbao/api/v2"
)

// ConnectorIssuer only has sign permission on one operator-configured role.
// It cannot generate/export private keys, change roles/roots or activate peers.
type ConnectorIssuer struct {
	client                             *bao.Client
	path, installation, cluster, epoch string
	verify                             *mtls.PeerVerifier
	now                                func() time.Time
}

var _ port.CertificateIssuer = (*ConnectorIssuer)(nil)

func NewConnectorIssuer(endpoint, token, mount, role, installation, cluster, epoch string, roots *x509.CertPool, h *http.Client, now func() time.Time) (*ConnectorIssuer, error) {
	if !keyName.MatchString(mount) || !keyName.MatchString(role) || !authorization.UUID(cluster) || !authorization.UUID(epoch) {
		return nil, value.ErrInvalid
	}
	verify, err := mtls.NewPeerVerifier(roots, installation, value.ConnectorPeer, now)
	if err != nil {
		return nil, err
	}
	c, err := client(endpoint, token, h)
	if err != nil {
		return nil, value.ErrUnavailable
	}
	return &ConnectorIssuer{client: c, path: mount + "/sign/" + role, installation: installation, cluster: cluster, epoch: epoch, verify: verify, now: now}, nil
}

func (s *ConnectorIssuer) SignConnector(ctx context.Context, p value.CertificateIssuePermit, csr []byte) (value.IssuedCertificate, error) {
	var out value.IssuedCertificate
	if !p.Valid(s.now()) || p.Enrollment.Binding.InstallationID != s.installation || p.Enrollment.Binding.ClusterID != s.cluster || p.Enrollment.Binding.IssuerEpoch != s.epoch {
		return out, value.ErrDenied
	}
	key, err := mtls.EnrollmentKey(csr)
	if err != nil || key != p.Enrollment.PublicKeyDigest {
		return out, value.ErrDenied
	}
	u, err := mtls.PeerURI(p.Enrollment.Binding)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := s.client.NewRequest(http.MethodPost, "/v1/"+s.path)
	if r.SetJSONBody(map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "uri_sans": []string{u.String()}, "not_after": p.CertificateNotAfter().Format(time.RFC3339), "exclude_cn_from_sans": true, "format": "pem"}) != nil {
		return out, value.ErrInvalid
	}
	response, err := s.client.RawRequestWithContext(ctx, r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		return out, value.ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(body) > 32768 {
		return out, value.ErrUnavailable
	}
	var wire struct {
		Data struct {
			Certificate string   `json:"certificate"`
			CAChain     []string `json:"ca_chain"`
			PrivateKey  string   `json:"private_key"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Data.PrivateKey != "" || len(wire.Data.CAChain) > 3 {
		return out, value.ErrUnavailable
	}
	decode := func(encoded string) ([]byte, error) {
		if len(encoded) == 0 || len(encoded) > 24<<10 {
			return nil, value.ErrInvalid
		}
		block, rest := pem.Decode([]byte(encoded))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
			return nil, value.ErrDenied
		}
		return block.Bytes, nil
	}
	der, err := decode(wire.Data.Certificate)
	if err != nil {
		return out, err
	}
	var chain [][]byte
	for _, encoded := range wire.Data.CAChain {
		b, e := decode(encoded)
		if e != nil {
			return out, e
		}
		chain = append(chain, b)
	}
	if ctx.Err() != nil || !p.Valid(s.now()) {
		return out, value.ErrDenied
	}
	return s.verify.CheckIssued(p, der, chain)
}
