package kms

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	bao "github.com/openbao/openbao/api/v2"
)

type ConnectorCredentialIssuer struct {
	client                                    *bao.Client
	path, installation, cluster, epoch, usage string
	verify                                    *mtls.ConnectorCredentialVerifier
	now                                       func() time.Time
}

var _ app.ConnectorCredentialIssuer = (*ConnectorCredentialIssuer)(nil)

// newConnectorCredentialIssuerWithClient signs over an installed provider
// effect client (ADR-193), whose borrowed token the lifetime owns.
func newConnectorCredentialIssuerWithClient(c *bao.Client, mount, role, usage string, profile value.ConnectorCredentialProfile, now func() time.Time) (*ConnectorCredentialIssuer, error) {
	if c == nil || !keyName.MatchString(mount) || !keyName.MatchString(role) || (usage != "client" && usage != "server") || !profile.Valid() || profile.Suspended || now == nil {
		return nil, value.ErrInvalid
	}
	v, e := mtls.NewConnectorCredentialVerifier(profile, now)
	if e != nil {
		return nil, e
	}
	b := profile.Binding
	return &ConnectorCredentialIssuer{c, mount + "/sign/" + role, b.InstallationID, b.ClusterID, b.IssuerEpoch, usage, v, now}, nil
}

func (s *ConnectorCredentialIssuer) SignConnectorCredential(ctx context.Context, p value.ConnectorCredentialPermit, csr []byte) (value.IssuedConnectorCredential, error) {
	var zero value.IssuedConnectorCredential
	if s == nil || ctx == nil || s.client == nil || s.now == nil || !p.Valid(s.now()) || p.Process.Binding.InstallationID != s.installation || p.Process.Binding.ClusterID != s.cluster || p.Process.Binding.IssuerEpoch != s.epoch || p.Usage != s.usage || s.verify.CheckConnectorPermit(p) != nil {
		return zero, value.ErrInvalid
	}
	key, e := mtls.EnrollmentKey(csr)
	if e != nil || key != p.PublicKeyDigest() {
		return zero, value.ErrDenied
	}
	uri, e := mtls.PeerURI(p.Process.Binding)
	if e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, p.SignBefore)
	defer end()
	input := map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "uri_sans": []string{uri.String()}, "not_after": p.CertificateNotAfter.Format(time.RFC3339), "exclude_cn_from_sans": true, "format": "pem"}
	if p.Usage == "server" {
		input["alt_names"] = p.Configuration.Profile.ServerName
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
	return s.verify.CheckConnectorCredential(p, csr, der, chain)
}
