package kms

import (
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	bao "github.com/openbao/openbao/api/v2"
	"io"
	"net/http"
	"time"
)

type WorkerCertificateIssuer struct {
	client                    *bao.Client
	path, installation, epoch string
	verify                    *mtls.KeyPeerVerifier
	now                       func() time.Time
}

var _ evidence.WorkerCertificateIssuer = (*WorkerCertificateIssuer)(nil)

func NewWorkerCertificateIssuer(endpoint, token, mount, role, installation, epoch string, roots *x509.CertPool, h *http.Client, now func() time.Time) (*WorkerCertificateIssuer, error) {
	if !keyName.MatchString(mount) || !keyName.MatchString(role) || !value.UUID(epoch) {
		return nil, artifact.ErrInvalid
	}
	v, e := mtls.NewKeyPeerVerifier(roots, installation, now)
	if e != nil {
		return nil, e
	}
	c, e := client(endpoint, token, h)
	if e != nil {
		return nil, e
	}
	return &WorkerCertificateIssuer{c, mount + "/sign/" + role, installation, epoch, v, now}, nil
}
func (s *WorkerCertificateIssuer) SignWorkerCertificate(ctx context.Context, a value.WorkerCertificateAttempt, csr []byte) (value.WorkerCertificate, error) {
	var out value.WorkerCertificate
	if s == nil || ctx == nil || s.client == nil || s.now == nil || !a.Valid(s.now()) || a.Enrollment.Worker.Binding.InstallationID != s.installation || a.RecoveryEpoch != s.epoch {
		return out, artifact.ErrInvalid
	}
	key, e := mtls.EnrollmentKey(csr)
	if e != nil || key != a.Enrollment.PublicKeyDigest {
		return out, artifact.ErrInvalid
	}
	uri, e := mtls.WorkerCertificateURI(a)
	if e != nil {
		return out, e
	}
	ctx, end := context.WithDeadline(ctx, a.SignBefore)
	defer end()
	r := s.client.NewRequest(http.MethodPost, "/v1/"+s.path)
	if r.SetJSONBody(map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "uri_sans": []string{uri.String()}, "not_after": a.CertificateNotAfter.Format(time.RFC3339), "exclude_cn_from_sans": true, "format": "pem"}) != nil {
		return out, artifact.ErrInvalid
	}
	response, e := s.client.RawRequestWithContext(ctx, r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if e != nil || response == nil || response.StatusCode != http.StatusOK {
		return out, ErrKeyService
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(body)
	if e != nil || len(body) > 32768 {
		return out, ErrKeyService
	}
	var wire struct {
		Data struct {
			Certificate string   `json:"certificate"`
			Chain       []string `json:"ca_chain"`
			Private     string   `json:"private_key"`
		}
	}
	if json.Unmarshal(body, &wire) != nil || wire.Data.Private != "" || len(wire.Data.Chain) > 3 {
		return out, ErrKeyService
	}
	decode := func(s string) ([]byte, error) {
		b, rest := pem.Decode([]byte(s))
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(rest) != 0 || len(b.Bytes) > 16<<10 {
			return nil, artifact.ErrInvalid
		}
		return b.Bytes, nil
	}
	der, e := decode(wire.Data.Certificate)
	if e != nil {
		return out, e
	}
	var chain [][]byte
	for _, s := range wire.Data.Chain {
		d, e := decode(s)
		if e != nil {
			return out, e
		}
		chain = append(chain, d)
	}
	if ctx.Err() != nil || !a.Valid(s.now()) {
		return out, artifact.ErrDownloadExpired
	}
	return s.verify.CheckWorkerCertificate(a, csr, der, chain)
}
