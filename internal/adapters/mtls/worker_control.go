package mtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type WorkerControlTrust struct {
	InstallationID, ClusterID, Endpoint string
	server, issuer                      []*x509.Certificate
	native                              *WorkerNativeTrust
}

func workerEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(endpoint, "#") || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, artifact.ErrInvalid
	}
	return u, nil
}

// ParseWorkerControl has no clock-dependent digest behavior. Roots must be
// bounded CA certificates; activation checks their lifetimes separately.
func ParseWorkerControl(raw []byte) (*WorkerControlTrust, error) {
	wire, err := contracts.DecodeWorkerControl(bytes.NewReader(raw))
	if err != nil || !(wire.Format == contracts.WorkerControlFormat && wire.Native == nil || wire.Format == contracts.WorkerNativeControlFormat && wire.Native != nil) || !value.UUID(wire.InstallationID) || !value.UUID(wire.ClusterID) {
		return nil, artifact.ErrInvalid
	}
	if _, err = workerEndpoint(wire.Endpoint); err != nil {
		return nil, err
	}
	trust := &WorkerControlTrust{InstallationID: wire.InstallationID, ClusterID: wire.ClusterID, Endpoint: wire.Endpoint}
	total := 0
	trust.server, err = parseWorkerRootSet(wire.ServerRoots, &total)
	if err != nil {
		return nil, err
	}
	trust.issuer, err = parseWorkerRootSet(wire.IssuerRoots, &total)
	if err != nil {
		return nil, err
	}
	if wire.Native != nil {
		trust.native, err = parseWorkerNative(*wire.Native, wire.InstallationID, &total)
		if err != nil {
			return nil, err
		}
	}
	return trust, nil
}

// All configured anchors must be current. A stale/unusable trust rollout is a
// configuration failure, not an invitation to select ambient system roots.
func (t *WorkerControlTrust) Roots(now time.Time) (*x509.CertPool, *x509.CertPool, error) {
	if t == nil || len(t.server) == 0 || len(t.issuer) == 0 {
		return nil, nil, artifact.ErrInvalid
	}
	if t.native != nil {
		if _, _, _, err := t.native.Roots(now); err != nil {
			return nil, nil, err
		}
	}
	server, issuer := x509.NewCertPool(), x509.NewCertPool()
	for i, certs := range [][]*x509.Certificate{t.server, t.issuer} {
		for _, c := range certs {
			if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
				return nil, nil, artifact.ErrDownloadExpired
			}
			if i == 0 {
				server.AddCert(c)
			} else {
				issuer.AddCert(c)
			}
		}
	}
	return server, issuer, nil
}

// WorkerControlDigest pins the exact immutable ConfigMap data bytes. Whitespace
// changes require a new protected profile; parsing alone never normalizes away
// a changed startup source.
func WorkerControlDigest(data map[string]string) (artifact.Digest, error) {
	if len(data) != 1 {
		return artifact.Digest{}, artifact.ErrInvalid
	}
	if _, err := ParseWorkerControl([]byte(data["worker.json"])); err != nil {
		return artifact.Digest{}, artifact.ErrInvalid
	}
	b, err := json.Marshal(data)
	if err != nil {
		return artifact.Digest{}, artifact.ErrInvalid
	}
	return artifact.Digest(sha256.Sum256(b)), nil
}
