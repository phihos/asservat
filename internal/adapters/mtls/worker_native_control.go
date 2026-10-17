package mtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// All values are copied public startup pins. Changing them is not a grant.
type WorkerNativeSettings struct {
	ExchangeEndpoint, StoreID, StoreEndpoint, StoreRegion, StoreBucket string
	StoreCredentialSecretName, StoreCredentialSecretUID, KeyEndpoint   string
	KeyScope                                                           value.KeyScope
}

type WorkerNativeTrust struct {
	settings              WorkerNativeSettings
	exchange, store, keys []*x509.Certificate
}

func (t *WorkerControlTrust) Native() *WorkerNativeTrust    { return t.native }
func (t *WorkerNativeTrust) Settings() WorkerNativeSettings { return t.settings }

var workerSecretName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$`)
var workerStoreRegion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$`)
var workerStoreBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func nativeWorkerEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 || u.Path != contracts.NativeWorkerPath || u.RawPath != "" {
		return false
	}
	u.Path = ""
	_, err = workerEndpoint(u.String())
	return err == nil && !strings.Contains(endpoint, "#")
}

func parseWorkerRootSet(roots [][]byte, total *int) ([]*x509.Certificate, error) {
	if len(roots) < 1 || len(roots) > 4 {
		return nil, artifact.ErrInvalid
	}
	out := make([]*x509.Certificate, 0, len(roots))
	seen := map[[32]byte]bool{}
	for _, raw := range roots {
		*total += len(raw)
		if len(raw) < 1 || len(raw) > 16<<10 || *total > 32<<10 {
			return nil, artifact.ErrInvalid
		}
		h := sha256.Sum256(raw)
		if seen[h] {
			return nil, artifact.ErrInvalid
		}
		seen[h] = true
		cert, err := x509.ParseCertificate(bytes.Clone(raw))
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || !cert.NotBefore.Before(cert.NotAfter) {
			return nil, artifact.ErrInvalid
		}
		out = append(out, cert)
	}
	return out, nil
}

func parseWorkerNative(w contracts.WorkerNativeControl, installation string, total *int) (*WorkerNativeTrust, error) {
	s, k := w.ObjectStore, w.KeyService
	scope := value.KeyScope{InstallationID: k.Scope.InstallationID, Purpose: k.Scope.Purpose, KeyID: k.Scope.KeyID}
	if w.Format != contracts.WorkerNativeStartupFormat || !nativeWorkerEndpoint(w.ExchangeEndpoint) || !value.UUID(s.ID) || !workerStoreRegion.MatchString(s.Region) || !workerStoreBucket.MatchString(s.Bucket) || strings.Contains(s.Bucket, "..") || strings.Contains(s.Bucket, ".-") || strings.Contains(s.Bucket, "-.") || net.ParseIP(s.Bucket) != nil || len(s.CredentialSecretName) > 253 || !workerSecretName.MatchString(s.CredentialSecretName) || !value.UUID(s.CredentialSecretUID) || !scope.Valid() || scope.InstallationID != installation || scope.Purpose != "artifact" {
		return nil, artifact.ErrInvalid
	}
	for _, endpoint := range []string{s.Endpoint, k.Endpoint} {
		if _, err := workerEndpoint(endpoint); err != nil {
			return nil, err
		}
	}
	t := &WorkerNativeTrust{settings: WorkerNativeSettings{w.ExchangeEndpoint, s.ID, s.Endpoint, s.Region, s.Bucket, s.CredentialSecretName, s.CredentialSecretUID, k.Endpoint, scope}}
	for i, roots := range [][][]byte{w.ExchangeServerRoots, s.ServerRoots, k.ServerRoots} {
		parsed, e := parseWorkerRootSet(roots, total)
		if e != nil {
			return nil, e
		}
		switch i {
		case 0:
			t.exchange = parsed
		case 1:
			t.store = parsed
		case 2:
			t.keys = parsed
		}
	}
	return t, nil
}

// Separate fresh pools prevent a store or key-service root from authenticating
// the exchange peer. Each call validates every configured original CA interval.
func (t *WorkerNativeTrust) Roots(now time.Time) (*x509.CertPool, *x509.CertPool, *x509.CertPool, error) {
	if t == nil {
		return nil, nil, nil, artifact.ErrInvalid
	}
	pools := []*x509.CertPool{x509.NewCertPool(), x509.NewCertPool(), x509.NewCertPool()}
	for i, certs := range [][]*x509.Certificate{t.exchange, t.store, t.keys} {
		if len(certs) == 0 {
			return nil, nil, nil, artifact.ErrInvalid
		}
		for _, c := range certs {
			if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
				return nil, nil, nil, artifact.ErrDownloadExpired
			}
			pools[i].AddCert(c)
		}
	}
	return pools[0], pools[1], pools[2], nil
}
