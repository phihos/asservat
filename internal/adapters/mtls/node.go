package mtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

var ErrNodeCredential = errors.New("node credential unavailable")

// NodeIssuer is the connector process's node-channel issuer (ADR-246). Its
// P-256 key exists only in this process's memory and is never written; a
// connector restart creates a new issuer, so every earlier node certificate
// stops verifying and the collectors enroll again. Leaves are client-only,
// carry no DNS/IP names and bind the attested node process in one URI.
type NodeIssuer struct {
	key       *ecdsa.PrivateKey
	ca        *x509.Certificate
	pool      *x509.CertPool
	clusterID string
	now       func() time.Time
}

func NewNodeIssuer(clusterID string, now func() time.Time) (*NodeIssuer, error) {
	if clusterID == "" || now == nil {
		return nil, ErrNodeCredential
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrNodeCredential
	}
	start := now().UTC().Add(-time.Minute).Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "asservat node channel " + clusterID},
		NotBefore: start, NotAfter: start.Add(400 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, ErrNodeCredential
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrNodeCredential
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &NodeIssuer{key: key, ca: ca, pool: pool, clusterID: clusterID, now: now}, nil
}

func serial() *big.Int {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return big.NewInt(0)
	}
	b[0] &= 0x7f
	return new(big.Int).SetBytes(b[:])
}

// NodeIdentityURI names one attested collector process.
func NodeIdentityURI(clusterID string, id collector.Identity) *url.URL {
	return &url.URL{Scheme: "urn", Opaque: "asservat:node:" + clusterID + ":" + id.NodeUID + ":" + id.PodUID + ":" + id.Epoch}
}

// IssueNode validates the identity-free CSR (the shared strict checks) and
// signs a client leaf that expires at notAfter.
func (i *NodeIssuer) IssueNode(csr []byte, id collector.Identity, notAfter time.Time) ([]byte, [32]byte, error) {
	var none [32]byte
	if _, err := EnrollmentKey(csr); err != nil || id.NodeUID == "" || id.PodUID == "" || id.Epoch == "" {
		return nil, none, ErrNodeCredential
	}
	request, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, none, ErrNodeCredential
	}
	now := i.now().UTC().Truncate(time.Second)
	if !notAfter.After(now) || notAfter.After(now.Add(collector.CertificateLifetime)) || notAfter.After(i.ca.NotAfter) {
		return nil, none, ErrNodeCredential
	}
	template := &x509.Certificate{SerialNumber: serial(), NotBefore: now.Add(-time.Minute), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
		URIs: []*url.URL{NodeIdentityURI(i.clusterID, id)}}
	der, err := x509.CreateCertificate(rand.Reader, template, i.ca, request.PublicKey, i.key)
	if err != nil {
		return nil, none, ErrNodeCredential
	}
	return der, sha256.Sum256(der), nil
}

// ServerConfig is the node listener's TLS configuration: TLS 1.3, the given
// server certificate, and client certificates verified against this issuer
// only when presented (enrollment presents none).
func (i *NodeIssuer) ServerConfig(server tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: i.pool,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
}

// NodeCredentials is the collector process's own key: generated at start,
// held only in memory, used for every renewal of this process and never
// replaced (ADR-071's one-key-per-process rule).
type NodeCredentials struct {
	mu   sync.Mutex
	key  *ecdsa.PrivateKey
	csr  []byte
	cert *tls.Certificate
	leaf *x509.Certificate
}

func NewNodeCredentials() (*NodeCredentials, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrNodeCredential
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, ErrNodeCredential
	}
	if _, err := EnrollmentKey(csr); err != nil {
		return nil, ErrNodeCredential
	}
	return &NodeCredentials{key: key, csr: csr}, nil
}

func (n *NodeCredentials) CSR() []byte { return bytes.Clone(n.csr) }

// Install accepts a returned leaf only if it certifies this process's key
// for client authentication and is currently valid.
func (n *NodeCredentials) Install(der []byte, now time.Time) (time.Time, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return time.Time{}, ErrNodeCredential
	}
	if k, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || !k.Equal(&n.key.PublicKey) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.IsCA || len(leaf.URIs) != 1 {
		return time.Time{}, ErrNodeCredential
	}
	n.mu.Lock()
	n.cert, n.leaf = &tls.Certificate{Certificate: [][]byte{bytes.Clone(der)}, PrivateKey: n.key, Leaf: leaf}, leaf
	n.mu.Unlock()
	return leaf.NotAfter, nil
}

// GetClientCertificate presents the current leaf, or none before enrollment.
func (n *NodeCredentials) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cert == nil {
		return &tls.Certificate{}, nil
	}
	return n.cert, nil
}
