package kubernetes

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The node listener certificate has no renewal path; deleting the listener
// Secret's data makes the connector issue a new pair on its next start.
const regionalNodeValidity = 10 * 365 * 24 * time.Hour

// NodeListener is the connector's ADR-246 node listener identity. Helm
// renders the listener Secret (connector namespace) and the root ConfigMap
// (collector namespace) empty; the connector fills both once and reuses the
// stored pair afterwards. Its Role holds get/update on exactly these names.
type NodeListener struct {
	Namespace, Secret         string
	RootNamespace, RootConfig string
	ServerName                string
}

// Ensure returns the listener's key pair. A Secret without the pair gets a new
// root and leaf; the root's PEM is then published (or kept current) in the
// collector namespace's ConfigMap.
func (l NodeListener) Ensure(ctx context.Context, config *rest.Config) (tls.Certificate, error) {
	var zero tls.Certificate
	if ctx == nil || config == nil || l.Namespace == "" || l.Secret == "" || l.RootNamespace == "" || l.RootConfig == "" || l.ServerName == "" {
		return zero, cfg.ErrInvalid
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	secrets := api.CoreV1().Secrets(l.Namespace)
	secret, err := secrets.Get(call, l.Secret, meta.GetOptions{})
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	chain, key := secret.Data[contracts.RegionalNodeServerFile], secret.Data[contracts.RegionalNodeServerKeyFile]
	if len(chain) == 0 && len(key) == 0 {
		if chain, key, err = newRegionalNodeCertificate(l.ServerName, time.Now()); err != nil {
			return zero, cfg.ErrUnavailable
		}
		secret.Data = map[string][]byte{contracts.RegionalNodeServerFile: chain, contracts.RegionalNodeServerKeyFile: key}
		// resourceVersion CAS: a concurrent writer wins and this start fails.
		if _, err = secrets.Update(call, secret, meta.UpdateOptions{}); err != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	defer clear(key)
	root, err := regionalNodeRoots(chain, key, l.ServerName, time.Now())
	if err != nil {
		return zero, err
	}
	configs := api.CoreV1().ConfigMaps(l.RootNamespace)
	published, err := configs.Get(call, l.RootConfig, meta.GetOptions{})
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	if published.Data[contracts.NodeConnectorRootFile] != root {
		published.Data = map[string]string{contracts.NodeConnectorRootFile: root}
		if _, err = configs.Update(call, published, meta.UpdateOptions{}); err != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return zero, cfg.ErrChanged
	}
	return pair, nil
}

// newRegionalNodeCertificate makes a P-256 root and a server leaf for the
// Service DNS name. The root's key is discarded after signing; the collector
// requires a CA root (node.go), so the leaf cannot be self-signed. The chain
// file holds the leaf, then the root.
func newRegionalNodeCertificate(serverName string, now time.Time) (chain, keyPEM []byte, err error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	start, end := now.Add(-5*time.Minute).UTC().Truncate(time.Second), now.Add(regionalNodeValidity).UTC().Truncate(time.Second)
	serial := func() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)) }
	rs, err := serial()
	if err != nil {
		return nil, nil, err
	}
	root := &x509.Certificate{SerialNumber: rs, Subject: pkix.Name{CommonName: "asservat connector node listener root"}, NotBefore: start, NotAfter: end,
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	if root, err = x509.ParseCertificate(rootDER); err != nil {
		return nil, nil, err
	}
	ls, err := serial()
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: ls, Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName}, NotBefore: start, NotAfter: end,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	defer clear(keyDER)
	if err != nil {
		return nil, nil, err
	}
	chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// regionalNodeRoots checks a stored pair exactly as the connector loads it
// and as the collector verifies it: key matches, the leaf chains to the CA
// root for serverName at now. It returns that root's PEM.
func regionalNodeRoots(chain, key []byte, serverName string, now time.Time) (string, error) {
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil || len(pair.Certificate) != 2 {
		return "", cfg.ErrChanged
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", cfg.ErrChanged
	}
	root, err := x509.ParseCertificate(pair.Certificate[1])
	if err != nil || !root.IsCA || !bytes.Equal(pair.Certificate[1], root.Raw) {
		return "", cfg.ErrChanged
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return "", cfg.ErrChanged
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})), nil
}
