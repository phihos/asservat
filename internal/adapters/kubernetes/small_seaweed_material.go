package kubernetes

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// BuildSmallSeaweedMaterial runs only before any backend resources exist.
// The separate backend IDs grant no Asservat installation/root authority.
func BuildSmallSeaweedMaterial(p contracts.SmallSeaweedPlan, now time.Time) (map[string][]byte, error) {
	if !p.Valid() || now.IsZero() {
		return nil, cfg.ErrInvalid
	}
	backend, e := prepUUID()
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	init, e := prepUUID()
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	admin, e := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: backend})
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	plan, _ := json.Marshal(p)
	credential, _ := json.Marshal(admin)
	data := map[string][]byte{contracts.SmallSeaweedPlanKey: plan, contracts.SmallSeaweedBackendKey: []byte(backend), contracts.SmallSeaweedInitializationKey: []byte(init), contracts.SmallSeaweedAdminKey: credential}
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, e := rand.Int(rand.Reader, serialLimit)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	leafSerial, e := rand.Int(rand.Reader, serialLimit)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: p.ServiceName() + " CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: p.Host()}, DNSNames: []string{p.ServiceName(), p.ServiceName() + "." + p.Namespace, p.Host(), p.Host() + ".cluster.local"}, NotBefore: ca.NotBefore, NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	data["ca.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	data["tls.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	for name, key := range map[string]*ecdsa.PrivateKey{"ca.key": caKey, "tls.key": leafKey} {
		raw, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return nil, cfg.ErrUnavailable
		}
		data[name] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
		clear(raw)
	}
	if ValidateSmallSeaweedMaterial(p, data, now) != nil {
		clearSmallSeaweedData(data)
		return nil, cfg.ErrUnavailable
	}
	return data, nil
}
func clearSmallSeaweedData(data map[string][]byte) {
	for _, b := range data {
		clear(b)
	}
}
func decodeSmallSeaweedAdmin(raw []byte) (contracts.SeaweedCredential, error) {
	var admin contracts.SeaweedCredential
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&admin) != nil || decoder.Decode(new(any)) != io.EOF || providerconfig.ValidateSeaweedCredential(admin) != nil || admin.Principal.Purpose != "admin" {
		return contracts.SeaweedCredential{}, cfg.ErrInvalid
	}
	return admin, nil
}
func ValidateSmallSeaweedMaterial(p contracts.SmallSeaweedPlan, data map[string][]byte, now time.Time) error {
	if !p.Valid() || now.IsZero() || len(data) != 8 {
		return cfg.ErrInvalid
	}
	for key, raw := range data {
		if !slices.Contains([]string{contracts.SmallSeaweedPlanKey, contracts.SmallSeaweedBackendKey, contracts.SmallSeaweedInitializationKey, contracts.SmallSeaweedAdminKey, "ca.crt", "ca.key", "tls.crt", "tls.key"}, key) || len(raw) == 0 || len(raw) > 16<<10 {
			return cfg.ErrInvalid
		}
	}
	plan, e := contracts.DecodeSmallSeaweedPlan(bytes.NewReader(data[contracts.SmallSeaweedPlanKey]))
	if e != nil || plan != p {
		return cfg.ErrInvalid
	}
	backend, init := string(data[contracts.SmallSeaweedBackendKey]), string(data[contracts.SmallSeaweedInitializationKey])
	if !authorization.UUID(backend) || !authorization.UUID(init) || backend == init {
		return cfg.ErrInvalid
	}
	admin, e := decodeSmallSeaweedAdmin(data[contracts.SmallSeaweedAdminKey])
	if e != nil || admin.Principal.ScopeID != backend {
		return cfg.ErrInvalid
	}
	caPair, e := tls.X509KeyPair(data["ca.crt"], data["ca.key"])
	if e != nil || len(caPair.Certificate) != 1 {
		return cfg.ErrInvalid
	}
	leafPair, e := tls.X509KeyPair(data["tls.crt"], data["tls.key"])
	if e != nil || len(leafPair.Certificate) != 1 {
		return cfg.ErrInvalid
	}
	ca, e := x509.ParseCertificate(caPair.Certificate[0])
	if e != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.CheckSignatureFrom(ca) != nil || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return cfg.ErrInvalid
	}
	leaf, e := x509.ParseCertificate(leafPair.Certificate[0])
	if e != nil || leaf.IsCA || !slices.Equal(leaf.DNSNames, []string{p.ServiceName(), p.ServiceName() + "." + p.Namespace, p.Host(), p.Host() + ".cluster.local"}) || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return cfg.ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: p.Host(), CurrentTime: now}); e != nil {
		return cfg.ErrInvalid
	}
	// X509KeyPair deliberately accepts trailing PEM text. Private retained state
	// is closed, so independently require exactly one block in each field.
	for _, name := range []string{"ca.crt", "ca.key", "tls.crt", "tls.key"} {
		block, rest := pem.Decode(data[name])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return cfg.ErrInvalid
		}
	}
	return nil
}
