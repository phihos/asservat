package kubernetes

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/xdg-go/scram"
)

// BuildSmallPostgresMaterial generates once, before the database exists. No
// material, password-derived digest or certificate key enters Helm values.
func BuildSmallPostgresMaterial(p contracts.SmallPostgresPlan, now time.Time) (map[string][]byte, error) {
	if !p.Valid() || now.IsZero() {
		return nil, cfg.ErrInvalid
	}
	d := make(map[string][]byte)
	for _, role := range []string{"administrator", "ddl", "backup", "keycloak"} {
		if role == "keycloak" && !p.Keycloak {
			continue
		}
		password := make([]byte, 32)
		if _, err := rand.Read(password); err != nil {
			return nil, cfg.ErrUnavailable
		}
		encoded := base64.RawURLEncoding.EncodeToString(password)
		clear(password)
		name := "asservat_" + role
		if role == "administrator" {
			name = "asservat_admin"
		}
		if role == "keycloak" {
			name = "keycloak"
		}
		verifier, err := smallPostgresVerifier(name, encoded)
		if err != nil {
			return nil, cfg.ErrUnavailable
		}
		d[role+"-verifier"] = []byte(verifier)
		switch role {
		case "administrator":
			d["administrator-password"] = []byte(encoded)
			d["postgres-administrator.json"], _ = json.Marshal(contracts.OwnerSQLCredential{Username: name, Password: encoded})
		case "ddl":
			d["postgres-ddl.json"], _ = json.Marshal(contracts.OwnerSQLCredential{Username: name, Password: encoded})
		case "backup":
			d["backup.pgpass"] = []byte(p.Host() + ":5432:postgres:" + name + ":" + encoded + "\n")
		case "keycloak":
			d["keycloak-password"] = []byte(encoded)
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, cfg.ErrUnavailable
	}
	d["backup-cipher"] = []byte(base64.RawURLEncoding.EncodeToString(key))
	clear(key)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	leafSerial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: p.ServiceName() + " CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: p.Host()}, DNSNames: []string{p.ServiceName(), p.ServiceName() + "." + p.Namespace, p.Host(), p.Host() + ".cluster.local"}, NotBefore: ca.NotBefore, NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	private, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	d["ca.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	d["server.crt"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	d["server.key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	clear(private)
	private, err = x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	d["ca.key"] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	clear(private)
	// Only the retained state contains the CA key; no workload projection mounts
	// it. A future explicit rotation can retain the original trust identity.
	if ValidateSmallPostgresMaterial(p, d, now) != nil {
		return nil, cfg.ErrUnavailable
	}
	return d, nil
}

func smallPostgresVerifier(name, password string) (string, error) {
	c, err := scram.SHA256.NewClient(name, password, "")
	if err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return "", err
	}
	defer clear(salt)
	s, err := c.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt), Iters: 4096})
	if err != nil {
		return "", err
	}
	defer clear(s.StoredKey)
	defer clear(s.ServerKey)
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(s.StoredKey) + ":" + b64(s.ServerKey), nil
}

func smallPostgresPassword(raw []byte) bool {
	b, err := base64.RawURLEncoding.DecodeString(string(raw))
	defer clear(b)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == string(raw)
}

// ValidateSmallPostgresMaterial refuses unknown keys, changed private/public
// pairings, mismatched SQL credentials and a different declared installation.
func ValidateSmallPostgresMaterial(p contracts.SmallPostgresPlan, d map[string][]byte, now time.Time) error {
	if !p.Valid() || now.IsZero() {
		return cfg.ErrInvalid
	}
	keys := []string{"administrator-password", "administrator-verifier", "postgres-administrator.json", "ddl-verifier", "postgres-ddl.json", "backup-verifier", "backup.pgpass", "backup-cipher", "ca.crt", "ca.key", "server.crt", "server.key"}
	if p.Keycloak {
		keys = append(keys, "keycloak-password", "keycloak-verifier")
	}
	if len(d) != len(keys) {
		return cfg.ErrInvalid
	}
	for k, v := range d {
		if !slices.Contains(keys, k) || len(v) == 0 || len(v) > 16<<10 {
			return cfg.ErrInvalid
		}
	}
	if !smallPostgresPassword(d["administrator-password"]) || !smallPostgresPassword(d["backup-cipher"]) {
		return cfg.ErrInvalid
	}
	passwords := map[string]string{"administrator": string(d["administrator-password"])}
	for _, role := range []string{"administrator", "ddl"} {
		var c contracts.OwnerSQLCredential
		decoded, err := contracts.DecodeOwnerSQLCredential(bytes.NewReader(d["postgres-"+role+".json"]))
		c = decoded
		name := "asservat_" + role
		if role == "administrator" {
			name = "asservat_admin"
		}
		if err != nil || c.Username != name || !smallPostgresPassword([]byte(c.Password)) {
			return cfg.ErrInvalid
		}
		if role == "administrator" && c.Password != passwords[role] {
			return cfg.ErrInvalid
		}
		passwords[role] = c.Password
	}
	line := string(d["backup.pgpass"])
	prefix := p.Host() + ":5432:postgres:asservat_backup:"
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "\n") {
		return cfg.ErrInvalid
	}
	passwords["backup"] = strings.TrimSuffix(strings.TrimPrefix(line, prefix), "\n")
	if p.Keycloak {
		passwords["keycloak"] = string(d["keycloak-password"])
	}
	seen := map[string]bool{}
	for role, password := range passwords {
		if !smallPostgresPassword([]byte(password)) || seen[password] {
			return cfg.ErrInvalid
		}
		seen[password] = true
		if !smallPostgresVerifierMatches(string(d[role+"-verifier"]), password) {
			return cfg.ErrInvalid
		}
	}
	caBlock, rest := pem.Decode(d["ca.crt"])
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return cfg.ErrInvalid
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil {
		return cfg.ErrInvalid
	}
	leafBlock, rest := pem.Decode(d["server.crt"])
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return cfg.ErrInvalid
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return cfg.ErrInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: p.Host(), CurrentTime: now}); err != nil {
		return cfg.ErrInvalid
	}
	keyBlock, rest := pem.Decode(d["server.key"])
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return cfg.ErrInvalid
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return cfg.ErrInvalid
	}
	private, ok := key.(*ecdsa.PrivateKey)
	public, okPub := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !okPub || !private.PublicKey.Equal(public) {
		return cfg.ErrInvalid
	}
	keyBlock, rest = pem.Decode(d["ca.key"])
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return cfg.ErrInvalid
	}
	key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return cfg.ErrInvalid
	}
	private, ok = key.(*ecdsa.PrivateKey)
	public, okPub = ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || !okPub || !private.PublicKey.Equal(public) {
		return cfg.ErrInvalid
	}
	return nil
}

func smallPostgresVerifierMatches(encoded, password string) bool {
	parts := strings.Split(strings.TrimPrefix(encoded, "SCRAM-SHA-256$4096:"), "$")
	if !strings.HasPrefix(encoded, "SCRAM-SHA-256$4096:") || len(parts) != 2 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(salt) != 16 {
		return false
	}
	defer clear(salt)
	c, err := scram.SHA256.NewClient("", password, "")
	if err != nil {
		return false
	}
	s, err := c.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt), Iters: 4096})
	if err != nil {
		return false
	}
	defer clear(s.StoredKey)
	defer clear(s.ServerKey)
	return parts[1] == base64.StdEncoding.EncodeToString(s.StoredKey)+":"+base64.StdEncoding.EncodeToString(s.ServerKey)
}
