package kubernetes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func installerServingTLSFilesValid(files map[string][]byte) bool {
	keys := contracts.InstallerInboxServingTLSFiles()
	for key, value := range files {
		known := false
		for _, allowed := range keys {
			known = known || key == allowed
		}
		if !known || len(value) == 0 || len(value) > 64<<10 {
			return false
		}
	}
	for _, group := range [][]string{keys[:3], keys[3:]} {
		count := 0
		for _, key := range group {
			if _, present := files[key]; present {
				count++
			}
		}
		if count != 0 && count != 3 {
			return false
		}
	}
	return true
}

// ValidateInstallerServingTLS verifies a complete operator bundle, including
// the actual private key, current CA roots and intermediates, for this host.
func ValidateInstallerServingTLS(certificate, key, ca []byte, serverName string, now time.Time) ([][]byte, error) {
	if serverName == "" || len(serverName) > 253 || len(certificate) == 0 || len(certificate) > 64<<10 || len(key) == 0 || len(key) > 64<<10 {
		return nil, cfg.ErrInvalid
	}
	block, rest := pem.Decode(bytes.TrimSpace(key))
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN ")) {
		return nil, cfg.ErrInvalid
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil || len(pair.Certificate) == 0 || len(pair.Certificate) > 4 {
		return nil, cfg.ErrInvalid
	}
	// X509KeyPair skips unrelated PEM blocks. The certificate input is closed.
	count := 0
	for remaining := bytes.TrimSpace(certificate); len(remaining) != 0; count++ {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, cfg.ErrInvalid
		}
		b, next := pem.Decode(remaining)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || count == 4 {
			return nil, cfg.ErrInvalid
		}
		remaining = bytes.TrimSpace(next)
	}
	roots, err := providerconfig.TrustRootsPEM(ca, now)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	pool, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, der := range roots {
		c, _ := x509.ParseCertificate(der)
		pool.AddCert(c)
	}
	for _, der := range pair.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil || !c.IsCA || now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return nil, cfg.ErrInvalid
		}
		intermediates.AddCert(c)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA {
		return nil, cfg.ErrInvalid
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: pool, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, cfg.ErrInvalid
	}
	return roots, nil
}

// ValidateInstallerServingTLSMaterial binds exactly the recipe's selected
// services before either the operator's provider writes or Secret creation.
func ValidateInstallerServingTLSMaterial(plan contracts.InstallerServingTLSPlan, files map[string][]byte, now time.Time) error {
	if !installerServingTLSFilesValid(files) {
		return cfg.ErrInvalid
	}
	keys := contracts.InstallerInboxServingTLSFiles()
	for i, host := range []string{plan.FederationServerName, plan.KeyServiceServerName} {
		group := keys[i*3 : i*3+3]
		if (host != "") != (len(files[group[0]]) != 0) {
			return cfg.ErrInvalid
		}
		if host != "" {
			if _, err := ValidateInstallerServingTLS(files[group[0]], files[group[1]], files[group[2]], host, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// EnsureInstallerServingTLS runs under the continuation's existing guarded
// namespace/admin operation. All material is checked before the first effect.
// Two fixed Secrets add at most two GETs, two CREATEs and two exact recovery
// GETs, within one original five-second call; no write is retried or replaced.
func EnsureInstallerServingTLS(ctx context.Context, config *rest.Config, namespace, installation string, plan contracts.InstallerServingTLSPlan, files map[string][]byte) error {
	if ctx == nil || ctx.Err() != nil || config == nil || namespace == "" || !authorization.UUID(installation) || !installerServingTLSFilesValid(files) {
		return cfg.ErrInvalid
	}
	if err := ValidateInstallerServingTLSMaterial(plan, files, time.Now()); err != nil {
		return err
	}
	keys := contracts.InstallerInboxServingTLSFiles()
	targets := []struct {
		name, host string
		keys       []string
	}{
		{contracts.FederationServingSecretName(installation), plan.FederationServerName, keys[:3]},
		{contracts.KeyServiceServingSecretName(installation), plan.KeyServiceServerName, keys[3:]},
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	secrets := api.CoreV1().Secrets(namespace)
	for _, target := range targets {
		if target.host == "" {
			continue
		}
		data := map[string][]byte{"tls.crt": files[target.keys[0]], "tls.key": files[target.keys[1]], "ca.crt": files[target.keys[2]]}
		got, err := secrets.Get(call, target.name, meta.GetOptions{})
		if apierrors.IsNotFound(err) {
			got, err = secrets.Create(call, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: target.name, Namespace: namespace}, Type: core.SecretTypeTLS, Data: data}, meta.CreateOptions{})
			if err != nil {
				// A lost reply permits only an exact read, never another CREATE.
				got, err = secrets.Get(call, target.name, meta.GetOptions{})
			}
		}
		if err != nil {
			return cfg.ErrUnavailable
		}
		if got.Name != target.name || got.Namespace != namespace || !authorization.UUID(string(got.UID)) || got.DeletionTimestamp != nil || got.Type != core.SecretTypeTLS || len(got.StringData) != 0 || !reflect.DeepEqual(got.Data, data) {
			return cfg.ErrChanged
		}
		if call.Err() != nil {
			return cfg.ErrUnavailable
		}
		if _, err := ValidateInstallerServingTLS(got.Data["tls.crt"], got.Data["tls.key"], got.Data["ca.crt"], target.host, time.Now()); err != nil {
			return err
		}
	}
	return nil
}
