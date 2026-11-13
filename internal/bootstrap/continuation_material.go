package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"slices"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// smallOwnerMaterial reads only the finite operator source names. The original
// phase-three inbox must retain the returned bytes before provider effects; this
// read grants no public serving trust or evidence/key authority.
func (k *InstallerContinuation) smallOwnerMaterial(ctx context.Context, serving contracts.InstallerServingTLSPlan) (map[string][]byte, error) {
	return k.smallOwnerMaterialFromSource(ctx, serving, nil)
}
func (k *InstallerContinuation) smallOwnerMaterialFromSource(ctx context.Context, serving contracts.InstallerServingTLSPlan, selected *core.Secret) (_ map[string][]byte, err error) {
	fail := func(step string) error {
		return &fixedStepError{step: "owner-material/" + step, err: mounts.ErrUnavailable}
	}
	out := map[string][]byte{}
	defer func() {
		if err != nil {
			for _, raw := range out {
				clear(raw)
			}
		}
	}()
	if k == nil || !initialOpenBaoCurrent(ctx) {
		return nil, fail("context")
	}
	promoted := k.input.Public != nil && k.input.Public.Promotion != nil
	if !promoted && serving.FederationServerName == "" && serving.KeyServiceServerName == "" {
		return out, nil
	}
	if k.in == nil || len(validation.IsDNS1123Label(k.input.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(k.input.MaterialSecretName)) != 0 {
		return nil, fail("source")
	}
	read, e := k.smallInstallerSecretReader(ctx)
	if e != nil {
		return nil, e
	}
	var material *core.Secret
	if selected != nil {
		material = selected.DeepCopy()
	} else {
		material, e = read(k.input.MaterialSecretName)
		if e != nil {
			return nil, e
		}
	}
	defer func() {
		for _, raw := range material.Data {
			clear(raw)
		}
	}()
	copyKey := func(key string, limit int) error {
		raw := material.Data[key]
		if len(raw) == 0 || len(raw) > limit {
			return fail("missing")
		}
		out[key] = bytes.Clone(raw)
		return nil
	}
	if promoted {
		// ADR-327: behind a TLS-terminating proxy the hub-api serves HTTP and
		// needs no serving pair.
		if !k.publicProxyTLS() {
			for _, key := range []string{contracts.OwnerPublicTLSCertificate, contracts.OwnerPublicTLSKey} {
				if e = copyKey(key, 64<<10); e != nil {
					return nil, e
				}
			}
			if e = validateSmallPublicTLS(out[contracts.OwnerPublicTLSCertificate], out[contracts.OwnerPublicTLSKey], k.input.Public.Origin, time.Now()); e != nil {
				return nil, fail("public-tls")
			}
		}
		if !k.bundledIdentity {
			if e = copyKey(contracts.OwnerPublicClientSecretFile, 4096); e != nil {
				return nil, e
			}
		} else {
			root := k.plan.Plan.RootName
			if !strings.HasSuffix(root, "-preparation") {
				return nil, fail("identity-source")
			}
			name := strings.TrimSuffix(root, "-preparation") + "-keycloak-state"
			if len(validation.IsDNS1123Subdomain(name)) != 0 {
				return nil, fail("identity-source")
			}
			state, e := read(name)
			if e != nil {
				return nil, e
			}
			defer func() {
				for _, raw := range state.Data {
					clear(raw)
				}
			}()
			var settings contracts.SmallKeycloakSettings
			if json.Unmarshal(state.Data[contracts.SmallKeycloakSettingsFile], &settings) != nil || ValidateSmallKeycloakMaterial(settings, state) != nil || settings.Namespace != k.input.Namespace || settings.SecretName != name || settings.Origin != k.input.Public.Origin || settings.ConsoleClientID != k.input.Public.ClientID || strings.TrimSuffix(settings.Hostname, "/")+"/realms/"+settings.Realm != k.input.Public.Issuer {
				return nil, fail("identity-source")
			}
			out[contracts.OwnerPublicClientSecretFile] = bytes.Clone(state.Data[contracts.SmallKeycloakConsoleSecret])
		}
		if len(bytes.TrimSpace(out[contracts.OwnerPublicClientSecretFile])) == 0 {
			return nil, fail("missing")
		}
	}
	keys := contracts.InstallerInboxServingTLSFiles()
	tlsFiles := map[string][]byte{}
	for i, host := range []string{serving.FederationServerName, serving.KeyServiceServerName} {
		if host == "" {
			continue
		}
		for _, key := range keys[i*3 : i*3+3] {
			if e = copyKey(key, 64<<10); e != nil {
				return nil, e
			}
			tlsFiles[key] = out[key]
		}
	}
	if kube.ValidateInstallerServingTLSMaterial(serving, tlsFiles, time.Now()) != nil {
		return nil, fail("serving-tls")
	}
	if !initialOpenBaoCurrent(ctx) {
		return nil, fail("context")
	}
	return out, nil
}

// Verify possession, current dates and exact hostname. Public client trust is
// independently configured outside this helper; no private/public CA is minted.
func validateSmallPublicTLS(certificate, key []byte, origin string, now time.Time) error {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return mounts.ErrUnavailable
	}
	pair, e := tls.X509KeyPair(certificate, key)
	if e != nil || len(pair.Certificate) == 0 || len(pair.Certificate) > 4 {
		return mounts.ErrUnavailable
	}
	count := 0
	for remaining := bytes.TrimSpace(certificate); len(remaining) != 0; count++ {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return mounts.ErrUnavailable
		}
		block, next := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || count == 4 {
			return mounts.ErrUnavailable
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return mounts.ErrUnavailable
		}
		if count == 0 && (cert.IsCA || cert.VerifyHostname(u.Hostname()) != nil || (len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage) > 0 && !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny))) {
			return mounts.ErrUnavailable
		}
		remaining = bytes.TrimSpace(next)
	}
	block, rest := pem.Decode(bytes.TrimSpace(key))
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN ")) {
		return mounts.ErrUnavailable
	}
	return nil
}
