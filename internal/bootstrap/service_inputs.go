package bootstrap

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/rest"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Helm-native service inputs shared by the federation, key service and
// publisher: rendered config.json, the generated <name>-ids Secret, PEM CA
// bundles and the in-cluster API. Nothing here is an authority source.

// serviceKubernetes is the Pod's in-cluster API configuration (mounted
// service account token and CA); tests replace it.
var serviceKubernetes = rest.InClusterConfig

func readServiceIDs(_ context.Context, ids *os.Root) (contracts.ServiceIDs, error) {
	v, err := contracts.ReadInstallationIDs(ids)
	if err != nil {
		var key contracts.InstallationIDError
		errors.As(err, &key)
		return contracts.ServiceIDs{}, &fixedStepError{"ids/" + string(key), mounts.ErrUnavailable}
	}
	return v, nil
}

// validServiceScope checks installation.name and the release namespace.
// The name is at most 30 characters, as setup requires for derived names.
func validServiceScope(name, namespace string) bool {
	return len(name) <= 30 && len(validation.IsDNS1123Label(name)) == 0 && len(validation.IsDNS1123Label(namespace)) == 0
}

// serviceLogin is one component's OpenBao Kubernetes login on the owner auth
// mount: service account `<name>-<component>` and one role per purpose,
// `<name>-<component>-<purpose>`, exactly as `asservat setup` creates them.
func serviceLogin(name, namespace, component string, provider contracts.OwnerProviderEndpoint, purposes ...string) kms.ProviderLogin {
	roles := make(map[string]string, len(purposes))
	for _, p := range purposes {
		roles[p] = providerconfig.OpenBaoRoleName(name, component, p)
	}
	return kms.ProviderLogin{Provider: provider, AuthMount: contracts.SmallOpenBaoOwnerAuthMount, Namespace: namespace, ServiceAccount: name + "-" + component, Roles: roles}
}

// readAuditMAC reads the four mounted keys of the `<name>-audit-mac` Secret
// (contracts.AuditMAC*, one file per key). The versions share the secrets
// Job's setup ID: `<id>-input/v1` and `<id>-account/v1`. It returns the MAC
// and its account version.
func readAuditMAC(ctx context.Context, files *os.Root) (*auditapp.OperationMAC, string, error) {
	read := func(name string, limit int64) []byte {
		b, err := mounts.Read(ctx, files, name, limit)
		if err != nil {
			return nil
		}
		return b
	}
	inputVersion, accountVersion := string(read(contracts.AuditMACInputVersion, 128)), string(read(contracts.AuditMACAccountVersion, 128))
	inputKey, accountKey := read(contracts.AuditMACInputKey, 64), read(contracts.AuditMACAccountKey, 64)
	defer clear(inputKey)
	defer clear(accountKey)
	setup, ok := strings.CutSuffix(inputVersion, "-input/v1")
	if !ok || !authorization.UUID(setup) || accountVersion != setup+"-account/v1" || len(inputKey) != 32 || len(accountKey) != 32 {
		return nil, "", &fixedStepError{"audit-mac", mounts.ErrUnavailable}
	}
	mac, err := auditapp.NewOperationMAC(inputVersion, inputKey, accountVersion, accountKey)
	if err != nil {
		return nil, "", &fixedStepError{"audit-mac", mounts.ErrUnavailable}
	}
	return mac, accountVersion, nil
}

// readServiceConfig reads config.json with the component's closed decoder.
func readServiceConfig[T any](ctx context.Context, files *os.Root, decode func(io.Reader) (T, error)) (T, error) {
	var zero T
	b, err := mounts.Read(ctx, files, contracts.ServiceConfigFile, contracts.ServiceConfigMaxBytes)
	if err != nil {
		return zero, &fixedStepError{"config", mounts.ErrUnavailable}
	}
	c, err := decode(bytes.NewReader(b))
	if err != nil {
		return zero, &fixedStepError{"config", mounts.ErrUnavailable}
	}
	return c, nil
}

// servicePEMRoots converts a PEM bundle to the DER roots the existing checks take.
func servicePEMRoots(b []byte) ([][]byte, error) {
	var out [][]byte
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
	if len(strings.TrimSpace(string(b))) != 0 {
		return nil, mounts.ErrUnavailable
	}
	if _, _, err := mtls.OwnerTrustRoots(out, time.Now()); err != nil {
		return nil, mounts.ErrUnavailable
	}
	return out, nil
}

func readServiceRoots(ctx context.Context, files *os.Root, name string) ([][]byte, error) {
	b, err := mounts.Read(ctx, files, name, 64<<10)
	if err != nil {
		return nil, &fixedStepError{"roots/" + name, mounts.ErrUnavailable}
	}
	roots, err := servicePEMRoots(b)
	if err != nil {
		return nil, &fixedStepError{"roots/" + name, err}
	}
	return roots, nil
}

// servicePostgres is one MaxConns=1 pool per runtime login.
func servicePostgres(p contracts.ServicePostgres, roots [][]byte) (contracts.OwnerPostgresEndpoint, bool) {
	_, err := netip.ParseAddr(p.Host)
	ok := (err == nil || ownerDNSName.MatchString(p.Host)) && identity.Text(p.Database, 63) && p.Port >= 1 && p.Port <= 65535
	return contracts.OwnerPostgresEndpoint{Host: p.Host, Port: p.Port, Database: p.Database, Roots: roots, MaxConnections: 1}, ok
}

func validServiceStore(s contracts.ServiceObjectStore) bool {
	return ownerEndpoint(s.Endpoint) && identity.Text(s.Region, 128) && identity.Text(s.Bucket, 63)
}

// readPKIRoots reads one OpenBao PKI mount's CA (field class J): the
// unauthenticated ca/pem endpoint over the pinned provider roots.
func readPKIRoots(ctx context.Context, endpoint string, providerRoots [][]byte, mount string) ([][]byte, error) {
	if !ownerProviderName.MatchString(mount) {
		return nil, mounts.ErrUnavailable
	}
	client, err := ownerHTTP(endpoint, providerRoots)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	r, err := http.NewRequestWithContext(call, http.MethodGet, strings.TrimSuffix(endpoint, "/")+"/v1/"+mount+"/ca/pem", nil)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	resp, err := client.Do(r)
	if err != nil {
		return nil, &fixedStepError{"pki/" + mount, mounts.ErrUnavailable}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, &fixedStepError{"pki/" + mount, mounts.ErrUnavailable}
	}
	roots, err := servicePEMRoots(b)
	if err != nil {
		return nil, &fixedStepError{"pki/" + mount, err}
	}
	return roots, nil
}

// recoveryProof bounds provider logins and renewals by the current recovery
// observation; the recovery fence is the only remaining startup proof.
func recoveryProof(recovery *postgres.RecoveryReader) func(context.Context) (time.Time, error) {
	return func(ctx context.Context) (time.Time, error) {
		r, err := recovery.RecoveryState(ctx)
		if err != nil || !r.Valid(time.Now()) {
			return time.Time{}, mounts.ErrUnavailable
		}
		return r.FreshUntil, nil
	}
}
