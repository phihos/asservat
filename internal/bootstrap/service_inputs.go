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

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Helm-native service inputs shared by the federation and key service:
// rendered config.json, the generated <name>-ids Secret, PEM CA
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

// readServiceConfig reads config.json with the component's closed decoder.
func readServiceConfig[T any](ctx context.Context, files *os.Root, decode func(io.Reader) (T, error)) (T, error) {
	var zero T
	b, err := mounts.Read(ctx, files, contracts.ServiceConfigFile, contracts.ServiceConfigMaxBytes)
	if err != nil {
		return zero, &fixedStepError{"config", mounts.ErrUnavailable}
	}
	c, err := decode(bytes.NewReader(b))
	if err != nil {
		// Helm-rendered values do not heal by waiting.
		return zero, &fixedStepError{"config", cfg.ErrInvalid}
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
