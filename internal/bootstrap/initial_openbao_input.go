package bootstrap

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

// Only public retained inputs are read here. Private seal/CA keys never enter
// this projection. A provider marker and current PVC proof are checked later
// before provider use; these files alone grant no installation authority.
func readBundledOpenBaoSource(ctx context.Context, files *os.Root, namespace, name string) (contracts.SmallOpenBaoPlan, []byte, string, error) {
	var zero contracts.SmallOpenBaoPlan
	raw, err := mounts.Read(ctx, files, contracts.InitialBootstrapKeyServicePlanFile, contracts.SmallOpenBaoPlanLimit)
	if err != nil {
		return zero, nil, "", mounts.ErrUnavailable
	}
	plan, err := contracts.DecodeSmallOpenBaoPlan(bytes.NewReader(raw))
	clear(raw)
	if err != nil || !plan.Valid() || plan.Namespace != namespace || plan.Name != name {
		return zero, nil, "", mounts.ErrUnavailable
	}
	ca, err := mounts.Read(ctx, files, contracts.InitialBootstrapKeyServiceCAFile, 32<<10)
	if err != nil {
		return zero, nil, "", mounts.ErrUnavailable
	}
	if _, err := providerconfig.TrustRootsPEM(ca, time.Now()); err != nil {
		return zero, nil, "", mounts.ErrUnavailable
	}
	backend, err := mounts.Read(ctx, files, contracts.InitialBootstrapKeyServiceBackendFile, 64)
	if err != nil || !authorization.UUID(string(backend)) || ctx.Err() != nil {
		return zero, nil, "", mounts.ErrUnavailable
	}
	return plan, ca, string(backend), nil
}

func resolveInitialBootstrapKeyService(ctx context.Context, files *os.Root, input *contracts.InitialBootstrapInput, kubernetesCA []byte) (*contracts.SmallOpenBaoPlan, error) {
	if input.KeyService.RootsSource == "" {
		return nil, nil
	}
	if input.KeyService.RootsSource != contracts.InitialBootstrapBundledOpenBaoRoots || input.KeyService.RootsPEM != "" {
		return nil, mounts.ErrUnavailable
	}
	plan, ca, _, err := readBundledOpenBaoSource(ctx, files, input.BootstrapNamespace, input.Name)
	if err != nil || input.KeyService.Endpoint != plan.Endpoint() || input.KeyService.AuditMount != contracts.SmallOpenBaoAuditMount || input.KeyService.AuditKey != "audit" || input.Providers != contracts.SmallOpenBaoInitialProviders() {
		return nil, mounts.ErrUnavailable
	}
	apiCA := []byte(input.Kubernetes.RootsPEM)
	if len(apiCA) == 0 {
		apiCA = kubernetesCA
	}
	roots, err := providerconfig.TrustRootsPEM(apiCA, time.Now())
	if err != nil || plan.Kubernetes.Endpoint != input.Kubernetes.Endpoint || !reflect.DeepEqual(roots, plan.Kubernetes.Roots) {
		return nil, mounts.ErrUnavailable
	}
	input.KeyService.RootsPEM, input.KeyService.RootsSource = string(ca), ""
	return &plan, nil
}
