package bootstrap

import (
	"bytes"
	"context"
	"os"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// Provider selection is transient composition information, not a replacement
// for the canonical desired identity or an installation/evidence capability.
type initialBootstrapServices struct {
	ObjectStore *contracts.SmallSeaweedPlan
	KeyService  *contracts.SmallOpenBaoPlan
}

func resolveInitialBootstrapObjectStore(ctx context.Context, input *os.Root, v *contracts.InitialBootstrapInput) (*contracts.SmallSeaweedPlan, error) {
	if v == nil || ctx == nil || input == nil {
		return nil, mounts.ErrUnavailable
	}
	if v.AuditStore.RootsSource == "" {
		return nil, nil
	}
	if v.AuditStore.RootsSource != contracts.InitialBootstrapBundledSeaweedRoots || v.AuditStore.RootsPEM != "" {
		return nil, mounts.ErrUnavailable
	}
	raw, err := mounts.Read(ctx, input, contracts.InitialBootstrapObjectStorePlanFile, 2048)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	plan, err := contracts.DecodeSmallSeaweedPlan(bytes.NewReader(raw))
	clear(raw)
	if err != nil || !plan.Valid() || plan.Name != v.Name || plan.Namespace != v.BootstrapNamespace || plan.Endpoint() != v.AuditStore.Endpoint {
		return nil, mounts.ErrUnavailable
	}
	ca, err := mounts.Read(ctx, input, contracts.InitialBootstrapObjectStoreCAFile, 32<<10)
	if err != nil || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	// Actual roots still pass the complete existing compiler and participate
	// in the original immutable desired digest. No source UID is invented.
	v.AuditStore.RootsPEM, v.AuditStore.RootsSource = string(ca), ""
	return &plan, nil
}
