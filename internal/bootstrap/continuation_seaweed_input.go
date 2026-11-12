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
)

// The selected small backend serves audit and evidence under disjoint existing
// prefixes in one owned bucket. The source selects public installation inputs,
// never a provider identity inferred from a hostname or an evidence permission.
func resolveInstallerContinuationObjectStore(ctx context.Context, files *os.Root, input *contracts.InstallerContinuation) (*contracts.SmallSeaweedPlan, [][]byte, error) {
	if ctx == nil || files == nil || input == nil || ctx.Err() != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	if input.ObjectStoreSource == "" {
		return nil, nil, nil
	}
	if input.ObjectStoreSource != contracts.InitialBootstrapBundledSeaweedRoots {
		return nil, nil, mounts.ErrUnavailable
	}
	raw, err := mounts.Read(ctx, files, contracts.InitialBootstrapObjectStorePlanFile, 2048)
	if err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	plan, err := contracts.DecodeSmallSeaweedPlan(bytes.NewReader(raw))
	clear(raw)
	if err != nil || !plan.Valid() || plan.Namespace != input.Namespace {
		return nil, nil, mounts.ErrUnavailable
	}
	ca, err := mounts.Read(ctx, files, contracts.InitialBootstrapObjectStoreCAFile, 32<<10)
	if err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	roots, err := providerconfig.TrustRootsPEM(ca, time.Now())
	if err != nil || ctx.Err() != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	if input.Public != nil && input.Public.Federation != nil && input.Public.Federation.EvidenceStore != nil {
		e := input.Public.Federation.EvidenceStore
		if e.RootsPEM != "" || e.Endpoint != plan.Endpoint() {
			return nil, nil, mounts.ErrUnavailable
		}
		e.RootsPEM = string(ca)
	}
	input.ObjectStoreSource = ""
	return &plan, roots, nil
}

func continuationObjectStoreMatchesOriginal(plan *contracts.SmallSeaweedPlan, roots [][]byte, input contracts.InstallerContinuation, original contracts.InitialPreparer) bool {
	if plan == nil {
		return true
	}
	if original.Services == nil {
		return false
	}
	a := original.Services.AuditStore
	if plan.Namespace != input.Namespace || plan.Namespace != original.Plan.BootstrapNamespace.Name || plan.Name+"-preparation" != original.Plan.RootName || plan.Endpoint() != a.Endpoint || !reflect.DeepEqual(roots, a.Roots) {
		return false
	}
	if input.Public != nil && input.Public.Federation != nil && input.Public.Federation.EvidenceStore != nil {
		e := input.Public.Federation.EvidenceStore
		if e.Endpoint != a.Endpoint || e.Region != a.Region || e.Bucket != a.Bucket {
			return false
		}
	}
	return true
}
