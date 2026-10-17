package bootstrap

import (
	"context"
	"os"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

type hubWorkerRuntimeSelection uint8

const (
	hubWorkerRuntimeUnavailable hubWorkerRuntimeSelection = iota
	hubWorkerRuntimeLegacy
	hubWorkerRuntimeProvider
)

// This is only a closed constructor selection. Even a complete public input
// grants no readiness or effects: the selected concrete constructor must prove
// the original projection, native source, credentials and current SQL itself.
func selectHubWorkerRuntime(in contracts.HubWorkerDeployment, podUID string) (hubWorkerRuntimeSelection, error) {
	if validateHubWorkerInputs(in) != nil {
		return hubWorkerRuntimeUnavailable, mounts.ErrUnavailable
	}
	provider := in.ProviderAuthentication != nil || in.ProviderInputs != nil ||
		in.Activation != nil && in.Activation.WorkerLayout == contracts.HubWorkerProviderInstalledLayout
	if !provider {
		return hubWorkerRuntimeLegacy, nil
	}
	if !authorization.UUID(podUID) || in.Activation == nil ||
		in.Activation.WorkerLayout != contracts.HubWorkerProviderInstalledLayout ||
		in.ProviderAuthentication == nil || in.ProviderInputs == nil ||
		in.Postgres.MaxConnections != 1 || !kube.HubWorkerActivationBound(in) {
		return hubWorkerRuntimeUnavailable, mounts.ErrUnavailable
	}
	return hubWorkerRuntimeProvider, nil
}

func runHubWorkerFiles(ctx context.Context, files *os.Root, podUID string) error {
	if ctx == nil || ctx.Err() != nil || files == nil {
		return mounts.ErrUnavailable
	}
	// Read only the fixed public input before selecting either path. Optional
	// subroots, SQL files and provider material cannot select a constructor.
	_, input, err := readHubWorkerInputs(ctx, files)
	if err != nil {
		return err
	}
	selected, err := selectHubWorkerRuntime(input, podUID)
	if err != nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	switch selected {
	case hubWorkerRuntimeProvider:
		// The constructor rereads and independently validates the full profile.
		// A malformed/replaced input cannot fall through to static credentials.
		d, err := NewProviderInstalledHubWorkerDeployment(ctx, files, podUID)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Run()
	case hubWorkerRuntimeLegacy:
		d, err := NewHubWorkerDeployment(ctx, files)
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Run()
	default:
		return mounts.ErrUnavailable
	}
}
