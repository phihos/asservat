package bootstrap

import (
	"context"
	"encoding/json"
	"io"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
)

func (k *InstallerContinuation) providerSetupReader(endpoint contracts.OwnerProviderEndpoint, token []byte) (*providerconfig.SetupReader, error) {
	if k.keyService != nil {
		return providerconfig.NewBundledSetupReader(endpoint, token, k.keyService.Plan)
	}
	return providerconfig.NewSetupReader(endpoint, token)
}

func (k *InstallerContinuation) workerProviderInbox(ctx context.Context, in contracts.HubWorkerDeployment, selected contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, layout string) (kube.InstallerInbox, error) {
	if k.mixedProviderMode() != "" {
		return k.mixedWorkerProviderInbox(ctx, in, selected, account, layout)
	}
	if k.keyService == nil || k.objectStore == nil {
		return k.awaitInbox(ctx, 1)
	}
	var zero kube.InstallerInbox
	credential, err := kube.ReadOrInitializeSeaweedCredential(ctx, k.in.kubernetes("administrator-token"), in.Namespace.Name, selected.AuditCredentials, contracts.ConfigurationProviderAuditCredentialFile, contracts.SeaweedPrincipalKey{Purpose: "configuration-audit", ScopeID: in.InstallationID})
	if err != nil {
		return zero, err
	}
	artifact, err := providerconfig.ConfigurationProviderPairSetupArtifact(in, selected, account, layout, time.Now())
	if err != nil {
		return zero, err
	}
	token, err := k.applySmallProvider(ctx, 1, artifact)
	if err != nil {
		return zero, err
	}
	runtime, err := providerconfig.SeaweedRuntimeCredential(credential)
	if err != nil {
		clear(token)
		return zero, err
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		clear(token)
		return zero, mounts.ErrUnavailable
	}
	// There is no new credential carrier: the scoped key is already retained
	// in its original worker Secret. Only this real response enters inspection.
	return kube.InstallerInbox{InspectionToken: token, AuditCredential: raw}, nil
}

// Reuse the ordinary reviewed create-only recipe. The short-lived private
// management token and HTTP transport remain with this finite installer only.
func (k *InstallerContinuation) applySmallProvider(ctx context.Context, phase int, artifact []byte) ([]byte, error) {
	if k.keyService == nil || phase != 1 && phase != 3 || ctx == nil || ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	p := k.keyService
	c, err := bao.NewClient(&bao.Config{Address: p.Plan.Endpoint(), HttpClient: p.HTTP, MaxRetries: 0, DisableRedirects: true, DisableEnvironment: true})
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	c.SetToken(string(p.Token))
	name := "asservat-worker-inspection"
	if phase == 3 {
		name = "asservat-owner-inspection"
	}
	token, err := providerconfig.ApplyBundledSetupArtifact(ctx, c, name, artifact, io.Discard)
	if err != nil {
		return nil, initialOpenBaoCheck("continuation-apply")
	}
	return token, nil
}
