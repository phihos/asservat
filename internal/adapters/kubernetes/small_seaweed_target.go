package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

// ResolveSmallSeaweedProvider observes current object identities for one
// installation operation. They are locators, not authority: Reload independently
// checks the exact Pod/controller/image/process/configuration before effects,
// after its CAS and after delivery. No replacement is selected within Reload.
func ResolveSmallSeaweedProvider(ctx context.Context, config *rest.Config, plan contracts.SmallSeaweedPlan, installation string, iam contracts.WorkerObjectReference) (*SeaweedProvider, error) {
	if ctx == nil || ctx.Err() != nil || !plan.Valid() || !authorization.UUID(installation) || !authorization.UUID(iam.UID) || iam.Name != plan.IAMSecretName() {
		return nil, seaweedProviderFailure("resolve-input")
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, seaweedProviderFailure("resolve-api")
	}
	reader := &SeaweedProvider{api: api}
	var server apps.StatefulSet
	if reader.read(ctx, "/apis/apps/v1/namespaces/"+plan.Namespace+"/statefulsets/"+plan.ServiceName(), &server) != nil || server.Name != plan.ServiceName() || server.Namespace != plan.Namespace || server.DeletionTimestamp != nil {
		return nil, seaweedProviderFailure("resolve-statefulset")
	}
	var pod core.Pod
	if reader.read(ctx, "/api/v1/namespaces/"+plan.Namespace+"/pods/"+plan.ServiceName()+"-0", &pod) != nil || pod.Name != plan.ServiceName()+"-0" || pod.Namespace != plan.Namespace || pod.DeletionTimestamp != nil || ctx.Err() != nil {
		return nil, seaweedProviderFailure("resolve-pod")
	}
	return NewSeaweedProvider(config, contracts.SeaweedProviderTarget{
		InstallationID: installation, Namespace: plan.Namespace,
		StatefulSet: contracts.WorkerObjectReference{Name: server.Name, UID: string(server.UID)},
		Pod:         contracts.WorkerObjectReference{Name: pod.Name, UID: string(pod.UID)},
		Config:      iam, Image: plan.Image, ExpectedArgs: providerconfig.SeaweedServerArgs(),
	})
}
