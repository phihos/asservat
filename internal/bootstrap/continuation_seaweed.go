package bootstrap

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// A cold provider operation owns the administrator client only until Close.
// It reuses the original Ready binding as provenance, never as renewed initial
// authority. Every effect remains bounded by this continuation's original ctx.
type continuationSeaweed struct {
	initial  contracts.SeaweedGrant
	binding  contracts.SmallSeaweedBindingReceipt
	backend  contracts.SmallSeaweedPrepared
	provider *kube.SeaweedProvider
	setup    *objectstore.SeaweedSetup
	closeTLS func()
}

func (s *continuationSeaweed) Close() {
	if s == nil {
		return
	}
	if s.setup != nil {
		s.setup.Close()
	}
	if s.closeTLS != nil {
		s.closeTLS()
	}
	clear(s.backend.RootsPEM)
	s.backend.Admin.SecretAccessKey = ""
}

func (k *InstallerContinuation) openSmallStore(ctx context.Context) (_ *continuationSeaweed, err error) {
	if k == nil || k.objectStore == nil || k.plan.Services == nil {
		return nil, mounts.ErrUnavailable
	}
	s := &continuationSeaweed{}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	admin := k.in.kubernetes("administrator-token")
	binder, err := kube.NewSmallSeaweedBinding(admin, *k.objectStore)
	if err != nil {
		return nil, &fixedStepError{"binding-client", err}
	}
	a := k.plan.Services.AuditStore
	s.binding, s.backend, err = binder.ReadReady(ctx, k.record.Scope.InstallationID, k.plan.Plan.RequestID, a.Bucket)
	if err != nil {
		return nil, &fixedStepError{"ready-source", err}
	}
	roots, err := providerconfig.TrustRootsPEM(s.backend.RootsPEM, time.Now())
	if err != nil || !reflect.DeepEqual(roots, a.Roots) || a.Endpoint != k.objectStore.Endpoint() {
		return nil, &fixedStepError{"original-trust", mounts.ErrUnavailable}
	}
	s.provider, err = kube.ResolveSmallSeaweedProvider(ctx, admin, *k.objectStore, k.record.Scope.InstallationID, s.backend.IAM)
	if err != nil {
		return nil, &fixedStepError{"current-provider", err}
	}
	c, err := s.provider.InitialAuditCredential(ctx)
	if err != nil {
		return nil, &fixedStepError{"original-initial-credential", err}
	}
	s.initial = contracts.SeaweedGrant{Credential: c, Bucket: a.Bucket, InstallationID: k.record.Scope.InstallationID}
	client, err := ownerHTTP(a.Endpoint, a.Roots)
	if err != nil {
		return nil, &fixedStepError{"tls-client", err}
	}
	s.closeTLS = client.CloseIdleConnections
	s.setup, err = objectstore.NewSeaweedSetup(a.Endpoint, a.Region, s.backend.Admin, client)
	if err != nil {
		return nil, &fixedStepError{"setup-client", err}
	}
	return s, nil
}

func (s *continuationSeaweed) enable(ctx context.Context, grants []contracts.SeaweedGrant) error {
	for _, grant := range grants {
		if grant.Bucket != s.initial.Bucket {
			return &fixedStepError{"owned-bucket-scope", mounts.ErrUnavailable}
		}
	}
	complete := make([]contracts.SeaweedGrant, 1, len(grants)+1)
	complete[0] = s.initial
	complete = append(complete, grants...)
	compiled, err := providerconfig.CompileSeaweedStorage(s.backend.Admin, complete)
	if err != nil {
		return &fixedStepError{"policy", err}
	}
	defer clear(compiled.Config)
	if err := s.setup.ConfigureBucket(ctx, s.binding.Binding.Initialization, compiled.Policies[s.initial.Bucket]); err != nil {
		return &fixedStepError{"owned-bucket", err}
	}
	if err := s.provider.Reload(ctx, compiled.Config); err != nil {
		return &fixedStepError{"iam-reload", err}
	}
	return nil
}

// Derive the same prefixes as the existing reviewed provider recipe instead of
// maintaining a second description of configuration audit storage privileges.
func workerSeaweedGrant(in contracts.HubWorkerDeployment, selection contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, layout string, credential contracts.SeaweedCredential, now time.Time) (contracts.SeaweedGrant, error) {
	var zero contracts.SeaweedGrant
	if credential.Principal != (contracts.SeaweedPrincipalKey{Purpose: "configuration-audit", ScopeID: in.InstallationID}) {
		return zero, mounts.ErrUnavailable
	}
	artifact, err := providerconfig.ConfigurationProviderPairSetupArtifact(in, selection, account, layout, now)
	if err != nil {
		return zero, err
	}
	var recipe struct {
		AuditStorage struct {
			Prefixes []string `json:"prefixes"`
		} `json:"auditStorage"`
	}
	if json.Unmarshal(artifact, &recipe) != nil || len(recipe.AuditStorage.Prefixes) == 0 {
		return zero, mounts.ErrUnavailable
	}
	return contracts.SeaweedGrant{Credential: credential, Bucket: in.AuditStore.Bucket, InstallationID: in.InstallationID, ClusterID: in.ClusterID, SourceUID: in.OwnerSource.UID, Prefixes: recipe.AuditStorage.Prefixes}, nil
}

func (k *InstallerContinuation) prepareSmallWorkerStore(ctx context.Context, in contracts.HubWorkerDeployment, selection contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, layout string) error {
	if k.objectStore == nil {
		return nil
	}
	credential, err := kube.ReadOrInitializeSeaweedCredential(ctx, k.in.kubernetes("administrator-token"), in.Namespace.Name, selection.AuditCredentials, contracts.ConfigurationProviderAuditCredentialFile, contracts.SeaweedPrincipalKey{Purpose: "configuration-audit", ScopeID: in.InstallationID})
	if err != nil {
		return &fixedStepError{"retained-worker-key", err}
	}
	grant, err := workerSeaweedGrant(in, selection, account, layout, credential, time.Now())
	if err != nil {
		return &fixedStepError{"worker-recipe", err}
	}
	store, err := k.openSmallStore(ctx)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.enable(ctx, []contracts.SeaweedGrant{grant})
}
