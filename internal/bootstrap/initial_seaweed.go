package bootstrap

import (
	"context"
	"errors"
	"reflect"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

type initialSeaweedFailure struct{ stage string }

func (s initialSeaweedFailure) Error() string     { return "initial object store " + s.stage }
func (s initialSeaweedFailure) FixedStep() string { return s.stage }
func (s initialSeaweedFailure) Unwrap() error     { return mounts.ErrUnavailable }

// Owned adapters expose fixed stage labels. Preserve those labels only; raw
// provider responses, URLs, credentials and request bodies never enter CLI copy.
func initialSeaweedAt(stage string, err error) error {
	var named interface{ FixedStep() string }
	if errors.As(err, &named) {
		stage += "/" + named.FixedStep()
	}
	return initialSeaweedFailure{stage: stage}
}

// This prepares provider configuration only. The existing paid initial audit
// must still consume the ordinary credential and pass its immutable-version,
// verification and activation checks in the later installer phases.
func (d *initialBootstrapProcess) prepareSmallObjectStore() error {
	plan := d.services.ObjectStore
	if plan == nil {
		return nil
	}
	credential, err := initialSeaweedCredential(d.state, time.Now())
	if err != nil {
		return initialSeaweedAt("original-material", err)
	}
	ctx, cancel := context.WithDeadline(d.root, d.state.Material.StorageUseUntil)
	defer cancel()
	config := d.inputs.kubernetes("administrator-token")
	binder, err := kube.NewSmallSeaweedBinding(config, *plan)
	if err != nil {
		return initialSeaweedAt("binding-client", err)
	}
	receipt, backend, err := binder.Begin(ctx, contracts.SmallSeaweedBindingRequest{
		InstallationID: d.state.InstallationID, RequestID: d.state.RequestID,
		Bucket: d.desired.AuditStore.Bucket, StorageUseUntil: d.state.Material.StorageUseUntil,
	})
	if err != nil {
		return initialSeaweedAt("binding", err)
	}
	defer func() { backend.Admin.SecretAccessKey = "" }()
	defer clear(backend.RootsPEM)
	roots, err := providerconfig.TrustRootsPEM(backend.RootsPEM, time.Now())
	if err != nil || !reflect.DeepEqual(roots, d.desired.AuditStore.Roots) || d.desired.AuditStore.Endpoint != plan.Endpoint() {
		return initialSeaweedAt("source-trust", err)
	}
	compiled, err := providerconfig.CompileSeaweedStorage(backend.Admin, []contracts.SeaweedGrant{{Credential: credential, Bucket: d.desired.AuditStore.Bucket, InstallationID: d.state.InstallationID}})
	if err != nil {
		return initialSeaweedAt("policy", err)
	}
	defer clear(compiled.Config)
	client, err := ownerHTTP(d.desired.AuditStore.Endpoint, d.desired.AuditStore.Roots)
	if err != nil {
		return initialSeaweedAt("tls-client", err)
	}
	defer client.CloseIdleConnections()
	setup, err := objectstore.NewSeaweedSetup(d.desired.AuditStore.Endpoint, d.desired.AuditStore.Region, backend.Admin, client)
	if err != nil {
		return initialSeaweedAt("setup-client", err)
	}
	defer setup.Close()
	if err = setup.ConfigureBucket(ctx, receipt.Binding.Initialization, compiled.Policies[d.desired.AuditStore.Bucket]); err != nil {
		return initialSeaweedAt("bucket", err)
	}
	receipt, err = binder.MarkReady(ctx, receipt)
	if err != nil || receipt.Binding.Initialization.Pending || ctx.Err() != nil {
		return initialSeaweedAt("bucket-readiness", err)
	}
	provider, err := kube.ResolveSmallSeaweedProvider(ctx, config, *plan, d.state.InstallationID, backend.IAM)
	if err != nil {
		return initialSeaweedAt("current-provider", err)
	}
	if err = provider.Reload(ctx, compiled.Config); err != nil {
		return initialSeaweedAt("configuration-reload", err)
	}
	return nil
}

// This is called only for the first material-required response from the
// original bootstrap producer. Open must persist these keys with its original
// IDs before anything enables them. Existing state never calls this generator.
func generateInitialSeaweedStorage(material *contracts.InitialBootstrapMaterial) error {
	if material == nil || material.Storage != (contracts.OwnerStorageCredential{}) {
		return mounts.ErrUnavailable
	}
	c, err := providerconfig.GenerateSeaweedStorageCredential()
	if err != nil {
		return mounts.ErrUnavailable
	}
	material.Storage = c
	return nil
}

// Bind only the credential read from acknowledged original bootstrap state.
// Locally generated candidates, an empty scope or another provider's session
// token must never substitute for this stored installation's initial writer.
func initialSeaweedCredential(state contracts.InitialBootstrapState, now time.Time) (contracts.SeaweedCredential, error) {
	var zero contracts.SeaweedCredential
	if now.IsZero() || !authorization.UUID(state.InstallationID) || !authorization.UUID(state.RequestID) || state.Material == nil || !now.Before(state.Material.StorageUseUntil) || state.Material.Storage.SessionToken != "" {
		return zero, mounts.ErrUnavailable
	}
	c := contracts.SeaweedCredential{Principal: contracts.SeaweedPrincipalKey{Purpose: "initial-audit", ScopeID: state.InstallationID}, AccessKeyID: state.Material.Storage.AccessKeyID, SecretAccessKey: state.Material.Storage.SecretAccessKey}
	if providerconfig.ValidateSeaweedCredential(c) != nil {
		return zero, mounts.ErrUnavailable
	}
	return c, nil
}
