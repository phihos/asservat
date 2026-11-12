package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

const smallRegionalRoot = "/run/asservat/cluster/bundled"
const smallRegionalPreparerFile = "hub-preparer.json"

type smallRegionalOptions struct {
	Name, BootstrapID, Namespace                                 string
	Join                                                         bool
	Alertmanager, MappingsJSON, EndpointsJSON, AuthorizationFile string
	Collector                                                    *kube.RegionalCollectorPlan
}

// This finite Helm invocation runs as the original trusted bootstrap account.
// It delivers an existing human-issued bootstrap; it never issues one itself or
// supplies runtime hub credentials. The ordinary external installer is unchanged.
func runSmallRegionalInstaller(ctx context.Context, options smallRegionalOptions, out io.Writer) (failure error) {
	step := "inputs"
	defer func() {
		if failure != nil {
			failure = &fixedStepError{"bundled-regional/" + step, failure}
		}
	}()
	if ctx == nil || ctx.Err() != nil || out == nil || len(validation.IsDNS1123Label(options.Name)) != 0 || len(options.Name) > 30 || !authorization.UUID(options.BootstrapID) {
		return mounts.ErrUnavailable
	}
	call, end := context.WithTimeout(ctx, 5*time.Minute)
	defer end()
	files, err := os.OpenRoot(smallRegionalRoot)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer files.Close()
	native, err := rest.InClusterConfig()
	if err != nil {
		return mounts.ErrUnavailable
	}
	original, config, plan, err := loadSmallRegionalSources(call, files, native, options.Name)
	if err != nil {
		return err
	}
	step = "offer"
	offer, err := kube.ReadRegionalOffer(call, config, original.Plan.Workload.Namespace, original.Plan.InstallationID)
	if err != nil {
		return err
	}
	owner, err := kube.OwnerInputs(call, config, original.Plan.Workload.Namespace, original.Plan.InstallationID)
	if err != nil || !smallRegionalOfferMatches(original, plan, owner, offer) {
		return mounts.ErrUnavailable
	}
	step = "provider"
	provider, err := openInitialOpenBaoProvider(call, files, plan, config)
	if err != nil {
		return err
	}
	defer provider.Close()
	if provider.Identity.Namespace != original.Plan.BootstrapNamespace {
		return mounts.ErrUnavailable
	}
	channel, err := kms.NewBootstrapChannel(plan.Endpoint(), string(provider.Token), contracts.SmallOpenBaoBootstrapMount, contracts.OwnerFleetChannelPrefix, "regional-installer", offer.InstallationID, provider.HTTP, time.Now)
	if err != nil {
		return err
	}
	step = "bootstrap"
	envelope, err := channel.ReadBootstrapEnvelope(call, options.BootstrapID)
	if err != nil || envelope.Binding.IssuerEpoch != offer.IssuerEpoch {
		return mounts.ErrUnavailable
	}
	// Persisting storage and installation may not outlive this issued credential.
	operation, stop := context.WithDeadline(call, envelope.NotAfter)
	defer stop()
	p := kube.RegionalInstallPlan{Offer: offer, Bootstrap: envelope, Namespace: options.Namespace, AccountAdministrator: true, Alertmanager: options.Alertmanager, Collector: options.Collector}
	if err := smallRegionalExtras(operation, options, &p); err != nil {
		return err
	}
	defer clear(p.ProfileAuthorization)
	step = "storage-keys"
	p.Evidence, p.History, err = kube.PrepareRegionalSeaweedStorage(operation, config, p)
	if err != nil {
		return err
	}
	defer clear(p.Evidence)
	defer clear(p.History)
	step = "storage"
	if err := enableSmallRegionalStorage(operation, config, files, original, p); err != nil {
		return err
	}
	step = "install"
	installed, err := kube.InstallRegionalConnector(operation, config, p)
	if err != nil {
		return err
	}
	if options.Join {
		step = "join"
		if installed.Join == nil {
			return mounts.ErrUnavailable
		}
		if _, err = joinInstalledRegionalCluster(operation, config, owner.Namespace.Name, *installed.Join, 2, 1); err != nil {
			return err
		}
	}
	step = "result"
	return json.NewEncoder(out).Encode(installed)
}

func loadSmallRegionalSources(ctx context.Context, files *os.Root, native *rest.Config, name string) (contracts.InitialPreparer, *rest.Config, contracts.SmallOpenBaoPlan, error) {
	var zero contracts.InitialPreparer
	var noPlan contracts.SmallOpenBaoPlan
	if ctx == nil || ctx.Err() != nil || files == nil || native == nil {
		return zero, nil, noPlan, mounts.ErrUnavailable
	}
	raw, err := mounts.Read(ctx, files, smallRegionalPreparerFile, contracts.InitialPreparationMaxBytes)
	if err != nil {
		return zero, nil, noPlan, err
	}
	original, err := contracts.DecodeInitialPreparer(bytes.NewReader(raw))
	if err != nil || original.Format != contracts.InitialPreparerFormat || original.Services == nil || original.Plan.RootName != name+"-preparation" || !authorization.UUID(original.Plan.InstallationID) {
		return zero, nil, noPlan, mounts.ErrUnavailable
	}
	plan, ca, _, err := readBundledOpenBaoSource(ctx, files, original.Plan.BootstrapNamespace.Name, name)
	if err != nil {
		return zero, nil, noPlan, err
	}
	roots, err := providerconfig.TrustRootsPEM(ca, time.Now())
	if err != nil || !continuationKeyServiceMatchesOriginal(plan, roots, contracts.InstallerContinuation{Namespace: original.Plan.BootstrapNamespace.Name}, original) {
		return zero, nil, noPlan, mounts.ErrUnavailable
	}
	// The original API address may use another certificate-covered address of
	// this same API. Its roots must match the independent in-cluster API roots.
	apiCA := native.CAData
	if len(apiCA) == 0 && native.CAFile != "" {
		apiCA, err = os.ReadFile(native.CAFile)
	}
	if err != nil || len(apiCA) > 32<<10 || native.Insecure {
		return zero, nil, noPlan, mounts.ErrUnavailable
	}
	apiRoots, err := providerconfig.TrustRootsPEM(apiCA, time.Now())
	if err != nil || !reflect.DeepEqual(apiRoots, original.Kubernetes.Roots) {
		return zero, nil, noPlan, mounts.ErrUnavailable
	}
	config := rest.CopyConfig(native)
	config.Host = original.Kubernetes.Endpoint
	config.CAFile = ""
	config.CAData = apiCA
	client, err := coreclient.NewForConfig(config)
	if err != nil {
		return zero, nil, noPlan, mounts.ErrUnavailable
	}
	current, err := client.ConfigMaps(plan.Namespace).Get(ctx, name+"-preparer", meta.GetOptions{})
	if err != nil || current.DeletionTimestamp != nil || current.Immutable == nil || !*current.Immutable || len(current.Data) != 1 || len(current.BinaryData) != 0 {
		return zero, nil, noPlan, mounts.ErrUnavailable
	}
	actual, err := contracts.DecodeInitialPreparer(strings.NewReader(current.Data["deployment.json"]))
	if err != nil || !reflect.DeepEqual(actual, original) || ctx.Err() != nil {
		return zero, nil, noPlan, mounts.ErrUnavailable
	}
	return original, config, plan, nil
}

func smallRegionalOfferMatches(original contracts.InitialPreparer, plan contracts.SmallOpenBaoPlan, owner contracts.OwnerDeployment, offer contracts.RegionalOffer) bool {
	if original.Services == nil || !plan.Valid() || owner.Public == nil {
		return false
	}
	s := original.Services
	executor, err := offer.RegionalExecutorOffered()
	return err == nil && executor && offer.Format == contracts.RegionalOfferFormat && offer.InstallationID == original.Plan.InstallationID && offer.HubClusterID == original.Plan.ClusterID && offer.IssuerEpoch == s.Fleet.IssuerEpoch && offer.PermissionRootID == owner.PermissionRootID && offer.Image == original.Plan.Workload.Image && owner.InstallationID == offer.InstallationID && owner.ClusterID == offer.HubClusterID && owner.Namespace.Name == original.Plan.Workload.Namespace && owner.KeyService.Endpoint == plan.Endpoint() && reflect.DeepEqual(owner.KeyService.Roots, s.KeyService.Roots) && offer.EvidenceStore.Endpoint == s.AuditStore.Endpoint && offer.EvidenceStore.Bucket == s.AuditStore.Bucket && offer.EvidenceStore.Region == s.AuditStore.Region && reflect.DeepEqual(offer.EvidenceStore.Roots, s.AuditStore.Roots)
}

func smallRegionalExtras(ctx context.Context, options smallRegionalOptions, p *kube.RegionalInstallPlan) error {
	decode := func(raw string, maximum int, target any) error {
		if len(raw) > maximum {
			return mounts.ErrUnavailable
		}
		d := json.NewDecoder(strings.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
			return mounts.ErrUnavailable
		}
		return nil
	}
	if options.MappingsJSON != "" && (decode(options.MappingsJSON, 32<<10, &p.IdentityMappings) != nil || !kube.IdentityMappingsValid(p.IdentityMappings)) {
		return mounts.ErrUnavailable
	}
	if options.EndpointsJSON != "" && (decode(options.EndpointsJSON, 64<<10, &p.ProfileEndpoints) != nil || !kube.ProfileEndpointsValid(p.ProfileEndpoints)) {
		return mounts.ErrUnavailable
	}
	if options.AuthorizationFile != "" {
		var err error
		p.ProfileAuthorization, err = readInstallerProfileAuthorization(ctx, options.AuthorizationFile)
		if err != nil {
			return err
		}
	}
	return nil
}

func enableSmallRegionalStorage(ctx context.Context, config *rest.Config, files *os.Root, original contracts.InitialPreparer, p kube.RegionalInstallPlan) error {
	raw, err := mounts.Read(ctx, files, contracts.InitialBootstrapObjectStorePlanFile, 2048)
	if err != nil {
		return err
	}
	plan, err := contracts.DecodeSmallSeaweedPlan(bytes.NewReader(raw))
	if err != nil || plan.Namespace != original.Plan.BootstrapNamespace.Name || plan.Name+"-preparation" != original.Plan.RootName {
		return mounts.ErrUnavailable
	}
	store, err := openSmallSeaweedStore(ctx, config, original, plan, p.Offer.InstallationID)
	if err != nil {
		return err
	}
	defer store.Close()
	grants := make([]contracts.SeaweedGrant, 0, 2)
	for i, purpose := range []string{"regional-write", "regional-history"} {
		credential := p.Evidence
		if i == 1 {
			credential = p.History
		}
		runtime, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(credential))
		if err != nil || runtime.SessionToken != "" {
			return mounts.ErrUnavailable
		}
		grants = append(grants, contracts.SeaweedGrant{Credential: contracts.SeaweedCredential{Principal: contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: p.Bootstrap.Binding.ClusterID}, AccessKeyID: runtime.AccessKeyID, SecretAccessKey: runtime.SecretAccessKey}, Bucket: store.initial.Bucket, InstallationID: p.Offer.InstallationID, ClusterID: p.Bootstrap.Binding.ClusterID, RootID: p.Offer.PermissionRootID})
	}
	current, err := store.provider.Configuration(ctx)
	if err != nil {
		return err
	}
	defer clear(current)
	compiled, err := providerconfig.AppendSeaweedRegionalGrants(current, store.backend.Admin, p.Offer.InstallationID, grants)
	if err != nil {
		return err
	}
	defer clear(compiled.Config)
	if err = store.setup.AppendBucketPolicy(ctx, store.binding.Binding.Initialization, compiled.Policies[store.initial.Bucket]); err != nil {
		return err
	}
	return store.provider.Reload(ctx, compiled.Config)
}
