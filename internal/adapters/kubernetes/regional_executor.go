package kubernetes

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	authn "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Fixed regional executor object names (ADR-196 step 4); guard names are
// derived from the namespace like the workload and source guards.
const (
	RegionalCapacityAccount = "capacity"
	RegionalSettings        = "connector-api-context"
	RegionalWorkTrust       = "api-context-work-trust"
	RegionalEvidence        = "regional-evidence"
	// RegionalExecutorConcurrency bounds concurrent regional context starts.
	RegionalExecutorConcurrency = 4
)

func regionalGuardNames(namespace string) (settings, trust, start string) {
	return namespace + "-settings", namespace + "-trust", namespace + "-start"
}

// regionalExecutor carries the executor objects created before ungating.
type regionalExecutor struct {
	capacity                  *core.ServiceAccount
	audience                  string
	settingsGuard, trustGuard contracts.OwnerDeploymentGuard
	startGuard                contracts.OwnerDeploymentGuard
	evidence, trust           contracts.WorkerObjectReference
	evidenceVersion           string
	trustSettings             contracts.APIContextWorkTrustSettings
}

// regionalExecutorRBAC extends the connector's reads with the executor's: its
// settings, trust and evidence objects, the capacity account's token and the
// capacity reservations (ADR-171/175), and the capacity account's own role.
func regionalExecutorRBAC(namespace string) (cluster []rbac.PolicyRule, connector []rbac.PolicyRule, capacity *rbac.Role) {
	settings, trust, start := regionalGuardNames(namespace)
	cluster = []rbac.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{settings, trust, start}, Verbs: []string{"get"}},
		// ADR-179: delegated preview/request target resolution in this cluster
		// reads the namespace, workload, Pods by selector and the Pod →
		// ReplicaSet → Deployment chain (installed native 59: denied without).
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets", "replicasets"}, Verbs: []string{"get"}},
		// ADR-230: a probe policy's poll lists the namespace's kubelet
		// Unhealthy Pod Events (message text never leaves the region).
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"list"}},
		// ADR-241: a log policy's poll reads its Pods' container logs (only
		// counts and times leave the region); a resource policy's poll lists
		// the workload's metrics API PodMetrics.
		{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
		{APIGroups: []string{"metrics.k8s.io"}, Resources: []string{"pods"}, Verbs: []string{"list"}}}
	connector = []rbac.PolicyRule{
		// get for the settings/trust reads; update only for their dry-run probes.
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{RegionalSettings, RegionalWorkTrust}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{RegionalInputs}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{RegionalEvidence}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{RegionalCapacityAccount}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{RegionalCapacityAccount}, Verbs: []string{"create"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations"}, Verbs: []string{"get"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations/status"}, Verbs: []string{"update"}},
	}
	capacity = &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: RegionalCapacityAccount}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations"}, Verbs: []string{"create", "get"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"capacityreservations/status"}, Verbs: []string{"update"}},
	}}
	return cluster, connector, capacity
}

// regionalAudience is the API server's default token audience, pinned for the
// ADR-175 capacity TokenRequest.
func regionalAudience(ctx context.Context, api kubernetes.Interface, namespace string) (string, error) {
	t, err := api.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, RegionalAccount, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if err != nil || len(t.Spec.Audiences) < 1 || t.Spec.Audiences[0] == "" {
		return "", cfg.ErrUnavailable
	}
	return t.Spec.Audiences[0], nil
}

// regionalTrust is the region's verify-only work trust: the offer's one hub
// work key for this cluster (ADR-196 decision 7).
func regionalTrust(p RegionalInstallPlan) (contracts.APIContextWorkTrustSettings, []byte, error) {
	b := p.Bootstrap.Binding
	t := contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, RootID: p.Offer.PermissionRootID, InstallationID: b.InstallationID, ClusterID: b.ClusterID, IssuerEpoch: b.IssuerEpoch, Revision: 1, Enabled: true, Keys: []contracts.APIContextWorkPublicKey{*p.Offer.WorkKey}}
	raw, err := contracts.EncodeAPIContextTrust(t)
	return t, raw, err
}

// regionalExecutorSettings are the guarded settings the executor reads at
// start. They pin every other mounted input, including regional.json.
func regionalExecutorSettings(p RegionalInstallPlan, out RegionalInstallation, x regionalExecutor, template, protection artifact.Digest, revision value.ConnectorCredentialProfile, inputs *core.ConfigMap) (contracts.ConnectorAPIContextSettings, error) {
	b := p.Bootstrap.Binding
	parts := strings.Split(p.Offer.Image, "@sha256:")
	if len(parts) != 2 {
		return contracts.ConnectorAPIContextSettings{}, cfg.ErrInvalid
	}
	projection := compiler.ProjectionDigest()
	r := revision.Revision
	return contracts.ConnectorAPIContextSettings{Format: contracts.ConnectorAPIContextFormat, RootID: p.Offer.PermissionRootID, InstallationID: b.InstallationID, ClusterID: b.ClusterID, IssuerEpoch: b.IssuerEpoch,
		ConnectorRevision: contracts.APIContextRevision{UID: r.UID, Generation: r.Generation, Digest: hex.EncodeToString(r.Digest[:])},
		Namespace:         out.Namespace.Name, NamespaceUID: out.Namespace.UID, Account: RegionalAccount, AccountUID: out.Account.UID, Deployment: RegionalDeployment, DeploymentUID: out.Deployment.UID,
		ImageDigest: parts[1], TemplateDigest: hex.EncodeToString(template[:]), ProjectionDigest: hex.EncodeToString(projection[:]), WorkloadProtectionDigest: hex.EncodeToString(protection[:]),
		CapacityAccount: RegionalCapacityAccount, CapacityAccountUID: string(x.capacity.UID),
		Inputs: []contracts.ConnectorAPIInput{{Kind: "ConfigMap", Name: RegionalInputs, UID: string(inputs.UID), ResourceVersion: inputs.ResourceVersion},
			{Kind: "Secret", Name: RegionalEvidence, UID: x.evidence.UID, ResourceVersion: x.evidenceVersion, DedicatedToAPI: true}},
		StartGuard: contracts.ConnectorAPIStartGuard{Name: x.startGuard.Name, PolicyUID: x.startGuard.PolicyUID, PolicyGeneration: x.startGuard.PolicyGeneration, BindingUID: x.startGuard.BindingUID, BindingResourceVersion: x.startGuard.BindingResourceVersion}}, nil
}

// proveRegionalExecutor proves the settings and trust guards with the
// connector account's own minted token and returns the digests the join
// record pins: the source guard's (staged at generation 1) and the
// executor's StartupDigest.
func proveRegionalExecutor(ctx context.Context, config *rest.Config, api kubernetes.Interface, p RegionalInstallPlan, out RegionalInstallation, admins []cfg.KubernetesActor, settings *core.ConfigMap, installed contracts.ConnectorAPIContextSettings, source cfg.ConfigMapAdministration, x regionalExecutor) (sourceDigest, startup artifact.Digest, failure error) {
	sub := func(step string, err error) error { return &regionalInstallError{step: step, cause: err} }
	token, err := api.CoreV1().ServiceAccounts(p.Namespace).CreateToken(ctx, RegionalAccount, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if err != nil || token.Status.Token == "" {
		return sourceDigest, startup, sub("executor-token", cfg.ErrUnavailable)
	}
	minted := rest.AnonymousClientConfig(config)
	minted.BearerToken = token.Status.Token
	defer func() { minted.BearerToken = "" }()
	control := source.ControlNamespace
	client, err := NewPermissionClient(minted, p.Bootstrap.Binding.ClusterID, control, time.Now)
	if err != nil {
		return sourceDigest, startup, sub("executor-clients", err)
	}
	probe, err := NewPermissionClient(minted, p.Bootstrap.Binding.ClusterID, control, time.Now)
	if err != nil {
		return sourceDigest, startup, sub("executor-clients", err)
	}
	pin := func(g contracts.OwnerDeploymentGuard) GuardPin {
		return GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
	}
	plan := func(g contracts.OwnerDeploymentGuard, name string) cfg.ConfigMapAdministration {
		return cfg.ConfigMapAdministration{Name: g.Name, SourceName: name, ControlNamespace: control, Administrators: admins}
	}
	sourceGuard, err := NewConnectorIdentityProtection(client, probe, source, pin(out.SourceGuard))
	if err != nil {
		return sourceDigest, startup, sub("executor-guards", err)
	}
	settingsGuard, err := NewConnectorAPISettingsProtection(client, probe, plan(x.settingsGuard, RegionalSettings), pin(x.settingsGuard))
	if err != nil {
		return sourceDigest, startup, sub("executor-guards", err)
	}
	trustGuard, err := NewAPIContextWorkTrustProtection(client, probe, plan(x.trustGuard, RegionalWorkTrust), pin(x.trustGuard))
	if err != nil {
		return sourceDigest, startup, sub("executor-guards", err)
	}
	var last error
	for end := time.Now().Add(45 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
		var settingsDigest artifact.Digest
		if sourceDigest, err = sourceGuard.Proven(ctx); err != nil {
			last = sub("source-guard", err)
		} else if settingsDigest, err = settingsGuard.Proven(ctx); err != nil {
			last = sub("settings-guard", err)
		} else if _, err = trustGuard.Proven(ctx); err != nil {
			last = sub("trust-guard", err)
		} else {
			read, uid, version, err := settingsGuard.ReadSettings(ctx)
			if err != nil || uid != string(settings.UID) || version != settings.ResourceVersion {
				return sourceDigest, startup, sub("settings", cfg.ErrChanged)
			}
			a, _ := contracts.EncodeConnectorAPIContextSettings(read)
			z, _ := contracts.EncodeConnectorAPIContextSettings(installed)
			if !bytes.Equal(a, z) {
				return sourceDigest, startup, sub("settings", cfg.ErrChanged)
			}
			if startup, _, err = ConnectorAPIStartupDigest(settingsDigest, uid, version, installed); err != nil {
				return sourceDigest, startup, sub("startup", err)
			}
			return sourceDigest, startup, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return sourceDigest, startup, regionalProofFailure(last)
}

// regionalJoinRecord is the immutable public join record (ADR-196 decision 2).
func regionalJoinRecord(p RegionalInstallPlan, out RegionalInstallation, source []byte, sourceDigest, startup artifact.Digest, capacity *contracts.RegionalJoinCapacity) (contracts.RegionalJoin, *core.ConfigMap, error) {
	b := p.Bootstrap.Binding
	j := contracts.RegionalJoin{Format: contracts.RegionalJoinFormat, InstallationID: b.InstallationID, ClusterID: b.ClusterID, PeerID: b.PeerID, IssuerEpoch: b.IssuerEpoch,
		Connector: contracts.FederationPeer{SourceUID: out.Source.UID, ProtectionDigest: hex.EncodeToString(sourceDigest[:]), Source: json.RawMessage(source)},
		Executor:  contracts.OwnerPublicExecutor{NamespaceUID: out.Namespace.UID, AccountUID: out.Account.UID, StartupDigest: hex.EncodeToString(startup[:]), ImageDigest: strings.Split(p.Offer.Image, "@sha256:")[1]},
		Capacity:  capacity}
	raw, err := json.Marshal(j)
	if err != nil || len(raw) > contracts.RegionalJoinMaxBytes {
		return j, nil, cfg.ErrInvalid
	}
	return j, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: contracts.RegionalJoinName}, Immutable: ptr.To(true), Data: map[string]string{contracts.RegionalJoinFile: string(raw)}}, nil
}
