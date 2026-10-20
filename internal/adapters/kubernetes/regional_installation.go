package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"slices"
	"strings"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	authn "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Fixed regional object names (ADR-193 step 5). The namespace is the
// operator's choice; everything inside it is installer-owned.
const (
	RegionalAccount    = "connector"
	RegionalDeployment = "connector"
	RegionalSource     = "connector-identity"
	RegionalSecret     = "cluster-credential"
	RegionalInputs     = "regional-inputs"
	regionalTemplate   = "asservat.io/template-sha256"
	regionalInstall    = "asservat.io/installation"
)

// RegionalInstallPlan is the regional installer's whole input: the hub's
// public offer, the operator-delivered bootstrap envelope and the target
// namespace. No field selects an endpoint outside the offer.
type RegionalInstallPlan struct {
	Offer     contracts.RegionalOffer
	Bootstrap value.BootstrapEnvelope
	Namespace string
	// AccountAdministrator admits a service account caller as the guards'
	// trusted initial administrator: the Helm hook's release-scoped installer
	// account (ADR-193 step 6). The operator CLI path never sets it.
	AccountAdministrator bool
	// Evidence is the operator's write-only evidence credential
	// (OwnerStorageCredential JSON). It is required exactly when the offer
	// names the regional executor (ADR-196 decision 7).
	Evidence []byte
}

// RegionalInstallation records the created objects by UID.
type RegionalInstallation struct {
	Namespace, Account, Deployment, Source, Secret, Inputs contracts.WorkerObjectReference
	WorkloadGuard, SourceGuard                             contracts.OwnerDeploymentGuard
	// Join is the public join record of an installed executor (ADR-196).
	Join *contracts.RegionalJoin
}

func (p RegionalInstallPlan) valid() bool {
	o, b := p.Offer, p.Bootstrap.Binding
	return o.Format == contracts.RegionalOfferFormat && p.Bootstrap.Valid() && b.InstallationID == o.InstallationID && b.IssuerEpoch == o.IssuerEpoch &&
		authorization.UUID(o.PermissionRootID) && identity.Text(o.Image, 512) && len(o.Federation.Roots) > 0 && len(o.ConnectorIssuerRoots) > 0 && len(o.ConnectorBacking) > 0 &&
		identity.Text(p.Namespace, 63) && !strings.HasPrefix(p.Namespace, "kube-") && p.executorValid()
}

// executorValid requires the evidence credential exactly with a complete
// executor offer, and a digest-pinned image for the executor's pins.
func (p RegionalInstallPlan) executorValid() bool {
	executor, err := p.Offer.RegionalExecutorOffered()
	if err != nil || executor != (len(p.Evidence) > 0) {
		return false
	}
	if !executor {
		return true
	}
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(p.Evidence))
	return err == nil && c.AccessKeyID != "" && c.SecretAccessKey != "" && digestPinnedAPIImage(p.Offer.Image) && p.Offer.WorkKey.ID != "" && p.Offer.KeyService.KeyID != "" && authorization.UUID(p.Offer.EvidenceStore.StoreID) &&
		(p.Offer.Capacity == nil || regionalCapacityOfferValid(*p.Offer.Capacity))
}

// regionalCapacityOfferValid checks the ADR-197 section's shape; the hub
// pins its values again at the join.
func regionalCapacityOfferValid(c contracts.RegionalCapacityOffer) bool {
	o := c.Owner
	host, port, err := net.SplitHostPort(c.OperationAddress)
	if err != nil || host == "" || port == "" || !authorization.UUID(o.SourceUID) || !hexDigest(o.TemplateDigest) || !hexDigest(o.ImageDigest) || !hexDigest(o.ProtectionDigest) || len(c.Keys) < 1 || len(c.Keys) > 256 {
		return false
	}
	for i, k := range c.Keys {
		if !identity.Text(k, 253) || slices.Contains(c.Keys[:i], k) {
			return false
		}
	}
	return true
}

func hexDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// InstallRegionalConnector installs one regional connector create-only, in
// this order: restricted namespace, account, RBAC, the Deployment gated at
// zero replicas, both guards, the source, the generation-0 Secret and
// regional.json. It then proves both guards with a minted short-lived token
// of the connector account and only then scales to one replica. A rerun
// reopens objects whose template matches and refuses any other.
// ponytail: a rerun with a different bootstrap is refused; reinstalling after
// bootstrap expiry means deleting the namespace first.
func InstallRegionalConnector(ctx context.Context, config *rest.Config, p RegionalInstallPlan) (_ RegionalInstallation, failure error) {
	var out RegionalInstallation
	step := "plan"
	defer func() {
		if failure != nil {
			failure = &regionalInstallError{step: step, cause: failure}
		}
	}()
	if ctx == nil || config == nil || !p.valid() {
		return out, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	step = "identity"
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(call, &authn.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil || !identity.Text(who.Status.UserInfo.Username, 253) || strings.HasPrefix(who.Status.UserInfo.Username, "system:serviceaccount:") && !p.AccountAdministrator {
		return out, cfg.ErrUnavailable // an operator identity unless the chart's installer account
	}
	// The connector account is the proof's probe; it can never administer.
	if who.Status.UserInfo.Username == "system:serviceaccount:"+p.Namespace+":"+RegionalAccount {
		return out, cfg.ErrInvalid
	}
	executor, _ := p.Offer.RegionalExecutorOffered()
	if executor {
		step = "start-api"
		if err = regionalStartAPIAvailable(call, config); err != nil {
			return out, err
		}
	}
	admins := []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}
	step = "namespace"
	marker := p.Offer.InstallationID + "/" + p.Bootstrap.Binding.ClusterID
	ns, err := ensureRegional(call, api.CoreV1().Namespaces(), &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: p.Namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "latest"}}}, marker)
	if err != nil {
		return out, err
	}
	out.Namespace = ref(ns.ObjectMeta)
	step = "account"
	account, err := ensureRegional(call, api.CoreV1().ServiceAccounts(p.Namespace), &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: RegionalAccount}, AutomountServiceAccountToken: ptr.To(false)}, marker)
	if err != nil {
		return out, err
	}
	out.Account = ref(account.ObjectMeta)
	var x regionalExecutor
	if executor {
		step = "capacity-account"
		if x.capacity, err = ensureRegional(call, api.CoreV1().ServiceAccounts(p.Namespace), &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: RegionalCapacityAccount}, AutomountServiceAccountToken: ptr.To(false)}, marker); err != nil {
			return out, err
		}
		step = "audience"
		if x.audience, err = regionalAudience(call, api, p.Namespace); err != nil {
			return out, err
		}
	}
	// ADR-197 decision 4: the regional capacity objects precede ungating.
	var capacity *contracts.RegionalCapacity
	if p.Offer.Capacity != nil {
		step = "capacity-probe"
		c, err := ensureRegionalCapacity(call, api, p, admins, x.audience)
		if err != nil {
			return out, err
		}
		capacity = &c
	}
	step = "rbac"
	clusterRole, role := regionalRBAC(p.Namespace)
	if executor {
		cluster, connector, capacity := regionalExecutorRBAC(p.Namespace)
		clusterRole.Rules = append(clusterRole.Rules, cluster...)
		role.Rules = append(role.Rules, connector...)
		if capacity != nil {
			clusterRole.Rules = append(clusterRole.Rules, regionalCapacityRBAC(p.Namespace)...)
		}
		if _, err = ensureRegional(call, api.RbacV1().Roles(p.Namespace), capacity, marker); err != nil {
			return out, err
		}
		if _, err = ensureRegional(call, api.RbacV1().RoleBindings(p.Namespace), &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: RegionalCapacityAccount}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: RegionalCapacityAccount}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: p.Namespace, Name: RegionalCapacityAccount}}}, marker); err != nil {
			return out, err
		}
	}
	if _, err = ensureRegional(call, api.RbacV1().ClusterRoles(), clusterRole, marker); err != nil {
		return out, err
	}
	subject := []rbac.Subject{{Kind: "ServiceAccount", Namespace: p.Namespace, Name: RegionalAccount}}
	if _, err = ensureRegional(call, api.RbacV1().ClusterRoleBindings(), &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: clusterRole.Name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: clusterRole.Name}, Subjects: subject}, marker); err != nil {
		return out, err
	}
	if _, err = ensureRegional(call, api.RbacV1().Roles(p.Namespace), role, marker); err != nil {
		return out, err
	}
	if _, err = ensureRegional(call, api.RbacV1().RoleBindings(p.Namespace), &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: RegionalAccount}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: RegionalAccount}, Subjects: subject}, marker); err != nil {
		return out, err
	}
	step = "deployment"
	deployment, err := ensureRegional(call, api.AppsV1().Deployments(p.Namespace), RegionalWorkload(p.Offer, executor), marker)
	if err != nil {
		return out, err
	}
	out.Deployment = ref(deployment.ObjectMeta)
	step = "workload-guard"
	control := cfg.NamespaceRef{Name: p.Namespace, UID: string(ns.UID)}
	workloadPlan := cfg.OwnerWorkloadAdministration{Name: p.Namespace, Deployment: RegionalDeployment, DeploymentUID: string(deployment.UID), ControlNamespace: control, Administrators: admins,
		ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: RegionalSource, ServiceAccount: RegionalAccount}},
		CredentialSecrets:   []cfg.OwnerCredentialSecret{{Secret: RegionalSecret, ServiceAccount: RegionalAccount}}}
	probes := []contracts.OwnerConfigurationProbe{{ConfigMap: RegionalSource, ServiceAccount: RegionalAccount}}
	if executor {
		// ADR-196 decision 4: the executor's starts and probes are in the
		// workload guard before ungating.
		for _, name := range []string{RegionalSettings, RegionalWorkTrust} {
			workloadPlan.ConfigurationProbes = append(workloadPlan.ConfigurationProbes, cfg.OwnerConfigurationProbe{ConfigMap: name, ServiceAccount: RegionalAccount})
			probes = append(probes, contracts.OwnerConfigurationProbe{ConfigMap: name, ServiceAccount: RegionalAccount})
		}
		workloadPlan.APIContextStarts = &cfg.OwnerAPIContextStarts{CapacityAccount: RegionalCapacityAccount, CapacityAccountUID: string(x.capacity.UID), ExecutionAccount: RegionalAccount, ExecutionAccountUID: string(account.UID), CapacityAudience: x.audience}
	}
	policy, binding, err := OwnerWorkloadAdmission(workloadPlan)
	if err != nil {
		return out, err
	}
	if out.WorkloadGuard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
		return out, err
	}
	step = "source-guard"
	sourcePlan := cfg.ConfigMapAdministration{Name: p.Namespace + "-source", SourceName: RegionalSource, ControlNamespace: control, Administrators: admins}
	if policy, binding, err = ConnectorIdentityAdmission(sourcePlan); err != nil {
		return out, err
	}
	if out.SourceGuard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
		return out, err
	}
	if executor {
		step = "executor-guards"
		settingsName, trustName, startName := regionalGuardNames(p.Namespace)
		if policy, binding, err = ConnectorAPISettingsAdmission(cfg.ConfigMapAdministration{Name: settingsName, SourceName: RegionalSettings, ControlNamespace: control, Administrators: admins}); err != nil {
			return out, err
		}
		if x.settingsGuard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
			return out, err
		}
		if policy, binding, err = APIContextWorkTrustAdmission(cfg.ConfigMapAdministration{Name: trustName, SourceName: RegionalWorkTrust, ControlNamespace: control, Administrators: admins}); err != nil {
			return out, err
		}
		if x.trustGuard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
			return out, err
		}
		users := "system:serviceaccount:" + p.Namespace + ":"
		if policy, binding, err = StartAdmission(cfg.LocalStartAdministration{Name: startName, ControlNamespace: control, CapacityUser: users + RegionalCapacityAccount, ExecutionUser: users + RegionalAccount}); err != nil {
			return out, err
		}
		if x.startGuard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
			return out, err
		}
	}
	step = "source"
	b := p.Bootstrap.Binding
	source, err := json.Marshal(contracts.ConnectorIdentityConfiguration{Format: contracts.ConnectorIdentityFormat, RootID: p.Offer.PermissionRootID, InstallationID: b.InstallationID, ClusterID: b.ClusterID, IssuerEpoch: b.IssuerEpoch, PeerID: b.PeerID, Revision: 1,
		ServerName: b.ClusterID + "." + p.Offer.ConnectorServerSuffix, ClientIssuerRoots: p.Offer.ConnectorIssuerRoots, ServerIssuerRoots: p.Offer.ConnectorIssuerRoots, Roles: p.Offer.Roles,
		Deployment: contracts.ConnectorDeployment{Namespace: p.Namespace, NamespaceUID: string(ns.UID), ServiceAccount: RegionalAccount, AccountUID: string(account.UID), Deployment: RegionalDeployment, DeploymentUID: string(deployment.UID), ServingSlots: contracts.RegionalServingSlots, RetainedProcesses: contracts.RegionalRetainedProcesses},
		Backing:    p.Offer.ConnectorBacking})
	if err != nil {
		return out, cfg.ErrInvalid
	}
	sourceObject, err := ensureRegional(call, api.CoreV1().ConfigMaps(p.Namespace), &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: RegionalSource}, Data: map[string]string{"connector-identity.json": string(source)}}, marker)
	if err != nil {
		return out, err
	}
	out.Source = ref(sourceObject.ObjectMeta)
	step = "credential"
	envelope, err := json.Marshal(fleetapp.ClusterCredentialSecret{Bootstrap: &p.Bootstrap})
	defer clear(envelope)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	// The Secret's template digest covers the envelope, so a rerun with the
	// same bootstrap reopens it even after the connector promoted its key.
	secret, err := ensureRegional(call, api.CoreV1().Secrets(p.Namespace), &core.Secret{ObjectMeta: meta.ObjectMeta{Name: RegionalSecret}, Data: map[string][]byte{"cluster-credential.json": envelope}}, marker)
	if err != nil {
		return out, err
	}
	out.Secret = ref(secret.ObjectMeta)
	if executor {
		step = "evidence"
		evidence, err := ensureRegional(call, api.CoreV1().Secrets(p.Namespace), &core.Secret{ObjectMeta: meta.ObjectMeta{Name: RegionalEvidence}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"evidence-storage.json": p.Evidence}}, marker)
		if err != nil {
			return out, err
		}
		x.evidence, x.evidenceVersion = ref(evidence.ObjectMeta), evidence.ResourceVersion
		step = "work-trust"
		var raw []byte
		if x.trustSettings, raw, err = regionalTrust(p); err != nil {
			return out, cfg.ErrInvalid
		}
		trust, err := ensureRegional(call, api.CoreV1().ConfigMaps(p.Namespace), &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: RegionalWorkTrust}, Immutable: ptr.To(true), Data: map[string]string{"api-context-work-trust.json": string(raw)}}, marker)
		if err != nil {
			return out, err
		}
		x.trust = ref(trust.ObjectMeta)
	}
	step = "api-roots"
	roots, err := regionalAPIRoots(call, api, p.Namespace)
	if err != nil {
		return out, err
	}
	step = "inputs"
	var apiContext *contracts.RegionalAPIContext
	if executor {
		apiContext = &contracts.RegionalAPIContext{Settings: RegionalSettings, SettingsGuard: x.settingsGuard,
			Starts:    contracts.OwnerDeploymentAPIContextStarts{CapacityAccount: ref(x.capacity.ObjectMeta), ExecutionAccount: out.Account, CapacityAudience: x.audience},
			WorkTrust: x.trust, WorkTrustGuard: x.trustGuard, TrustSettings: x.trustSettings,
			EvidenceStore: *p.Offer.EvidenceStore, KeyService: *p.Offer.KeyService, Owners: *p.Offer.Owners, Concurrency: RegionalExecutorConcurrency}
	}
	inputs, err := json.Marshal(contracts.RegionalDeployment{Format: contracts.RegionalDeploymentFormat, InstallationID: b.InstallationID, ClusterID: b.ClusterID, PermissionRootID: p.Offer.PermissionRootID, IssuerEpoch: b.IssuerEpoch, PeerID: b.PeerID,
		Namespace: out.Namespace, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.default.svc", Roots: roots}, Deployment: out.Deployment, WorkloadGuard: out.WorkloadGuard, ConfigurationProbes: probes,
		Source: out.Source, SourceGuard: out.SourceGuard, ClusterCredential: out.Secret, ClusterCredentialAccount: RegionalAccount, Hub: p.Offer.Federation, APIContext: apiContext, Capacity: capacity})
	if err != nil {
		return out, cfg.ErrInvalid
	}
	inputObject, err := ensureRegional(call, api.CoreV1().ConfigMaps(p.Namespace), &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: RegionalInputs}, Immutable: ptr.To(true), Data: map[string]string{"regional.json": string(inputs)}}, marker)
	if err != nil {
		return out, err
	}
	out.Inputs = ref(inputObject.ObjectMeta)
	step = "protection-proof"
	protection, err := proveRegionalProtection(call, config, api, p, out, workloadPlan, sourcePlan)
	if err != nil {
		return out, err
	}
	if executor {
		step = "settings"
		template, err := ConnectorAPITemplateDigest(deployment.Spec.Template)
		if err != nil {
			return out, err
		}
		decoded, _, err := DecodeConnectorIdentityConfiguration(source, out.Source.UID, p.Offer.PermissionRootID, b, time.Now())
		if err != nil {
			return out, err
		}
		installed, err := regionalExecutorSettings(p, out, x, template, protection, decoded.Source.Observation.Profile, inputObject)
		if err != nil {
			return out, err
		}
		encoded, err := contracts.EncodeConnectorAPIContextSettings(installed)
		if err != nil {
			return out, cfg.ErrInvalid
		}
		settings, err := ensureRegional(call, api.CoreV1().ConfigMaps(p.Namespace), &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: RegionalSettings}, Immutable: ptr.To(true), Data: map[string]string{"connector-api-context.json": string(encoded)}}, marker)
		if err != nil {
			return out, err
		}
		step = "executor-proof"
		sourceDigest, startup, err := proveRegionalExecutor(call, config, api, p, out, admins, settings, installed, sourcePlan, x)
		if err != nil {
			return out, err
		}
		var joinCapacity *contracts.RegionalJoinCapacity
		if capacity != nil {
			step = "capacity-proof"
			digest, err := proveRegionalCapacity(call, config, api, p, *capacity, admins)
			if err != nil {
				return out, err
			}
			joinCapacity = &contracts.RegionalJoinCapacity{NamespaceGuardDigest: hex.EncodeToString(digest[:]), Keys: capacity.Keys, TemplateDigest: installed.TemplateDigest, ProtectionDigest: installed.WorkloadProtectionDigest}
		}
		step = "join-record"
		join, object, err := regionalJoinRecord(p, out, source, sourceDigest, startup, joinCapacity)
		if err != nil {
			return out, err
		}
		if _, err = ensureRegional(call, api.CoreV1().ConfigMaps(p.Namespace), object, marker); err != nil {
			return out, err
		}
		out.Join = &join
	}
	step = "ungate"
	// Ungate only after both guards are proven with the account's own token.
	scale, err := api.AppsV1().Deployments(p.Namespace).GetScale(call, RegionalDeployment, meta.GetOptions{})
	if err != nil {
		return out, cfg.ErrUnavailable
	}
	if scale.Spec.Replicas != 1 {
		scale.Spec.Replicas = 1
		if _, err = api.AppsV1().Deployments(p.Namespace).UpdateScale(call, RegionalDeployment, scale, meta.UpdateOptions{}); err != nil {
			return out, cfg.ErrUnavailable
		}
	}
	return out, nil
}

// proveRegionalProtection mints a ten-minute token of the connector account
// and requires both guards to deny it while the exact source still decodes.
func proveRegionalProtection(ctx context.Context, config *rest.Config, api kubernetes.Interface, p RegionalInstallPlan, out RegionalInstallation, workload cfg.OwnerWorkloadAdministration, source cfg.ConfigMapAdministration) (artifact.Digest, error) {
	var zero artifact.Digest
	sub := func(step string, err error) error { return &regionalInstallError{step: step, cause: err} }
	token, err := api.CoreV1().ServiceAccounts(p.Namespace).CreateToken(ctx, RegionalAccount, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if err != nil || token.Status.Token == "" {
		return zero, sub("token", cfg.ErrUnavailable)
	}
	minted := rest.AnonymousClientConfig(config)
	minted.BearerToken = token.Status.Token
	defer func() { minted.BearerToken = "" }()
	control := workload.ControlNamespace
	// Separate observer and probe clients, as the connector process uses.
	client, err := NewPermissionClient(minted, p.Bootstrap.Binding.ClusterID, control, time.Now)
	if err != nil {
		return zero, sub("clients", err)
	}
	probe, err := NewPermissionClient(minted, p.Bootstrap.Binding.ClusterID, control, time.Now)
	if err != nil {
		return zero, sub("clients", err)
	}
	pin := func(g contracts.OwnerDeploymentGuard) GuardPin {
		return GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
	}
	guard, err := NewOwnerWorkloadProtection(client, probe, workload, pin(out.WorkloadGuard))
	if err != nil {
		return zero, sub("guards", err)
	}
	sourceGuard, err := NewConnectorIdentityProtection(client, probe, source, pin(out.SourceGuard))
	if err != nil {
		return zero, sub("guards", err)
	}
	reader, err := NewConnectorIdentitySource(client, sourceGuard, out.Source.Name, out.Source.UID, p.Offer.PermissionRootID, p.Bootstrap.Binding)
	if err != nil {
		return zero, sub("reader", err)
	}
	// Admission policies propagate asynchronously; a failed proof has no
	// effect, so it is retried within this bound before ungating.
	var last error
	for end := time.Now().Add(45 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
		if digest, _, err := guard.Current(ctx); err != nil {
			last = sub("workload-guard", err)
		} else if _, err = reader.ReadConnectorIdentityConfiguration(ctx); err != nil {
			last = sub("source", err)
		} else {
			return digest, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return zero, regionalProofFailure(last)
}

func regionalAPIRoots(ctx context.Context, api kubernetes.Interface, namespace string) ([][]byte, error) {
	// The namespace's kube-root-ca.crt carries the in-cluster API roots.
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
		c, err := api.CoreV1().ConfigMaps(namespace).Get(ctx, "kube-root-ca.crt", meta.GetOptions{})
		if err == nil {
			roots, err := pemRoots([]byte(c.Data["ca.crt"]))
			if err != nil || len(roots) == 0 {
				return nil, cfg.ErrUnavailable
			}
			return roots, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, cfg.ErrUnavailable
}

// RegionalWorkload is the connector Deployment, gated at zero replicas: the
// product image from the offer, the fixed projected inputs and Restricted
// security. It mounts no Secret; the credential is read through the API.
func RegionalWorkload(o contracts.RegionalOffer, executor bool) *apps.Deployment {
	labels := map[string]string{"app.kubernetes.io/name": "asservat-connector"}
	projection := []core.VolumeProjection{
		{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: RegionalInputs}, Items: []core.KeyToPath{{Key: "regional.json", Path: "regional.json"}}, Optional: ptr.To(false)}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: ConnectorEnrollmentAudience(o.InstallationID), Path: "connector-pod.token", ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-observer.token", ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-probe.token", ExpirationSeconds: ptr.To(int64(600))}},
	}
	if executor {
		// The executor's write-only evidence credential (ADR-196 decision 7).
		projection = append(projection, core.VolumeProjection{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: RegionalEvidence}, Items: []core.KeyToPath{{Key: "evidence-storage.json", Path: "evidence-storage.json"}}, Optional: ptr.To(false)}})
	}
	spec := core.PodSpec{ServiceAccountName: RegionalAccount, AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyAlways, TerminationGracePeriodSeconds: ptr.To(int64(10)),
		SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Volumes:         []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: projection}}}},
		Tolerations:     []core.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}, {Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}},
		Containers: []core.Container{{Name: "connector", Image: o.Image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/asservat", "connector"},
			Env:             []core.EnvVar{{Name: contracts.RegionalPodUIDEnvironment, ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"}}}},
			VolumeMounts:    []core.VolumeMount{{Name: "inputs", MountPath: contracts.RegionalDeploymentRoot, ReadOnly: true}},
			SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
			Resources:       core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("500m"), core.ResourceMemory: resource.MustParse("256Mi")}}}}}
	return &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: RegionalDeployment}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(0)), Selector: &meta.LabelSelector{MatchLabels: labels},
		Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: spec}}}
}

// regionalRBAC grants the connector exactly its reads, its own Secret CAS and
// the dry-run probe updates the guards must deny.
func regionalRBAC(namespace string) (*rbac.ClusterRole, *rbac.Role) {
	clusterRole := &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: namespace + "-connector"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{namespace}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{namespace, namespace + "-source"}, Verbs: []string{"get"}},
		{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews", "selfsubjectreviews"}, Verbs: []string{"create"}},
		{APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews"}, Verbs: []string{"create"}},
	}}
	role := &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: RegionalAccount}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{RegionalAccount}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{RegionalSource}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{RegionalDeployment}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{RegionalSecret}, Verbs: []string{"get", "update"}},
	}}
	return clusterRole, role
}

type regionalObject interface {
	meta.Object
	comparable
}

type regionalClient[T regionalObject] interface {
	Create(context.Context, T, meta.CreateOptions) (T, error)
	Get(context.Context, string, meta.GetOptions) (T, error)
}

// ensureRegional creates one object with the installation marker and its
// template digest, or reopens an existing one only when both match.
func ensureRegional[T regionalObject](ctx context.Context, c regionalClient[T], want T, marker string) (T, error) {
	var zero T
	stamped := reflect.ValueOf(want).Elem().Interface()
	raw, err := json.Marshal(stamped)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	d := sha256.Sum256(raw)
	annotations := map[string]string{regionalInstall: marker, regionalTemplate: hex.EncodeToString(d[:])}
	want.SetAnnotations(annotations)
	got, err := c.Create(ctx, want, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if got, err = c.Get(ctx, want.GetName(), meta.GetOptions{}); err == nil && (got.GetDeletionTimestamp() != nil || got.GetAnnotations()[regionalInstall] != marker || got.GetAnnotations()[regionalTemplate] != annotations[regionalTemplate]) {
			return zero, cfg.ErrChanged
		}
	}
	if err != nil {
		return zero, &regionalAPIError{reason: string(apierrors.ReasonForError(err))}
	}
	if !authorization.UUID(string(got.GetUID())) {
		return zero, cfg.ErrUnavailable
	}
	return got, nil
}

// regionalInstallError names the installer step; causes render only closed
// codes or API reasons, never server text or object content.
type regionalInstallError struct {
	step  string
	cause error
}

func (e *regionalInstallError) Error() string {
	var nested *regionalInstallError
	if errors.As(e.cause, &nested) {
		return strings.Replace(nested.Error(), "stopped at ", "stopped at "+e.step+"/", 1)
	}
	text := "regional installation stopped at " + e.step
	if e.step == "start-api" {
		return text + ": required CapacityReservation API unavailable; check the shipped regional CRD prerequisite"
	}
	var api *regionalAPIError
	var source *configurationWorkerDiagnostic
	var owner *ownerOperationDiagnostic
	switch {
	case errors.As(e.cause, &api):
		text += ": API " + api.reason
	case errors.As(e.cause, &source):
		text += ": " + configurationSourceCodes(source).Error()
	case errors.As(e.cause, &owner):
		text += ": " + projectionNativeCodes(owner).Error()
	case errors.Is(e.cause, cfg.ErrChanged):
		text += ": changed"
	case errors.Is(e.cause, cfg.ErrInvalid):
		text += ": invalid"
	default:
		text += ": unavailable"
	}
	return text
}
func (e *regionalInstallError) Unwrap() error { return e.cause }

type regionalAPIError struct{ reason string }

func (e *regionalAPIError) Error() string { return "API " + e.reason }
func (e *regionalAPIError) Unwrap() error { return cfg.ErrUnavailable }

func regionalProofFailure(last error) error {
	if last == nil {
		return cfg.ErrUnavailable
	}
	return last
}

func ref(m meta.ObjectMeta) contracts.WorkerObjectReference {
	return contracts.WorkerObjectReference{Name: m.Name, UID: string(m.UID)}
}
