package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	audit "asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// TestFederationRegionalProductWithRealKubernetes runs the actual product
// `hub-federation` (ADR-170) and `connector` (ADR-169) processes as
// Restricted Pods in two owned clusters. The hub duties run under the product
// connector role grants, real OpenBao PKI/transit and encrypted S3 audit; the
// regional Pod holds only its cluster credential Secret and in-cluster reads.
// Synthetic setup roots remain explicit: the fixture creates the roles, PKI,
// owner/fleet trust and the fleet operator's authority, not a product
// installer. Generation 1 comes from a BootstrapIssuer slot (ADR-193).
func TestFederationRegionalProductWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned two-cluster context fixture required")
	}
	raw, e := os.ReadFile(path)
	var f fixture
	if e != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) != 2 || f.WorkerImage == "" {
		t.Fatal("owned product fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	installation, epoch, root := custodyID(), custodyID(), custodyID()
	r := newDirectNativeCluster(t, ctx, f, 1, installation, productRegionalSpec(f.WorkerImage, installation))
	hub := newFederationHub(t, ctx, f)
	// The SQL lab needs an accepted owner configuration only for its fleet
	// trust and observation loop; no owner process runs in this test.
	ownerCA := directNativeCA(t)
	pool := value.OwnerPool{InstallationID: installation, ClusterID: hub.id, IssuerEpoch: epoch, Namespace: hub.namespace, NamespaceUID: hub.namespaceUID, Service: "owner", ServiceUID: custodyID(), Deployment: "owner", DeploymentUID: custodyID(), ServiceAccount: "owner", AccountUID: custodyID(), Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile, NativeCandidateLimit: value.OwnerRegistrationsPerPool}
	accepted := value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{41}}, ProtectionDigest: artifact.Digest{42}, IssuerRoots: [][]byte{ownerCA.DER}}
	sql := newDirectNativeSQL(t, ctx, f, accepted, root)
	sql.startSources(t, ctx, cancel, accepted)
	credentials := sql.productConnectorRoles(t, ctx)
	sql.retirementBacking(t)
	pki := newFederationPKI(t, f)
	// ADR-193 step 3f: the fleet operator issues one audited slot for this
	// cluster; the hub stages the source and enrolls generation 1 in-band.
	envelope := issueRegionalBootstrap(t, ctx, f, sql, pki, installation, r.id)
	source := r.regionalSource(t, ctx, sql, root, installation, epoch, envelope.Binding.PeerID, false, CA{DER: pki.root}, CA{DER: pki.root})
	profile := source.configuration.Source.Observation.Profile
	pki.roles(t, profile)
	credential := r.bootstrapCredential(t, ctx, envelope, value.ClusterCredentialProfile{RootID: root, PeerID: profile.Binding.PeerID, InstallationID: installation, ClusterID: r.id}, hub.dial)
	// The regional input is materialized first: the Pod has been waiting
	// since cluster setup, and the product retries enrollment until the hub
	// serves. Kubelet mount backoff can still delay its start.
	in := contracts.RegionalDeployment{Format: contracts.RegionalDeploymentFormat, InstallationID: installation, ClusterID: r.id, PermissionRootID: root, IssuerEpoch: epoch, PeerID: profile.Binding.PeerID,
		Namespace: contracts.WorkerObjectReference{Name: r.namespace.Name, UID: string(r.namespace.UID)}, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.default.svc", Roots: r.apiRoots(t)},
		Deployment: contracts.WorkerObjectReference{Name: "regional", UID: string(r.deployments["regional"].UID)}, WorkloadGuard: federationGuard(r.plan.Name, r.guard, r.plan.Administrators), ConfigurationProbes: federationProbes(r.plan.ConfigurationProbes),
		Source: contracts.WorkerObjectReference{Name: source.name, UID: source.uid}, SourceGuard: federationGuard(source.plan.Name, source.pin, source.plan.Administrators),
		ClusterCredential: contracts.WorkerObjectReference{Name: credential.secret, UID: credential.uid}, ClusterCredentialAccount: "regional", Hub: contracts.RegionalHubEndpoint{Endpoint: "https://" + hub.dial, ServerName: federationServerName, Roots: [][]byte{hub.ca}}}
	encoded, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.api.CoreV1().ConfigMaps(r.namespace.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "regional-inputs"}, Data: map[string]string{"regional.json": string(encoded)}}, meta.CreateOptions{}); e != nil {
		t.Fatal("regional input", e)
	}
	r.inputUntil["regional"] = time.Now().Add(4 * time.Minute)
	// ADR-193: no peer list; the federation resolves the staged profile.
	hub.start(t, ctx, f, sql, pki, credentials, root, installation)

	r.waitProductRunning(t, ctx)
	pod := r.pods["regional"]
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil || v.Projected != nil && slicesContainSecret(v.Projected.Sources) {
			t.Fatal("regional Pod mounts a Secret")
		}
	}
	// Success is the hub's own SQL record: an accepted process for exactly
	// this regional Pod with both leaves activated, then the product's single
	// readiness line after the delegated registry checks.
	deadline := time.Now().Add(90 * time.Second)
	var active bool
	for time.Now().Before(deadline) && !active {
		e = sql.lab.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM connector_identity_process p WHERE p.root_id=$1 AND p.peer_id=$2 AND p.pod_uid=$3 AND p.accepted_at IS NOT NULL
 AND EXISTS(SELECT 1 FROM connector_credential_attempt c WHERE c.id=p.client_current_id AND c.activated_at IS NOT NULL)
 AND EXISTS(SELECT 1 FROM connector_credential_attempt c WHERE c.id=p.server_current_id AND c.activated_at IS NOT NULL))`, root, profile.Binding.PeerID, string(pod.UID)).Scan(&active)
		if e != nil {
			t.Fatal(e)
		}
		if !active {
			time.Sleep(time.Second)
		}
	}
	if !active {
		hub.logs(t, ctx)
		r.productLogs(t, ctx)
		var claimed, acknowledged, staged, reserved, activated bool
		_ = sql.lab.admin.QueryRow(ctx, `SELECT b.claimed_at IS NOT NULL, b.claim_acknowledged_at IS NOT NULL,
 EXISTS(SELECT 1 FROM connector_identity_profile p WHERE p.root_id=$3 AND p.peer_id=$4),
 EXISTS(SELECT 1 FROM cluster_bootstrap_activation a WHERE a.installation_id=b.installation_id AND a.bootstrap_id=b.id),
 EXISTS(SELECT 1 FROM cluster_bootstrap_activation a WHERE a.installation_id=b.installation_id AND a.bootstrap_id=b.id AND a.activated_at IS NOT NULL)
 FROM fleet_bootstrap b WHERE b.installation_id=$1 AND b.id=$2`, installation, envelope.BootstrapID, root, profile.Binding.PeerID).Scan(&claimed, &acknowledged, &staged, &reserved, &activated)
		t.Logf("bootstrap state: claimed=%v claim-acknowledged=%v staged=%v reserved=%v activated=%v", claimed, acknowledged, staged, reserved, activated)
		t.Fatal("regional process not enrolled with both leaves")
	}
	for time.Now().Before(deadline) {
		if strings.Contains(r.productLog(t, ctx), "connector process credentials active") {
			break
		}
		time.Sleep(time.Second)
	}
	if !strings.Contains(r.productLog(t, ctx), "connector process credentials active") {
		hub.logs(t, ctx)
		r.productLogs(t, ctx)
		t.Fatal("regional credentials never became active after registry checks")
	}
	// Generation 1 came from the bootstrap: an activated, audited bootstrap
	// row and lineage, and the Secret promoted with its envelope erased.
	var activated bool
	if e = sql.lab.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cluster_bootstrap_activation a JOIN cluster_enrollment_lineage l ON l.lineage_id=a.lineage_id
 WHERE a.installation_id=$1 AND a.bootstrap_id=$2 AND a.activated_at IS NOT NULL AND a.audit_acknowledged_at IS NOT NULL AND l.root_id=$3 AND l.peer_id=$4 AND l.fenced IS NULL)`,
		installation, envelope.BootstrapID, root, profile.Binding.PeerID).Scan(&activated); e != nil || !activated {
		t.Fatal("generation 1 not bootstrap-activated", e)
	}
	stored, e := r.api.CoreV1().Secrets(r.namespace.Name).Get(ctx, credential.secret, meta.GetOptions{})
	var promoted app.ClusterCredentialSecret
	if e != nil || json.Unmarshal(stored.Data["cluster-credential.json"], &promoted) != nil || promoted.Generation < 1 || promoted.Bootstrap != nil || promoted.PendingSeed != nil {
		t.Fatal("cluster credential Secret not promoted", e)
	}
	for _, x := range []struct {
		api       kubernetes.Interface
		namespace string
		selector  string
	}{{hub.api, hub.namespace, "app=federation"}, {r.api, r.namespace.Name, "fixture-role=regional"}} {
		list, e := x.api.CoreV1().Pods(x.namespace).List(ctx, meta.ListOptions{LabelSelector: x.selector})
		if e != nil || len(list.Items) != 1 {
			t.Fatal("product Pod lookup", e)
		}
		for _, s := range list.Items[0].Status.ContainerStatuses {
			if s.RestartCount != 0 {
				t.Fatal("product process restarted", x.selector)
			}
		}
	}
	t.Logf("product federation/regional enrollment: hub roles=%d bootstrap=product-issuer synthetic-setup-roots=true installer=false", len(credentials))
}

// waitProductRunning waits for the original regional Pod to run without a
// restart and reports its waiting reasons and events if it never does.
func (x *directNativeCluster) waitProductRunning(t *testing.T, ctx context.Context) {
	t.Helper()
	original := x.pods["regional"]
	for end := x.inputUntil["regional"]; time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		p, e := x.api.CoreV1().Pods(x.namespace.Name).Get(ctx, original.Name, meta.GetOptions{})
		if e != nil || p.UID != original.UID {
			t.Fatal("regional original Pod changed", e)
		}
		for _, s := range p.Status.ContainerStatuses {
			if s.RestartCount != 0 || s.State.Terminated != nil {
				x.productLogs(t, ctx)
				t.Fatal("regional product process failed at startup")
			}
		}
		if p.Status.Phase == core.PodRunning {
			x.pods["regional"] = p.DeepCopy()
			return
		}
	}
	p, e := x.api.CoreV1().Pods(x.namespace.Name).Get(ctx, original.Name, meta.GetOptions{})
	if e == nil {
		for _, c := range p.Status.Conditions {
			t.Logf("regional condition %s=%s reason=%s", c.Type, c.Status, c.Reason)
		}
		for _, s := range p.Status.ContainerStatuses {
			if s.State.Waiting != nil {
				t.Logf("regional waiting reason=%s message=%.300s", s.State.Waiting.Reason, s.State.Waiting.Message)
			}
		}
	}
	events, e := x.api.CoreV1().Events(x.namespace.Name).List(ctx, meta.ListOptions{FieldSelector: "involvedObject.name=" + original.Name})
	if e == nil {
		for _, ev := range events.Items {
			t.Logf("regional event %s count=%d: %.300s", ev.Reason, ev.Count, ev.Message)
		}
	}
	t.Fatal("regional product Pod never ran")
}

func slicesContainSecret(sources []core.VolumeProjection) bool {
	for _, s := range sources {
		if s.Secret != nil {
			return true
		}
	}
	return false
}

func federationGuard(name string, pin kube.GuardPin, admins []cfg.KubernetesActor) contracts.OwnerDeploymentGuard {
	out := contracts.OwnerDeploymentGuard{Name: name, PolicyUID: pin.PolicyUID, PolicyGeneration: pin.PolicyGeneration, BindingUID: pin.BindingUID, BindingResourceVersion: pin.BindingResourceVersion}
	for _, a := range admins {
		out.Administrators = append(out.Administrators, contracts.OwnerDeploymentActor{Kind: a.Kind, Name: a.Name})
	}
	return out
}

const federationServerName = "federation.fixture.invalid"

func federationProbes(in []cfg.OwnerConfigurationProbe) []contracts.OwnerConfigurationProbe {
	out := make([]contracts.OwnerConfigurationProbe, len(in))
	for i, p := range in {
		out[i] = contracts.OwnerConfigurationProbe{ConfigMap: p.ConfigMap, ServiceAccount: p.ServiceAccount}
	}
	return out
}

func productRegionalSpec(image, installation string) func(string) core.PodSpec {
	return func(mode string) core.PodSpec {
		projection := []core.VolumeProjection{
			{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: "regional-inputs"}, Items: []core.KeyToPath{{Key: "regional.json", Path: "regional.json"}}, Optional: ptr.To(false)}},
			{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: kube.ConnectorEnrollmentAudience(installation), Path: "connector-pod.token", ExpirationSeconds: ptr.To(int64(600))}},
			{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-observer.token", ExpirationSeconds: ptr.To(int64(600))}},
			{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-probe.token", ExpirationSeconds: ptr.To(int64(600))}},
		}
		return productPodSpec(mode, image, []string{"/asservat", "connector"}, contracts.RegionalDeploymentRoot, projection, []core.EnvVar{{Name: contracts.RegionalPodUIDEnvironment, ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"}}}})
	}
}

func productPodSpec(account, image string, command []string, root string, projection []core.VolumeProjection, env []core.EnvVar) core.PodSpec {
	return core.PodSpec{ServiceAccountName: account, AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyAlways, TerminationGracePeriodSeconds: ptr.To(int64(10)),
		SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Volumes:         []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: projection}}}},
		// The accepted connector template pins both eviction tolerations.
		Tolerations: []core.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}, {Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}},
		Containers: []core.Container{{Name: "product", Image: image, ImagePullPolicy: core.PullIfNotPresent, Command: command, Env: env,
			VolumeMounts:    []core.VolumeMount{{Name: "inputs", MountPath: root, ReadOnly: true}},
			SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
			Resources:       core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("500m"), core.ResourceMemory: resource.MustParse("256Mi")}}}}}
}

func (x *directNativeCluster) apiRoots(t *testing.T) [][]byte {
	t.Helper()
	b, _ := pem.Decode(x.config.CAData)
	if b == nil {
		t.Fatal("regional API root unavailable")
	}
	return [][]byte{b.Bytes}
}

func (x *directNativeCluster) productLog(t *testing.T, ctx context.Context) string {
	t.Helper()
	p := x.pods["regional"]
	if p == nil {
		return ""
	}
	stream, e := x.api.CoreV1().Pods(x.namespace.Name).GetLogs(p.Name, &core.PodLogOptions{LimitBytes: ptr.To(int64(16 << 10))}).Stream(ctx)
	if e != nil {
		return ""
	}
	defer stream.Close()
	b, _ := io.ReadAll(io.LimitReader(stream, 16<<10))
	return string(b)
}

// productLogs reports only fixed product diagnostic lines, never inputs.
func (x *directNativeCluster) productLogs(t *testing.T, ctx context.Context) {
	t.Helper()
	for _, line := range strings.Split(x.productLog(t, ctx), "\n") {
		if strings.HasPrefix(line, "connector ") || strings.HasPrefix(line, "service stopped") {
			t.Log("regional:", line)
		}
	}
}

// productConnectorRoles creates the eight ADR-170 connector duty logins with
// the exact product grant inventory and makes them the source's duty roles.
// The staging pool uses the product source login.
func (l *directNativeSQL) productConnectorRoles(t *testing.T, ctx context.Context) map[string]contracts.OwnerSQLCredential {
	t.Helper()
	prefix := connectorSQLRolePrefix(custodyID())
	out := map[string]contracts.OwnerSQLCredential{}
	names := map[string]string{}
	for _, purpose := range append(contracts.PublicRuntimeFederationPurposes(), contracts.PublicRuntimeConnectorMaintenancePurposes()...) {
		name := prefix + strings.ReplaceAll(purpose, "-", "_")
		password := "synthetic-" + purpose
		if _, e := l.lab.admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{name}.Sanitize()+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 3 PASSWORD '"+password+"'"); e != nil {
			t.Fatal("product connector role", purpose, e)
		}
		grants, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, name)
		if !ok {
			t.Fatal("product grant layout missing", purpose)
		}
		for _, g := range grants {
			if _, e := l.lab.admin.Exec(ctx, g); e != nil {
				t.Fatal("product connector grant", purpose, e)
			}
		}
		names[purpose] = name
		out[purpose] = contracts.OwnerSQLCredential{Username: name, Password: password}
	}
	l.roles = value.ConnectorIdentityRoles{Source: names["connector-source"], Journal: names["connector-journal"], Acknowledgement: names["connector-ack"], Cleanup: names["connector-cleanup"], Verifier: names["connector-verifier"], Finalizer: names["connector-finalizer"]}
	old := l.pools["connector-source"]
	c := old.Config()
	c.ConnConfig.User, c.ConnConfig.Password = names["connector-source"], "synthetic-connector-source"
	p, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	old.Close()
	l.pools["connector-source"] = p
	return out
}

// retirementBacking selects the installed connector-operation-history/v2
// layout with prepaid retirement, the only one the product journal role has.
func (l *directNativeSQL) retirementBacking(t *testing.T) {
	t.Helper()
	b := &l.backing
	q := *b.Policy.History
	q.Layout = audit.ConnectorRetirementHistoryLayout
	b.Policy.History = &q
	b.Policy.ValidUntil = time.Now().UTC().Truncate(time.Microsecond).Add(20 * time.Minute)
	bb, ww := q.SlotBacking(b.Policy.MaxPurgeLeases)
	b.Policy.BackupReservedBytes = bb * b.Policy.MetadataSlots
	b.Policy.WALReservedBytes = ww * b.Policy.MetadataSlots
	rows := 1 + b.ProfileLimit + b.ProfileLimit*(b.SourceTransitionLimit+1)
	b.SourceBackupReservedBytes = rows * 2 * q.MaximumRowFootprintBytes * q.BackupCopies
	b.SourceWALReservedBytes = (2*b.SourceTransitionLimit + app.ConnectorRetirementTicketTransitions*b.ProfileLimit*(b.SourceTransitionLimit+1)) * q.MaximumTransitionWALBytes * q.WALCopies
	if !b.Valid() {
		t.Fatal("synthetic v2 retirement backing invalid")
	}
}

type federationPKI struct {
	f                         fixture
	mount, transit            string
	root                      []byte
	client, server, wrap, unw string
}

func newFederationPKI(t *testing.T, f fixture) *federationPKI {
	t.Helper()
	id := strings.ReplaceAll(custodyID()[:8], "-", "")
	p := &federationPKI{f: f, mount: "federation-pki-" + id, transit: "federation-audit-" + id}
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+p.mount, map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "2h"}}, 204)
	generated := request(t, f.KMS, "synthetic-root", p.mount+"/root/generate/internal", map[string]any{"common_name": "synthetic-connector-root", "ttl": "2h", "key_type": "ec", "key_bits": 256}, 200)
	b, _ := pem.Decode([]byte(generated["data"].(map[string]any)["certificate"].(string)))
	if b == nil {
		t.Fatal("connector PKI root")
	}
	p.root = b.Bytes
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+p.transit, map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", p.transit+"/keys/records", map[string]any{"type": "aes256-gcm96"}, 200)
	p.wrap = p.token(t, "seal", `path "`+p.transit+`/encrypt/records" { capabilities=["update"] }`)
	p.unw = p.token(t, "open", `path "`+p.transit+`/decrypt/records" { capabilities=["update"] }`)
	return p
}

// issueRegionalBootstrap issues one slot for cluster through the product
// BootstrapIssuer and returns the envelope the operator delivers. The fleet
// operator's protected authority is synthetic; the reservation, KV delivery,
// encrypted issue audit and activation are the actual adapters on the
// fixture's bootstrap logins.
func issueRegionalBootstrap(t *testing.T, ctx context.Context, f fixture, l *directNativeSQL, p *federationPKI, installation, cluster string) value.BootstrapEnvelope {
	t.Helper()
	const profile = "regional-installer"
	mount := p.mount + "-bootstrap"
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+mount, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, 204)
	if e := waitFixtureKV(ctx, f.KMS, mount); e != nil {
		t.Fatal(e)
	}
	request(t, f.KMS, "synthetic-root", mount+"/config", map[string]any{"cas_required": true, "max_versions": 1, "delete_version_after": "5m"}, 204)
	token := p.token(t, "bootstrap", `path "`+mount+`/data/connector/`+installation+`/*" { capabilities=["create","read"] }`)
	keys := tlsBridge(t, f.KMS)
	channel, e := kms.NewBootstrapChannel(keys.URL, token, mount, "connector", profile, installation, keys.Client(), time.Now)
	if e != nil {
		t.Fatal(e)
	}
	seal, e := kms.NewSealer(keys.URL, p.wrap, p.transit, "records", keys.Client())
	if e != nil {
		t.Fatal(e)
	}
	open, e := kms.NewOpener(keys.URL, p.unw, p.transit, "records", keys.Client())
	if e != nil {
		t.Fatal(e)
	}
	storage := tlsBridge(t, f.S3)
	store, e := objectstore.New(storage.URL, l.audit.Region, l.audit.Bucket, credentials.NewStaticCredentialsProvider(l.audit.AccessKey, l.audit.SecretKey, ""), storage.Client())
	if e != nil {
		t.Fatal(e)
	}
	// The reservation mints slot, cluster and peer IDs; the fixture's cluster
	// already has its ID, so the second minted ID is that one.
	ids := []string{custodyID(), cluster, custodyID()}
	reserve, e := postgres.NewBootstrapReservations(ctx, l.pools["bootstrap-reserve"], installation, func() string { out := ids[0]; ids = ids[1:]; return out })
	if e != nil {
		t.Fatal(e)
	}
	var issues [3]*postgres.BootstrapIssues
	for i, purpose := range []string{"bootstrap-record", "bootstrap-audit", "bootstrap-activate"} {
		if issues[i], e = postgres.NewBootstrapIssues(ctx, l.pools[purpose], installation); e != nil {
			t.Fatal(e)
		}
	}
	authority := enrollmentAuthorityFunc(func(ctx context.Context, token, delivery string) (value.EnrollmentAuthority, error) {
		if token != "synthetic-operator" || delivery != profile {
			return value.EnrollmentAuthority{}, value.ErrDenied
		}
		// The current trust revision, read fresh: the fixture stands in for the
		// protected fleet operator resolution.
		var epoch string
		trust := identity.Revision{}
		var digest []byte
		if e := l.lab.admin.QueryRow(ctx, `SELECT issuer_epoch::text, source_uid, source_generation, source_digest FROM fleet_trust WHERE installation_id=$1`, installation).Scan(&epoch, &trust.UID, &trust.Generation, &digest); e != nil {
			return value.EnrollmentAuthority{}, value.ErrUnavailable
		}
		copy(trust.Digest[:], digest)
		now := time.Now().UTC()
		return value.EnrollmentAuthority{InstallationID: installation, IssuerEpoch: epoch, DeliveryProfile: profile, Actor: identity.Principal{Issuer: "https://identity.example.test", Subject: "synthetic-operator", ClientID: "console", Kind: identity.Human},
			IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, AdministrationRevision: trust, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}, nil
	})
	issuer := app.BootstrapIssuer{Authority: authority, Reservations: reserve, Credentials: channel, Records: issues[0], Audits: issues[1], Objects: &objectstore.BootstrapIssueObjects{Store: store, Seal: seal, Open: open}, Activation: issues[2], Now: time.Now}
	intent, e := issuer.Issue(ctx, "synthetic-operator", app.BootstrapInput{KeyDigest: artifact.Digest{1}, DisplayName: "synthetic region", Region: "eu-test", DeliveryProfile: profile})
	if e != nil || !intent.Issued || intent.Credential == nil || intent.Slot.Binding.ClusterID != cluster {
		t.Fatal("audited bootstrap issuance", e)
	}
	// The operator's own read of the delivered secret, never printed.
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, keys.URL+"/v1/"+mount+"/data/connector/"+installation+"/"+intent.Slot.ID, nil)
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("X-Vault-Token", token)
	response, e := keys.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	var delivered struct {
		Data struct {
			Data struct {
				Secret string `json:"secret"`
			} `json:"data"`
		} `json:"data"`
	}
	decoded := json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&delivered)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || decoded != nil {
		t.Fatal("operator bootstrap read unavailable")
	}
	s := intent.Slot
	return value.BootstrapEnvelope{BootstrapID: s.ID, Binding: s.Binding, DeliveryProfile: profile, RequestDigest: s.RequestDigest, NotBefore: s.NotBefore, NotAfter: s.NotAfter, Secret: delivered.Data.Data.Secret}
}

func (p *federationPKI) token(t *testing.T, name, policy string) string {
	t.Helper()
	full := p.mount + "-" + name
	request(t, p.f.KMS, "synthetic-root", "sys/policies/acl/"+full, map[string]any{"policy": policy}, 204)
	return request(t, p.f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{full}, "no_default_policy": true, "ttl": "20m"}, 200)["auth"].(map[string]any)["client_token"].(string)
}

// roles fixes each usage to the peer URI (and server DNS name), matching the
// product verifier's exact leaf shape.
func (p *federationPKI) roles(t *testing.T, profile value.ConnectorCredentialProfile) {
	t.Helper()
	uri, e := mtls.PeerURI(profile.Binding)
	if e != nil {
		t.Fatal(e)
	}
	for _, usage := range []string{"client", "server"} {
		role := map[string]any{"require_cn": false, "use_csr_common_name": false, "use_csr_sans": false, "allow_ip_sans": false, "allow_localhost": false, "allowed_uri_sans": []string{uri.String()}, "key_type": "any", "server_flag": usage == "server", "client_flag": usage == "client", "code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{}, "basic_constraints_valid_for_non_ca": true, "not_before_duration": "30s", "max_ttl": "1h", "ttl": "30m"}
		if usage == "server" {
			role["allowed_domains"] = []string{profile.ServerName}
			role["allow_bare_domains"] = true
		}
		request(t, p.f.KMS, "synthetic-root", p.mount+"/roles/connector-"+usage, role, 200)
	}
	p.client = p.token(t, "client", `path "`+p.mount+`/sign/connector-client" { capabilities=["update"] }`)
	p.server = p.token(t, "server", `path "`+p.mount+`/sign/connector-server" { capabilities=["update"] }`)
}

type federationHub struct {
	api                         kubernetes.Interface
	id, namespace, namespaceUID string
	dial                        string
	ca                          []byte
	certificate, key            []byte
}

func newFederationHub(t *testing.T, ctx context.Context, f fixture) *federationHub {
	t.Helper()
	config, e := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if e != nil {
		t.Fatal(e)
	}
	api, e := kubernetes.NewForConfig(config)
	if e != nil {
		t.Fatal(e)
	}
	id := custodyID()
	name := "federation-" + id[len(id)-10:]
	ns, e := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = api.CoreV1().Namespaces().Delete(c, name, meta.DeleteOptions{})
	})
	h := &federationHub{api: api, id: custodyID(), namespace: name, namespaceUID: string(ns.UID)}
	service, e := api.CoreV1().Services(name).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: "federation"}, Spec: core.ServiceSpec{Type: core.ServiceTypeNodePort, Selector: map[string]string{"app": "federation"}, Ports: []core.ServicePort{{Name: "federation", Port: 9446, TargetPort: intstr.FromInt(9446), Protocol: core.ProtocolTCP}}}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	nodes, e := api.CoreV1().Nodes().List(ctx, meta.ListOptions{})
	if e != nil {
		t.Fatal(e)
	}
	for _, node := range nodes.Items {
		if string(node.UID) != f.Clusters[0].NodeUID {
			continue
		}
		for _, a := range node.Status.Addresses {
			if a.Type == core.NodeInternalIP && net.ParseIP(a.Address) != nil {
				h.dial = net.JoinHostPort(a.Address, fmt.Sprint(service.Spec.Ports[0].NodePort))
			}
		}
	}
	if h.dial == "" {
		t.Fatal("federation node address missing")
	}
	// Deployment-provided serving identity for the fixed server name.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-federation-root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, e := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{federationServerName}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, &leafKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	h.ca = caDER
	h.certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	h.key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	return h
}

func (h *federationHub) start(t *testing.T, ctx context.Context, f fixture, l *directNativeSQL, p *federationPKI, sql map[string]contracts.OwnerSQLCredential, root, installation string) {
	t.Helper()
	pg, e := url.Parse("postgres://" + f.NativeProviders.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	port := 5432
	if pg.Port() != "" {
		fmt.Sscan(pg.Port(), &port)
	}
	c := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: installation, ClusterID: h.id, PermissionRootID: root, Port: 9446, Concurrency: 2,
		Postgres:   contracts.OwnerPostgresEndpoint{Host: pg.Hostname(), Port: port, Database: "custody_test", Roots: [][]byte{f.NativeProviders.Root}, MaxConnections: 1},
		AuditStore: contracts.OwnerAuditStore{Endpoint: l.audit.Endpoint, Roots: [][]byte{f.NativeProviders.Root}, Region: l.audit.Region, Bucket: l.audit.Bucket},
		KeyService: contracts.FederationKeyService{Endpoint: f.NativeProviders.KMS, Roots: [][]byte{f.NativeProviders.Root}, AuditMount: p.transit, AuditKey: "records", PKIMount: p.mount, ClientRole: "connector-client", ServerRole: "connector-server"}}
	backing, e := json.Marshal(l.backing)
	if e != nil {
		t.Fatal(e)
	}
	c.Connector = &contracts.FederationConnector{Backing: backing}
	deployment, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	keys, _ := json.Marshal(contracts.FederationAuditKeys{Format: contracts.FederationAuditKeysFormat, InstallationID: installation, RootID: root, InputVersion: "connector-mac-v1", InputKey: bytes.Repeat([]byte{31}, 32), AccountVersion: l.backing.AccountVersion, AccountKey: bytes.Repeat([]byte{32}, 32)})
	storage, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: l.audit.AccessKey, SecretAccessKey: l.audit.SecretKey})
	secret := map[string][]byte{"federation-audit-keys.json": keys, "audit-storage.json": storage, "audit-wrap.token": []byte(p.wrap), "audit-unwrap.token": []byte(p.unw), "connector-client-sign.token": []byte(p.client), "connector-server-sign.token": []byte(p.server), "tls.crt": h.certificate, "tls.key": h.key}
	for purpose, credential := range sql {
		if !strings.HasPrefix(purpose, "connector-cleanup") && !strings.HasPrefix(purpose, "connector-verifier") && !strings.HasPrefix(purpose, "connector-finalizer") {
			secret["sql-federation-"+purpose+".json"], _ = json.Marshal(credential)
		}
	}
	if _, e = h.api.CoreV1().ConfigMaps(h.namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "federation-inputs"}, Data: map[string]string{"federation.json": string(deployment)}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = h.api.CoreV1().Secrets(h.namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "federation-credentials"}, Data: secret}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = h.api.CoreV1().ServiceAccounts(h.namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "federation"}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	items := []core.KeyToPath{}
	for name := range secret {
		items = append(items, core.KeyToPath{Key: name, Path: name})
	}
	projection := []core.VolumeProjection{
		{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: "federation-inputs"}, Items: []core.KeyToPath{{Key: "federation.json", Path: "federation.json"}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: "federation-credentials"}, Items: items, Optional: ptr.To(false)}},
	}
	labels := map[string]string{"app": "federation"}
	spec := productPodSpec("federation", f.WorkerImage, []string{"/asservat", "hub-federation"}, contracts.FederationDeploymentRoot, projection, nil)
	if _, e = h.api.AppsV1().Deployments(h.namespace).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "federation"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: spec}}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	for end := time.Now().Add(2 * time.Minute); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		list, e := h.api.CoreV1().Pods(h.namespace).List(ctx, meta.ListOptions{LabelSelector: "app=federation"})
		if e != nil {
			t.Fatal(e)
		}
		for _, p := range list.Items {
			for _, s := range p.Status.ContainerStatuses {
				if s.RestartCount != 0 || s.State.Terminated != nil {
					h.logs(t, ctx)
					t.Fatal("federation process failed at startup")
				}
				if s.Ready && s.State.Running != nil && time.Since(s.State.Running.StartedAt.Time) > 3*time.Second {
					return // past startup composition, listening
				}
			}
		}
	}
	h.logs(t, ctx)
	t.Fatal("federation process not running")
}

func (h *federationHub) logs(t *testing.T, ctx context.Context) {
	t.Helper()
	list, e := h.api.CoreV1().Pods(h.namespace).List(ctx, meta.ListOptions{LabelSelector: "app=federation"})
	if e != nil || len(list.Items) == 0 {
		return
	}
	for _, previous := range []bool{false, true} {
		stream, e := h.api.CoreV1().Pods(h.namespace).GetLogs(list.Items[0].Name, &core.PodLogOptions{Previous: previous, LimitBytes: ptr.To(int64(8 << 10))}).Stream(ctx)
		if e != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(stream, 8<<10))
		stream.Close()
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "service stopped") || strings.HasPrefix(line, "federation") {
				t.Log("federation:", line)
			}
		}
	}
}
