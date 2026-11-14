package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// Static upstream choices are prepared before the unified runner. No generated
// installation ID, source receipt or runtime authority is fabricated here.
type installerContinuationFixture struct {
	providers                                                     *initialRuntimeNativeProviders
	document                                                      []byte
	identity                                                      *installedIdentity
	issuer, origin, consoleSecret, evidenceBucket, keyServiceHost string
}

func prepareInstallerContinuationNative(t *testing.T, ctx context.Context, api kubernetes.Interface, f fixture, desired contracts.InitialBootstrap) *installerContinuationFixture {
	t.Helper()
	namespace := desired.BootstrapNamespace
	providers := initialRuntimeProviderPrerequisites(t, ctx, api, f, desired, desired.Kubernetes, namespace)
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") != "1" {
		installerContinuationRBAC(t, ctx, api, namespace, desired.Name+"-bootstrap-runner")
	}
	installShippedPermissionCRDs(t, ctx, api)
	var roots bytes.Buffer
	for _, der := range providers.issuerRoots {
		_ = pem.Encode(&roots, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	// ADR-193 step 5: the regional cluster dials the federation's pinned node
	// port on the hub node (both owned clusters share one network).
	federationEndpoint := "https://" + net.JoinHostPort(nodeInternalIP(t, ctx, api, f.Clusters[0].NodeUID), "31446")
	keyServiceHost := nodeInternalIP(t, ctx, api, f.Clusters[0].NodeUID)
	// ADR-196 decision 7: the hub's evidence bucket for regional executors,
	// beside the audit bucket on the same owned store.
	evidenceBucket := desired.AuditStore.Bucket + "-evidence"
	installerEvidenceBucket(t, ctx, providers, evidenceBucket)
	var storeRoots bytes.Buffer
	for _, der := range desired.AuditStore.Roots {
		_ = pem.Encode(&storeRoots, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	// ADR-193 operator prerequisite: the connector PKI mount and its root.
	connectorPKI := "connector-pki-" + namespace
	providers.admin(t, ctx, http.MethodPost, "sys/mounts/"+connectorPKI, map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "2h"}}, http.StatusNoContent)
	var generated struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if json.Unmarshal(providers.admin(t, ctx, http.MethodPost, connectorPKI+"/root/generate/internal", map[string]any{"common_name": "synthetic-connector-root", "ttl": "2h", "key_type": "ec", "key_bits": 256}, http.StatusOK), &generated) != nil || generated.Data.Certificate == "" {
		t.Fatal("connector PKI root")
	}
	connectorRoots := generated.Data.Certificate
	// ADR-194 operator prerequisites: the public Transit mount and the worker
	// PKI mount with its root; the artifact creates the keys and the role.
	publicTransit, workerPKI := "public-transit-"+namespace, "worker-pki-"+namespace
	providers.admin(t, ctx, http.MethodPost, "sys/mounts/"+publicTransit, map[string]any{"type": "transit"}, http.StatusNoContent)
	providers.admin(t, ctx, http.MethodPost, "sys/mounts/"+workerPKI, map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "2h"}}, http.StatusNoContent)
	providers.admin(t, ctx, http.MethodPost, workerPKI+"/root/generate/internal", map[string]any{"common_name": "synthetic-worker-root", "ttl": "2h", "key_type": "ec", "key_bits": 256}, http.StatusOK)
	fleetKV := "fleet-kv-" + namespace
	providers.admin(t, ctx, http.MethodPost, "sys/mounts/"+fleetKV, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, http.StatusNoContent)
	// The installed journey's owned Keycloak replaces the synthetic issuer,
	// which is never contacted, and adds the MCP client.
	origin, consoleSecret := "https://asservat.synthetic.invalid", "synthetic-client-secret"
	issuer, providerRoots := "https://id.synthetic.invalid/realms/org", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.NativeProviders.Root}))
	clients := []contracts.IdentityClient{{ID: "console", Kind: "human", ClassQualified: true}}
	var identity *installedIdentity
	if f.Identity != nil {
		identity = newInstalledIdentity(t, f, origin, consoleSecret)
		issuer, providerRoots = identity.Issuer, identity.RootPEM
		clients = append(clients, contracts.IdentityClient{ID: "mcp", Kind: "human", ClassQualified: true})
	}
	approvals := installedIdentityApprovals()
	var processors []contracts.ProcessingOrganization
	var eligibleSubjects []contracts.IdentitySubject
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") == "1" {
		// The chart's public list contract represents no selected subjects as
		// an empty array. Keep the declared installer bytes exact in this mode.
		eligibleSubjects = []contracts.IdentitySubject{}
	}
	if installedJourneyFocus() == "privacy-inventory" {
		for _, organization := range reportFixtureProcessors() {
			processors = append(processors, contracts.ProcessingOrganization{ID: organization.ID, Name: organization.Name, Activities: organization.Activities, Regions: organization.Regions})
		}
	}
	capacity := nativeCapacityProfile()
	connector := contracts.InstallerConnectorSettings{Accounts: 4, RecordsPerAccount: 256, RetainedSeconds: 15000, Profiles: 2, SourceTransitions: 64, PurgeLeases: 2, ValidSeconds: 7200,
		Footprint: contracts.InstallerCapacityFootprint{RowBytes: 1 << 20, TransitionWALBytes: 1 << 20}}
	baseline := &contracts.InstallerRetentionBaseline{PurposeRef: "synthetic-baseline",
		Defaults:              contracts.InstallerRetentionDurations{EvidenceSeconds: 86400, CaseMetadataSeconds: 86400, AuditMetadataSeconds: 86400},
		Maxima:                contracts.InstallerRetentionDurations{EvidenceSeconds: 604800, CaseMetadataSeconds: 604800, AuditMetadataSeconds: 604800},
		DeletionBudgetSeconds: 3600}
	maxLifetime, maxLogins, maxSessions, maxLogout := 3600, 8*int(installedFundedRuns()), 8*int(installedFundedRuns()), 8*int(installedFundedRuns())
	var captureHistory *contracts.CaptureHistoryLimits
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") == "1" {
		trial := helmContextTrialProfile(t).Public
		capacity, connector, baseline = trial.Capacity, trial.Federation.Connector, trial.RetentionBaseline
		maxLifetime, maxLogins, maxSessions, maxLogout = trial.MaxLifetimeSeconds, trial.MaxLogins, trial.MaxSessions, trial.MaxLogoutEvents
		captureHistory, processors = trial.CaptureHistory, trial.Processors
	}
	document, _ := json.Marshal(contracts.InstallerContinuation{Format: contracts.InstallerContinuationFormat, Namespace: namespace,
		WorkerProvider:      contracts.InstallerProviderSelection{AuthMount: providers.worker.AuthMount, AuthMountAccessor: providers.worker.AuthMountAccessor},
		OwnerProvider:       contracts.InstallerProviderSelection{AuthMount: providers.owner.AuthMount, AuthMountAccessor: providers.owner.AuthMountAccessor},
		OwnerIssuerRootsPEM: roots.String(), OwnerPKIMount: "owner-pki", OwnerConnections: 4, OwnerConcurrency: 2,
		// ADR-185: synthetic browser identity settings exercise the public sources step.
		Public: &contracts.InstallerPublicSettings{Origin: origin, Issuer: issuer, ClientID: "console",
			MaxLifetimeSeconds: maxLifetime, MaxLogins: maxLogins, MaxSessions: maxSessions, MaxLogoutEvents: maxLogout, Clients: clients,
			EligibleSubjects: eligibleSubjects,
			EligibleGroups:   []string{"synthetic-group", installedUnrelatedGroup}, GroupMaxAgeSeconds: 300, Approvals: approvals,
			// ADR-190: the operator's synthetic capacity profile and release operator.
			Capacity: capacity, CaptureHistory: captureHistory,
			// ADR-210: the synthetic group's console users are the processing
			// operators, so the journey's one user initializes processing.
			ProcessingOperators: []contracts.ProcessingOperator{{ClientID: "console", Issuer: issuer, Kind: "Group", ID: installedIdentityGroup}},
			Processors:          processors,
			// ADR-193: the federation's operator choices.
			Federation: &contracts.InstallerFederationSettings{ConnectorPKIMount: connectorPKI, ConnectorIssuerRootsPEM: connectorRoots,
				Endpoint: federationEndpoint, ServerName: "federation.synthetic.invalid", ServiceType: "NodePort", NodePort: 31446,
				// ADR-196 decision 5: the owner's native port on the same node.
				OwnerAddress: net.JoinHostPort(nodeInternalIP(t, ctx, api, f.Clusters[0].NodeUID), "31447"), OwnerNodePort: 31447,
				// ADR-197: the owner's v2 operation port on the same Service.
				OwnerOperationAddress: net.JoinHostPort(nodeInternalIP(t, ctx, api, f.Clusters[0].NodeUID), "31449"), OwnerOperationNodePort: 31449,
				// ADR-198: the key service on the same node, named by its IP.
				KeyServiceEndpoint: "https://" + net.JoinHostPort(keyServiceHost, "31448"), KeyServiceNodePort: 31448,
				EvidenceStore: &contracts.InstallerEvidenceStore{Endpoint: desired.AuditStore.Endpoint, RootsPEM: storeRoots.String(), Region: desired.AuditStore.Region, Bucket: evidenceBucket},
				Connector:     connector,
				Fleet:         &contracts.InstallerFleetIssuance{ChannelMount: fleetKV, DeliveryProfile: "regional-installer"}},
			// ADR-195: the operator's synthetic baseline retention values.
			RetentionBaseline: baseline,
			// ADR-194: the promoted launch.
			Promotion: &contracts.InstallerOwnerPromotion{BrowserAudience: "asservat-api", ProviderRootsPEM: providerRoots,
				// ADR-202: the public API's NodePort for the installed journey.
				Exposure:     &contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 31450},
				TransitMount: publicTransit, WorkerPKIMount: workerPKI, Version: "native-qualification"}}})
	return &installerContinuationFixture{providers: providers, document: document, identity: identity, issuer: issuer, origin: origin, consoleSecret: consoleSecret, evidenceBucket: evidenceBucket, keyServiceHost: keyServiceHost}
}

// installerContinuationRBAC mirrors the chart's continuation ClusterRole
// (templates/bootstrap-continuation.yaml); check-helm pins the chart side.
func installerContinuationRBAC(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, account string) {
	t.Helper()
	role, err := api.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: namespace + "-continuation"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "create", "update"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"get", "create"}},
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "create", "update"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"evidencestoragepools", "evidencebudgetpolicies"}, Verbs: []string{"get", "list", "create"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"evidencestoragepools"}, Verbs: []string{"update"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"accessbindings", "permissionsources"}, Verbs: []string{"get", "list", "watch", "create"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"accessbindings"}, Verbs: []string{"delete"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"debugpolicies"}, Verbs: []string{"get", "create"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"captureprofiles"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"asservat.io"}, Resources: []string{"evidenceretentionpolicies"}, Verbs: []string{"get", "list", "watch", "create", "update"}},
		{APIGroups: []string{""}, Resources: []string{"namespaces", "pods"}, Verbs: []string{"get", "list"}},
		// ADR-242: the hub-worker's namespace inheritance watch.
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}},
		// ADR-247: the owner's permission workload journal watch.
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"watch"}},
		// ADR-204: the download workers' PriorityClass and the hub-api's Job
		// dispatch and retirement Role in the workers' namespace.
		{APIGroups: []string{"scheduling.k8s.io"}, Resources: []string{"priorityclasses"}, Verbs: []string{"get", "create"}},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"get", "create", "delete"}},
	}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := api.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: role.Name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: role.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: namespace, Name: account}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if keepFailedFixture(t) {
			return
		}
		c, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		if e := api.RbacV1().ClusterRoleBindings().Delete(c, binding.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}}); e != nil {
			t.Error("continuation binding cleanup", e)
		}
		if e := api.RbacV1().ClusterRoles().Delete(c, role.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &role.UID}}); e != nil {
			t.Error("continuation role cleanup", e)
		}
	})
}

// installerOperatorStorage is the operator's own S3 IAM step for one wait: a
// principal confined to the artifact's prefixes, with deletion denied to every
// runtime principal. IAM scoping itself was qualified by the provider-pair run.
// installerEvidenceBucket creates the owned store's synthetic evidence
// bucket with the fixture administrator.
func installerEvidenceBucket(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, bucket string) {
	t.Helper()
	store := s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: aws.String(p.desired.AuditStore.Endpoint), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: p.client, RetryMaxAttempts: 1})
	if _, err := store.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("evidence bucket", err)
	}
}

// installerEvidenceCredential provisions the operator's regional evidence
// identity (ADR-196 decision 7): Write under v1/<cluster>/ only, with the
// bucket's explicit deletion denial, and no read or list.
func installerEvidenceCredential(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, bucket, cluster string) []byte {
	t.Helper()
	var native struct {
		Container string `json:"runtimeProviderPairS3Container"`
	}
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &native) != nil || !strings.HasPrefix(native.Container, "asservat-context-") || !strings.HasSuffix(native.Container, "-s3") {
		clear(raw)
		t.Fatal("owned S3 container identity missing", err)
	}
	clear(raw)
	// One IAM user per workload cluster: s3.configure merges keys and actions
	// into an existing user, which would let one cluster's key write another's.
	key, secret := "regional-evidence-"+cluster[:8], "regional-evidence-secret-"+cluster[:8]
	shell := "s3.configure -user=administrator -access_key=synthetic-only -secret_key=synthetic-only-secret -actions=Admin,Read,Write,List -apply\n" +
		"s3.configure -user=regional-evidence-" + cluster[:8] + " -access_key=" + key + " -secret_key=" + secret + " -actions=Write:" + bucket + "/v1/" + cluster + "/* -apply\n"
	command, commandDone := installedBoundedCommand(ctx, installedDockerTimeout, "docker", "exec", "-i", native.Container, "/usr/bin/weed", "shell", "-master=localhost:9333", "-filer=localhost:8888")
	defer commandDone()
	command.Stdin = strings.NewReader(shell)
	if output, e := command.CombinedOutput(); e != nil {
		clear(output)
		t.Fatal("owned exact IAM provisioning command unavailable", e)
	}
	policy := installerEvidenceBucketPolicy(bucket)
	installerMergeBucketPolicy(t, ctx, p, bucket, []byte(policy))
	out, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: key, SecretAccessKey: secret})
	return out
}

// installerAuditActions grants read and write under each audit prefix.
func installerAuditActions(p *initialRuntimeNativeProviders, prefixes []string) []string {
	var actions []string
	for _, prefix := range prefixes {
		actions = append(actions, "Read:"+p.desired.AuditStore.Bucket+"/"+prefix+"*", "Write:"+p.desired.AuditStore.Bucket+"/"+prefix+"*")
	}
	return actions
}

func installerOperatorStorage(t *testing.T, ctx context.Context, p *initialRuntimeNativeProviders, user string, actions, users []string) []byte {
	t.Helper()
	var native struct {
		Container string `json:"runtimeProviderPairS3Container"`
	}
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &native) != nil || !strings.HasPrefix(native.Container, "asservat-context-") || !strings.HasSuffix(native.Container, "-s3") {
		clear(raw)
		t.Fatal("owned S3 container identity missing", err)
	}
	clear(raw)
	return installerOwnedOperatorStorage(t, ctx, p, native.Container, user, actions, users)
}

func installerContinuationRunning(t *testing.T, ctx context.Context, api kubernetes.Interface, d *apps.Deployment, image string) {
	t.Helper()
	selector := meta.FormatLabelSelector(d.Spec.Selector)
	limit, stop := context.WithTimeout(ctx, 90*time.Second)
	defer stop()
	for {
		list, err := api.CoreV1().Pods(d.Namespace).List(limit, meta.ListOptions{LabelSelector: selector, Limit: 3})
		if err == nil && len(list.Items) == 1 && len(list.Items[0].Status.ContainerStatuses) > 0 {
			status := list.Items[0].Status.ContainerStatuses[0]
			if status.State.Terminated != nil || status.RestartCount != 0 {
				// Product runtimes print fixed stop messages only; bounded output.
				logs, _ := api.CoreV1().Pods(d.Namespace).GetLogs(list.Items[0].Name, &core.PodLogOptions{Previous: status.State.Terminated == nil, LimitBytes: ptr.To(int64(8192))}).DoRaw(limit)
				t.Fatal("runtime process exited", d.Name, status.State.Terminated, status.RestartCount, string(logs))
			}
			digest := strings.Split(image, "@sha256:")
			if status.State.Running != nil && len(digest) == 2 && strings.HasSuffix(status.ImageID, "sha256:"+digest[1]) {
				return
			}
		}
		select {
		case <-limit.Done():
			t.Fatal("runtime process not running", d.Name)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Cleanup uses the original accepted installer actor for guarded deletion.
// Only after the journey ends does the owned fixture grant that actor DELETE
// for these two exact Deployment names. This is not installer/runtime RBAC.
// Reads use the fixture administrator; the guard and normal foreground GC stay
// active. A retained failed fixture must remain intact for diagnosis.
func installerContinuationLaunchedCleanup(t *testing.T, admin, actor kubernetes.Interface, desired contracts.InitialBootstrap, prefix string) {
	t.Helper()
	if keepFailedFixture(t) {
		return
	}
	ctx, end := context.WithTimeout(context.Background(), 90*time.Second)
	defer end()
	names := []string{prefix + "-owner", prefix + "-worker"}
	role, err := admin.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{
		ObjectMeta: meta.ObjectMeta{Name: prefix + "-fixture-cleanup"},
		Rules:      []rbac.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: names, Verbs: []string{"delete"}}},
	}, meta.CreateOptions{})
	if err != nil {
		t.Error("owned cleanup role", err)
		return
	}
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := admin.RbacV1().ClusterRoles().Delete(clean, role.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &role.UID}}); err != nil {
			t.Error("owned cleanup role retirement", err)
		}
	}()
	binding, err := admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{
		ObjectMeta: meta.ObjectMeta{Name: role.Name},
		RoleRef:    rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: role.Name},
		Subjects:   []rbac.Subject{{Kind: "ServiceAccount", Namespace: desired.BootstrapNamespace, Name: desired.Name + "-bootstrap-runner"}},
	}, meta.CreateOptions{})
	if err != nil {
		t.Error("owned cleanup binding", err)
		return
	}
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := admin.RbacV1().ClusterRoleBindings().Delete(clean, binding.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}}); err != nil {
			t.Error("owned cleanup binding retirement", err)
		}
	}()
	for _, name := range names {
		d, err := admin.AppsV1().Deployments(desired.TargetNamespace).Get(ctx, name, meta.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			t.Error("owned cleanup deployment read", err)
			return
		}
		providerWorkerNativeCleanupAs(t, admin, actor, d)
	}
}

func installerContinuationLogs(t *testing.T, api kubernetes.Interface, pod *core.Pod) {
	if !t.Failed() {
		return
	}
	c, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	current, err := api.CoreV1().Pods(pod.Namespace).Get(c, pod.Name, meta.GetOptions{})
	if err != nil || current.UID != pod.UID {
		return
	}
	for _, name := range []string{"produce", "schema", "prepare", "retire", "continue"} {
		// Only fixed product errors are emitted; never projected file contents.
		logs, e := api.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &core.PodLogOptions{Container: name, LimitBytes: ptr.To(int64(65536))}).DoRaw(c)
		if e == nil {
			t.Log("continuation", pod.UID, name, string(logs))
		}
	}
}

// Install the legacy permission subset, or the entire canonical chart CRD
// bundle for the actual Helm operator flow, and wait for every entry to be
// established before the runner starts with --skip-crds.
func installShippedPermissionCRDs(t *testing.T, ctx context.Context, api kubernetes.Interface) {
	t.Helper()
	client := api.CoreV1().RESTClient()
	files := []string{"accessbindings.yaml", "permissionsources.yaml", "evidencestoragepools.yaml", "evidencebudgetpolicies.yaml", "evidenceretentionpolicies.yaml", "debugpolicies.yaml"}
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") == "1" {
		// Match the guide's full canonical operator prerequisite, once, before
		// Helm runs with --skip-crds. The inventory remains on this real API.
		entries, err := os.ReadDir("../../charts/asservat/crds")
		if err != nil {
			t.Fatal("shipped chart CRD bundle", err)
		}
		files = nil
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
				files = append(files, entry.Name())
			}
		}
	}
	for _, file := range files {
		data, err := os.ReadFile("../../charts/asservat/crds/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var crd struct {
			Metadata struct{ Name string } `json:"metadata"`
		}
		if json.Unmarshal(data, &crd) != nil || crd.Metadata.Name == "" {
			t.Fatal("invalid shipped CRD", file)
		}
		if err = client.Post().AbsPath("/apis/apiextensions.k8s.io/v1/customresourcedefinitions").Body(data).Do(ctx).Error(); err != nil {
			t.Fatal("shipped CRD create", file, err)
		}
		t.Cleanup(func() {
			if keepFailedFixture(t) {
				return
			}
			c, end := context.WithTimeout(context.Background(), 10*time.Second)
			defer end()
			_ = client.Delete().AbsPath("/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + crd.Metadata.Name).Do(c).Error()
		})
		wait, end := context.WithTimeout(ctx, 30*time.Second)
		for established := false; !established; {
			raw, e := client.Get().AbsPath("/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + crd.Metadata.Name).DoRaw(wait)
			var status struct {
				Status struct {
					Conditions []struct{ Type, Status string } `json:"conditions"`
				} `json:"status"`
			}
			if e == nil && json.Unmarshal(raw, &status) == nil {
				for _, c := range status.Status.Conditions {
					established = established || c.Type == "Established" && c.Status == "True"
				}
			}
			if !established {
				select {
				case <-wait.Done():
					end()
					t.Fatal("shipped CRD not established", file)
				case <-time.After(200 * time.Millisecond):
				}
			}
		}
		end()
	}
}

// nativeCapacityProfile is the operator's synthetic capacity profile; its
// footprints and sizes mirror the capacity SQL fixture (ADR-190). Processing
// coverage (ADR-146) requires a capture's deletion date (retention plus the
// deletion budget, about 4200 s here) before the processing root's current
// end, which root renewal sets AdmissionSeconds ahead, so the profile uses the
// one-day maximum (local hold 12). Each renewal also spends one lifetime
// processing root transition and one configuration transition; 8 and 100 with
// 60 s renewals expired the root nine minutes after install (local hold 10).
// Every MCP call, including status polls, charges one normal-lane record to the
// same Keycloak MCP principal until its 10000 s retention; the second workload
// cluster's short journey runs as that principal after the full journey, so
// the normal lane holds 128 records rather than 64.
func nativeCapacityProfile() *contracts.InstallerCapacitySettings {
	f := func(row, wal int64) contracts.InstallerCapacityFootprint {
		return contracts.InstallerCapacityFootprint{RowBytes: row, TransitionWALBytes: wal}
	}
	lane := func(accounts, records int64) contracts.InstallerCapacityLane {
		return contracts.InstallerCapacityLane{Accounts: accounts, Records: records, RetainedSeconds: 10000}
	}
	// Several focuses on one installation each get their own funding: the
	// per-focus records and normal-lane records add up (installedEachFocus).
	var records, normal int64
	installedEachFocus(func() {
		r, n := installedFocusCapacityRecords()
		records, normal = records+r, normal+n
	})
	poolSpec, policySpec := installerDeclaredCapacitySpecs()
	profile := &contracts.InstallerCapacitySettings{Pool: "capacity", Policy: "applications", PoolSpec: poolSpec, PolicySpec: policySpec, NamespaceKeys: []string{"team"}, Accounts: 16, Records: records, AdmissionSeconds: 86400,
		Lanes:               contracts.InstallerCapacityLanes{CaptureRetainedSeconds: 10000, Normal: lane(4, normal*installedKeptRuns()), Resolution: lane(4, 8*installedFundedRuns()), Processing: lane(2, 16)},
		StopRetainedSeconds: 10000,
		Backup:              contracts.InstallerCapacityBackup{HorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 2, WALCopies: 3},
		Footprints:          contracts.InstallerCapacityFootprints{Capture: f(128<<10, 256<<10), Operation: f(128<<10, 256<<10), Processing: f(128<<10, 256<<10), Native: f(64<<10, 128<<10), Stop: f(128<<10, 256<<10), ProcessingState: f(16<<10, 64<<10)},
		PurgeLeases:         4,
		Processing:          contracts.InstallerCapacityProcessing{MaxRules: 2, MaxRootTransitions: 512},
		Metadata:            contracts.InstallerCapacityMetadata{FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, ConfigurationTransitions: 4096},
		Envelope:            contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1 << 50}, SQLBytes: 1 << 50, BackupBytes: 1 << 50, WALBytes: 1 << 50, KeyAttempts: 1 << 50},
		Backends:            []contracts.InstallerCapacityBackend{{StorageProfile: "dedicated", Usable: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
	if installedJourneyFocus() == "share-retirement" {
		// Selected before installation/admission: exercise original finite
		// bounds, never rewrite a running operation to make cleanup due.
		profile.Backup.HorizonSeconds = 2
		// The ten-second cohort did not qualify healthy native retirement.
		// Select thirty seconds before installation for serial native checks
		// and cold provider work; retention and proof requirements stay fixed.
		// This moves original purge 60s earlier and live removal 20s earlier.
		profile.Backup.CleanupBudgetSeconds, profile.Backup.ProofWindowSeconds = 30, 10
		profile.Lanes.Normal.RetainedSeconds = 240
		profile.Lanes.Resolution.RetainedSeconds = 240
		profile.Lanes.CaptureRetainedSeconds = 300
	}
	return profile
}

// installedFocusCapacityRecords is the current focus' records per account
// and normal-lane records (before the keep run's multiplier).
func installedFocusCapacityRecords() (records, normal int64) {
	// The manual profile journey reserves 48 evidence objects for four captures
	// plus history, deriving 12 protocol records. Qualify those records upfront;
	// its single pprof summary still charges ten conservative read-work units.
	records = int64(8)
	if installedLogsFocus() {
		records = installedLogsQueryUnits * installedKeptRuns() // one focus run; a keep run funds its reruns
	}
	if installedJourneyFocus() == "manual-raw" {
		// Two summaries (4 units) plus two independently paid packet queries
		// (8 units) fit an originally accepted sixteen-record backing.
		records = 16
	}
	if installedJourneyFocus() == "manual-profile" {
		records = 12
	}
	if installedJourneyFocus() == "profile-comparison" {
		records = installedProfileComparisonQueries * query.ProfileComparisonQueryUnits
	}
	// The saved-syscall journey performs five distinct paid queries, including
	// the changed-filter cursor refusal. Retiring a worker never refunds a
	// query unit. Arguments additionally funds two four-unit raw queries; the
	// metadata-only focus retains five two-unit source reads.
	if installedJourneyFocus() == "manual-syscall" || installedJourneyFocus() == "manual-arguments" {
		records = installedSyscallProjectionQueries * query.SyscallProjectionQueryUnits
		if installedJourneyFocus() == "manual-arguments" {
			records = installedArgumentQueryUnits
		}
	}
	// Every live list/open/read/update/close is one audited normal-lane
	// operation for the same human; six episodes poll roughly once a second.
	normal = 128
	if installedJourneyFocus() == "live-observation" {
		normal = 512
	}
	return records, normal
}

// installedProcessDiagnostics logs each named Deployment's Pod restarts, last
// termination and log tails. The products print fixed step names and error
// classes only, never projected file contents.
func installedProcessDiagnostics(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string, deployments ...string) {
	t.Helper()
	c, end := context.WithTimeout(ctx, 20*time.Second)
	defer end()
	for _, name := range deployments {
		d, e := api.AppsV1().Deployments(namespace).Get(c, name, meta.GetOptions{})
		if e != nil {
			t.Log("diagnostics: deployment", name, e)
			continue
		}
		installedPodDiagnostics(t, c, api, namespace, name, meta.FormatLabelSelector(d.Spec.Selector))
	}
}

// installedPodDiagnostics logs the status and recent logs of every Pod that
// selector matches in namespace (an empty selector matches all of them).
func installedPodDiagnostics(t *testing.T, c context.Context, api kubernetes.Interface, namespace, name, selector string) {
	t.Helper()
	pods, e := api.CoreV1().Pods(namespace).List(c, meta.ListOptions{LabelSelector: selector})
	if e != nil {
		t.Log("diagnostics: pods", name, e)
		return
	}
	for _, pod := range pods.Items {
		t.Logf("diagnostics: %s pod %s phase %s", name, pod.Name, pod.Status.Phase)
		for _, s := range pod.Status.ContainerStatuses {
			reason, exit := "", int32(0)
			if x := s.LastTerminationState.Terminated; x != nil {
				reason, exit = x.Reason, x.ExitCode
			}
			currentTermination := "unobserved"
			if x := s.State.Terminated; x != nil {
				currentTermination = fmt.Sprintf("reason=%q exit=%d", x.Reason, x.ExitCode)
			}
			t.Logf("diagnostics: %s pod %s container %s ready %v restarts %d last %q exit %d current termination %s", name, pod.Name, s.Name, s.Ready, s.RestartCount, reason, exit, currentTermination)
			for _, previous := range []bool{true, false} {
				logs, e := api.CoreV1().Pods(namespace).GetLogs(pod.Name, &core.PodLogOptions{Container: s.Name, Previous: previous, Timestamps: true, TailLines: ptr.To(int64(400)), LimitBytes: ptr.To(int64(65536))}).DoRaw(c)
				if e == nil && len(logs) > 0 {
					t.Logf("diagnostics: %s previous=%v log:\n%s", pod.Name, previous, logs)
				}
			}
		}
	}
}

// syntheticServingPair is a synthetic CA and one server leaf for serverName.
func syntheticServingPair(t *testing.T, serverName string) (caDER, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-serving-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err = x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{serverName}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(serverName); ip != nil {
		leaf.DNSNames, leaf.IPAddresses = nil, []net.IP{ip}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return caDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// installerPromotedOwnerReady waits for the owner Pod's Ready condition and
// requires that its process never restarted.
func installerPromotedOwnerReady(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, name, image string) {
	t.Helper()
	d, err := api.AppsV1().Deployments(namespace).Get(ctx, name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	installerContinuationRunning(t, ctx, api, d, image)
	for until := time.Now().Add(2 * time.Minute); ; {
		list, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: meta.FormatLabelSelector(d.Spec.Selector), Limit: 3})
		if err == nil && len(list.Items) == 1 && len(list.Items[0].Status.ContainerStatuses) > 0 && list.Items[0].Status.ContainerStatuses[0].RestartCount == 0 {
			for _, c := range list.Items[0].Status.Conditions {
				if c.Type == core.PodReady && c.Status == core.ConditionTrue {
					return
				}
			}
		}
		if time.Now().After(until) {
			installedProcessDiagnostics(t, ctx, api, namespace, name)
			t.Fatal("promoted owner not Ready", err)
		}
		time.Sleep(installedPoll)
	}
}

// installerHubRetentionReady waits until the hub retention source is Ready
// at least at sequence with exactly the baseline policy accepted, read like
// the hub-api: through the hub projection's retention-read login (the ledger
// refuses superusers). It returns the sequence and epoch.
func installerHubRetentionReady(t *testing.T, ctx context.Context, api kubernetes.Interface, admin *pgxpool.Pool, namespace, installation, root, cluster string, sequence int64) (int64, string) {
	t.Helper()
	return installerHubRetentionReadyEpoch(t, ctx, api, admin, namespace, installation, root, cluster, sequence, "")
}

// installerHubRetentionReadyEpoch additionally waits for an epoch other than
// previous, when previous is set.
func installerHubRetentionReadyEpoch(t *testing.T, ctx context.Context, api kubernetes.Interface, admin *pgxpool.Pool, namespace, installation, root, cluster string, least int64, previous string) (int64, string) {
	t.Helper()
	return installerHubRetentionReadyPolicyCount(t, ctx, api, admin, namespace, installation, root, cluster, least, previous, 1)
}

func installerHubRetentionReadyPolicyCount(t *testing.T, ctx context.Context, api kubernetes.Interface, admin *pgxpool.Pool, namespace, installation, root, cluster string, least int64, previous string, policies int) (int64, string) {
	t.Helper()
	projection, err := api.CoreV1().Secrets(namespace).Get(ctx, contracts.PublicRuntimeProjectionName(installation), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var login contracts.OwnerSQLCredential
	if json.Unmarshal(projection.Data["sql-public-hub-runtime.json"], &login) != nil || login.Username == "" {
		t.Fatal("retention-read login missing")
	}
	// The product ledger requires verified TLS, as the step-5 issuance logins.
	c := admin.Config().ConnConfig
	address, tlsConfig := pgTLSBridge(t, net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))))
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword(login.Username, login.Password), Host: address, Path: "/" + c.Database, RawQuery: "sslmode=disable"}
	pc, err := pgxpool.ParseConfig(dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.TLSConfig, pc.ConnConfig.Fallbacks, pc.MaxConns = tlsConfig, nil, 1
	reader, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	sources, err := postgres.NewRetentionSources(ctx, reader, root)
	if err != nil {
		t.Fatal("retention-read ledger", err)
	}
	for until := time.Now().Add(5 * time.Minute); ; {
		var namespaceUID string
		var digest []byte
		var sequence int64
		e := admin.QueryRow(ctx, `SELECT namespace_uid, protection_digest, sequence FROM retention_source WHERE root_id=$1 AND cluster_id=$2 AND hub`, root, cluster).Scan(&namespaceUID, &digest, &sequence)
		if e == nil && len(digest) == 32 && sequence >= least {
			ref := privacy.PolicySourceRef{ClusterID: cluster, ControlNamespaceUID: namespaceUID, Hub: true}
			copy(ref.ProtectionDigest[:], digest)
			if a, e := sources.AcceptedRetentionSource(ctx, root, ref); e == nil && a.Ready && a.Acceptance.Generation == sequence && len(a.Snapshot.Policies) == policies && a.Epoch != previous {
				t.Logf("hub retention source Ready at sequence %d with %d policies", sequence, policies)
				return sequence, a.Epoch
			}
		}
		if ctx.Err() != nil || time.Now().After(until) {
			t.Fatal("hub retention source not Ready", e, sequence)
		}
		time.Sleep(installedPoll)
	}
}

// installerWorkerSelector is the hub-worker Deployment's Pod selector.
func installerWorkerSelector(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, name string) string {
	t.Helper()
	d, err := api.AppsV1().Deployments(namespace).Get(ctx, name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return meta.FormatLabelSelector(d.Spec.Selector)
}

// installerCrashHubWorker stops the hub-worker container on its own kind node.
// The namespace guard rightly refuses API Pod deletion to everyone but the
// controllers and kubelet; the kubelet restarts the container as it would a
// crashed process. Only an owned harness node (asservat- prefix, matching kind
// cluster label) is touched.
func installerCrashHubWorker(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, deployment string) {
	t.Helper()
	pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: installerWorkerSelector(t, ctx, api, namespace, deployment)})
	if err != nil || len(pods.Items) != 1 || len(pods.Items[0].Status.ContainerStatuses) != 1 {
		t.Fatal("hub-worker Pod", err)
	}
	pod := pods.Items[0]
	node, before := pod.Spec.NodeName, pod.Status.ContainerStatuses[0].RestartCount
	// Startup waits for the kubelet's projection refresh instead of exiting
	// (a fixed 30 s mount wait restarted it in 3 of 5 runs on 2026-10-26).
	if before != 0 {
		installedProcessDiagnostics(t, ctx, api, namespace, deployment)
		t.Fatal("hub-worker restarted before the forced crash", before)
	}
	cluster := strings.TrimSuffix(strings.TrimSuffix(node, "-control-plane"), "-worker")
	if !strings.HasPrefix(node, "asservat-") || cluster == node {
		t.Fatal("hub-worker not on an owned harness node", node)
	}
	label, err := installedOutput(ctx, installedDockerTimeout, "docker", "inspect", "--format", "{{ index .Config.Labels \"io.x-k8s.kind.cluster\" }}", node)
	if err != nil || strings.TrimSpace(string(label)) != cluster {
		t.Fatal("node container not owned by this harness cluster", err)
	}
	ids, err := installedOutput(ctx, installedDockerTimeout, "docker", "exec", node, "crictl", "ps", "-q", "--label", "io.kubernetes.pod.uid="+string(pod.UID), "--name", pod.Status.ContainerStatuses[0].Name)
	id := strings.TrimSpace(string(ids))
	if err != nil || id == "" || strings.Contains(id, "\n") {
		t.Fatal("hub-worker container", err)
	}
	if err = installedRun(ctx, installedDockerTimeout, "docker", "exec", node, "crictl", "stop", id); err != nil {
		t.Fatal("hub-worker container stop", err)
	}
	for until := time.Now().Add(2 * time.Minute); ; {
		p, e := api.CoreV1().Pods(namespace).Get(ctx, pod.Name, meta.GetOptions{})
		if e == nil && len(p.Status.ContainerStatuses) == 1 && p.Status.ContainerStatuses[0].RestartCount > before && p.Status.ContainerStatuses[0].State.Running != nil {
			return
		}
		if time.Now().After(until) {
			t.Fatal("hub-worker not restarted", e)
		}
		time.Sleep(installedPoll)
	}
}

// installerKeyServiceInstalled checks the ADR-198 key service: it is
// available, accepted its configuration in SQL, serves TLS under the offer's
// roots at the offered endpoint and refuses an unknown client chain, and no
// other Pod mounts the root key Secret or the key-service logins.
// installerPublisherInstalled checks the ADR-203 publisher's Deployment is
// available and its process has not restarted: it composed every input,
// logged in to OpenBao and read the cluster catalog. Publishing a capture is
// the journey's check.
func installerPublisherInstalled(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, installation string) {
	t.Helper()
	name := contracts.PublisherName(installation)
	d, err := api.AppsV1().Deployments(namespace).Get(ctx, name, meta.GetOptions{})
	if err != nil || d.Status.AvailableReplicas != 1 {
		installedProcessDiagnostics(t, ctx, api, namespace, name)
		t.Fatal("publisher not available", err)
	}
	pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: meta.FormatLabelSelector(d.Spec.Selector)})
	if err != nil || len(pods.Items) != 1 || len(pods.Items[0].Status.ContainerStatuses) != 1 || pods.Items[0].Status.ContainerStatuses[0].RestartCount != 0 {
		installedProcessDiagnostics(t, ctx, api, namespace, name)
		t.Fatal("publisher restarted or is not alone", err)
	}
	t.Log("publisher available without restarts")
}

func installerKeyServiceInstalled(t *testing.T, ctx context.Context, api kubernetes.Interface, admin *pgxpool.Pool, namespace, installation string, offer contracts.RegionalOffer, servingCA []byte) {
	t.Helper()
	k := offer.KeyService
	if k == nil || len(k.Roots) != 1 || !bytes.Equal(k.Roots[0], servingCA) || k.KeyID == "" {
		t.Fatal("offer names no key service")
	}
	name := contracts.KeyServiceName(installation)
	if d, e := api.AppsV1().Deployments(namespace).Get(ctx, name, meta.GetOptions{}); e != nil || d.Status.AvailableReplicas != 1 {
		installedProcessDiagnostics(t, ctx, api, namespace, name)
		t.Fatal("key service not available", e)
	}
	var revision int64
	if e := admin.QueryRow(ctx, `SELECT (convert_from(snapshot_json, 'UTF8')::jsonb->'Revision'->>'Generation')::bigint FROM local_key_configuration WHERE installation_id=$1 AND purpose='artifact' AND key_id=$2`, installation, k.KeyID).Scan(&revision); e != nil || revision != 1 {
		t.Fatal("key configuration not accepted in SQL", revision, e)
	}
	t.Log("key service available; its configuration accepted at revision 1")
	u, err := url.Parse(k.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	ca, err := x509.ParseCertificate(servingCA)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(ca)
	// A client chain from an unknown CA, sent regardless of the server's
	// acceptable CAs: the dial verifies the server under the offered roots,
	// and TLS 1.3 reports the server's refusal as a remote alert on the first
	// read.
	_, certPEM, keyPEM := syntheticServingPair(t, "unknown-client.synthetic.invalid")
	unknown, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: u.Hostname(), RootCAs: roots, MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &unknown, nil }}}
	for until := time.Now().Add(time.Minute); ; {
		conn, e := dialer.DialContext(ctx, "tcp", u.Host)
		if e == nil {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, e = conn.Read(make([]byte, 1))
			conn.Close()
			if e != nil && strings.Contains(e.Error(), "remote error: tls: ") {
				t.Log("key service serves the offered roots and refuses an unknown client chain:", e)
				break
			}
		}
		if time.Now().After(until) {
			t.Fatal("key service endpoint not refusing an unknown client as expected", e)
		}
		time.Sleep(installedPoll)
	}
	pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	private := map[string]bool{contracts.LocalArtifactKeySecretName(installation): true, contracts.KeyServiceRuntimeProjectionName(installation): true, contracts.KeyServiceServingSecretName(installation): true}
	for _, p := range pods.Items {
		for _, v := range p.Spec.Volumes {
			var names []string
			if v.Secret != nil {
				names = append(names, v.Secret.SecretName)
			}
			if v.Projected != nil {
				for _, s := range v.Projected.Sources {
					if s.Secret != nil {
						names = append(names, s.Secret.Name)
					}
				}
			}
			for _, n := range names {
				if n == contracts.LocalArtifactKeySecretName(installation) || private[n] && p.Labels["asservat.io/private-role"] != "key-service" {
					t.Fatal("key material mounted into pod", p.Name, n)
				}
			}
		}
	}
	t.Log("no Pod mounts the root key; only the key service mounts its logins")
}

// installerOwnerExposed completes a TLS handshake with the owner's exposed
// native port under its bootstrap server name, from outside the cluster: the
// L4 Service reaches the owner and the server-name router hands the
// connection to the observation server (ADR-196 decision 5).
func installerOwnerExposed(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, installation string, offer contracts.RegionalOffer) {
	t.Helper()
	o := offer.Owners
	if o == nil || o.Address == "" {
		t.Fatal("offer names no owner address")
	}
	c := o.Configuration
	pool := fleetvalue.OwnerPool{InstallationID: c.InstallationID, ClusterID: c.ClusterID, IssuerEpoch: c.IssuerEpoch, Namespace: c.Namespace.Name, NamespaceUID: c.Namespace.UID,
		Service: c.Service.Name, ServiceUID: c.Service.UID, Deployment: c.Deployment.Name, DeploymentUID: c.Deployment.UID, ServiceAccount: c.ServiceAccount.Name, AccountUID: c.ServiceAccount.UID,
		Port: c.Port, NativePort: c.NativePort, NativeBootstrap: c.NativeBootstrap, NativeCandidateLimit: c.NativeCandidateLimit, OperationPort: c.OperationPort}
	name, err := mtls.OwnerBootstrapServerName(pool)
	if err != nil {
		t.Fatal("owner bootstrap name", err)
	}
	roots := x509.NewCertPool()
	for _, der := range c.IssuerRoots {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		roots.AddCert(cert)
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}}
	for until := time.Now().Add(time.Minute); ; {
		conn, e := dialer.DialContext(ctx, "tcp", o.Address)
		if e == nil {
			conn.Close()
			t.Log("owner native port reachable from outside under its bootstrap name")
			return
		}
		if time.Now().After(until) {
			installedProcessDiagnostics(t, ctx, api, namespace, "asservat-"+strings.ReplaceAll(installation, "-", "")+"-owner")
			t.Fatal("owner native port not reachable", e)
		}
		time.Sleep(installedPoll)
	}
}

// installedPostgresRestart restarts the owned PostgreSQL container (data on
// its volume, same address) and waits until the hub's own observation has
// re-activated the trust root: no fixture SQL writes activation.
func installedPostgresRestart(t *testing.T, ctx context.Context, admin *pgxpool.Pool, container, installation string) {
	t.Helper()
	ip := func() string {
		out, err := installedOutput(ctx, installedDockerTimeout, "docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container)
		if err != nil {
			t.Fatal("PostgreSQL container address", err)
		}
		return strings.TrimSpace(string(out))
	}
	before := ip()
	if container == "" || !strings.HasPrefix(container, "asservat-") || before == "" {
		t.Fatal("owned PostgreSQL container unknown", container)
	}
	if out, err := installedCombinedOutput(ctx, installedDockerTimeout, "docker", "restart", container); err != nil {
		t.Fatal("PostgreSQL restart", err, string(out))
	}
	if after := ip(); after != before {
		t.Fatal("PostgreSQL address changed on restart", before, after)
	}
	// The fixture's own pooled connections died with the server.
	admin.Reset()
	started := time.Now()
	for until := started.Add(3 * time.Minute); ; time.Sleep(installedPoll) {
		var active bool
		err := admin.QueryRow(ctx, `SELECT NOT recovery_blocked AND NOT suspended AND fresh_until>clock_timestamp() FROM fleet_current_trust WHERE installation_id=$1`, installation).Scan(&active)
		if err == nil && active {
			break
		}
		if time.Now().After(until) {
			t.Fatal("installation did not re-activate after the PostgreSQL restart", err)
		}
	}
	t.Logf("installed journey: PostgreSQL restarted; trust root re-activated after %s", time.Since(started).Round(time.Second))
	// The permission reconciler's epoch fails with the restart and retries
	// after its 30 s SQL controller lease; authority is stale until then.
	for until := time.Now().Add(3 * time.Minute); ; time.Sleep(installedPoll) {
		var current bool
		err := admin.QueryRow(ctx, `SELECT COALESCE(bool_and(observed_at>pg_postmaster_start_time() AND fresh_until>clock_timestamp()),false) FROM permission_stream`).Scan(&current)
		if err == nil && current {
			break
		}
		if time.Now().After(until) {
			t.Fatal("permission stream not current after the PostgreSQL restart", err)
		}
	}
	t.Logf("installed journey: permission stream current again %s after the PostgreSQL restart", time.Since(started).Round(time.Second))
}

// installedHubRestarts returns each running hub container's restart count
// and whether all of them are Ready.
func installedHubContainers(ctx context.Context, api kubernetes.Interface, namespace string) (map[string]int32, bool, error) {
	pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{})
	if err != nil {
		return nil, false, err
	}
	out, ready := map[string]int32{}, true
	for _, pod := range pods.Items {
		if pod.Status.Phase == core.PodSucceeded || pod.Status.Phase == core.PodFailed {
			continue
		}
		for _, c := range pod.Status.ContainerStatuses {
			out[pod.Name+"/"+c.Name] = c.RestartCount
			ready = ready && c.Ready
		}
	}
	return out, ready && len(out) > 0, nil
}

// installedContextStandbyWindow waits until the hub-api container has run for
// 35 s since its last start. A regional connector whose context standby was
// refused at TLS by the replaced process reopens 30 s later (openingRetry), so
// before that the hub has no idle standby to route a preview to. The full
// chain's minutes of discovery cover this; the fast fixture's enrollment
// returns within seconds of the join's hub-api restart.
func installedContextStandbyWindow(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, deployment string) {
	t.Helper()
	d, err := api.AppsV1().Deployments(namespace).Get(ctx, deployment, meta.GetOptions{})
	if err != nil {
		t.Fatal("hub-api deployment", err)
	}
	for until := time.Now().Add(2 * time.Minute); ; time.Sleep(installedPoll) {
		pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: meta.FormatLabelSelector(d.Spec.Selector)})
		var started time.Time
		if err == nil && len(pods.Items) == 1 && len(pods.Items[0].Status.ContainerStatuses) == 1 {
			if r := pods.Items[0].Status.ContainerStatuses[0].State.Running; r != nil && pods.Items[0].Status.ContainerStatuses[0].Ready {
				started = r.StartedAt.Time
			}
		}
		if !started.IsZero() && time.Since(started) >= 35*time.Second {
			t.Logf("hub-api running %s since its last start; the regional context standby had its reopening interval", time.Since(started).Round(time.Second))
			return
		}
		if time.Now().After(until) {
			t.Fatal("hub-api did not stay running for the context standby's reopening interval", err)
		}
	}
}

func installedHubRestarts(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string) map[string]int32 {
	t.Helper()
	before, _, err := installedHubContainers(ctx, api, namespace)
	if err != nil {
		t.Fatal("hub Pods", err)
	}
	return before
}

// installedHubSettled waits until every hub container has been Ready for
// 20 s without another restart, and logs which ones restarted since before.
func installedHubSettled(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string, before map[string]int32) {
	t.Helper()
	var since time.Time
	var last map[string]int32
	start := time.Now()
	for until := start.Add(5 * time.Minute); ; time.Sleep(installedPoll) {
		current, ready, err := installedHubContainers(ctx, api, namespace)
		if err != nil || !ready || !maps.Equal(current, last) {
			since = time.Time{}
		} else if since.IsZero() {
			since = time.Now()
		}
		last = current
		if !since.IsZero() && time.Since(since) >= 20*time.Second {
			var restarted []string
			for name, n := range current {
				if n != before[name] {
					restarted = append(restarted, fmt.Sprintf("%s +%d", name, n-before[name]))
				}
			}
			sort.Strings(restarted)
			t.Logf("installed journey: hub processes settled %s after re-activation (Ready for the last 20 s); restarted: %v", time.Since(start).Round(time.Second), restarted)
			return
		}
		if time.Now().After(until) {
			t.Fatal("hub processes did not settle after the PostgreSQL restart", err)
		}
	}
}

// waitInstalledPublisherSettled waits until the publisher's running container
// started after the cluster catalog's last change, so no catalog restart is
// pending.
func waitInstalledPublisherSettled(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, installation string) {
	t.Helper()
	for until := time.Now().Add(2 * time.Minute); ; time.Sleep(installedPoll) {
		changed := time.Time{}
		if cm, err := api.CoreV1().ConfigMaps(namespace).Get(ctx, contracts.OwnerClusterCatalogName(installation), meta.GetOptions{}); err == nil {
			changed = cm.CreationTimestamp.Time
			for _, m := range cm.ManagedFields {
				if m.Time != nil && m.Time.After(changed) {
					changed = m.Time.Time
				}
			}
		}
		pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{})
		if err == nil && !changed.IsZero() {
			for _, p := range pods.Items {
				if p.DeletionTimestamp != nil || !strings.HasPrefix(p.Name, contracts.PublisherName(installation)+"-") {
					continue
				}
				for _, c := range p.Status.ContainerStatuses {
					if c.Ready && c.State.Running != nil && c.State.Running.StartedAt.After(changed) {
						return
					}
				}
			}
		}
		if time.Now().After(until) {
			// An unchanged-content catalog write restarts nothing.
			t.Log("publisher started before the last catalog write; continuing", changed)
			return
		}
	}
}
