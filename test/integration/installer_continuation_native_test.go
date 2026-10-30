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
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
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
	"k8s.io/client-go/rest"
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
	installerContinuationRBAC(t, ctx, api, namespace, desired.Name+"-bootstrap-runner")
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
	var approvals *contracts.IdentityApprovals
	if installedRecordingFocus() {
		// Real fresh password authentication at the reference provider's LoA1;
		// this fixture does not configure or claim MFA/LoA2.
		approvals = &contracts.IdentityApprovals{RequireRecordingApproval: installedJourneyFocus() != "policy-recording" && installedJourneyFocus() != "ongoing-save", StepUp: &contracts.IdentityStepUp{ACRValues: []string{"1"}, MaxAgeSeconds: 300}}
	}
	document, _ := json.Marshal(contracts.InstallerContinuation{Format: contracts.InstallerContinuationFormat, Namespace: namespace,
		WorkerProvider:      contracts.InstallerProviderSelection{AuthMount: providers.worker.AuthMount, AuthMountAccessor: providers.worker.AuthMountAccessor},
		OwnerProvider:       contracts.InstallerProviderSelection{AuthMount: providers.owner.AuthMount, AuthMountAccessor: providers.owner.AuthMountAccessor},
		OwnerIssuerRootsPEM: roots.String(), OwnerPKIMount: "owner-pki", OwnerConnections: 4, OwnerConcurrency: 2,
		// ADR-185: synthetic browser identity settings exercise the public sources step.
		Public: &contracts.InstallerPublicSettings{Origin: origin, Issuer: issuer, ClientID: "console",
			MaxLifetimeSeconds: 3600, MaxLogins: 8, MaxSessions: 8, MaxLogoutEvents: 8, Clients: clients,
			EligibleGroups: []string{"synthetic-group", installedUnrelatedGroup}, GroupMaxAgeSeconds: 300, Approvals: approvals,
			// ADR-190: the operator's synthetic capacity profile and release operator.
			Capacity: nativeCapacityProfile(),
			// ADR-210: the synthetic group's console users are the processing
			// operators, so the journey's one user initializes processing.
			ProcessingOperators: []contracts.ProcessingOperator{{ClientID: "console", Issuer: issuer, Kind: "Group", ID: installedIdentityGroup}},
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
				Connector: contracts.InstallerConnectorSettings{Accounts: 4, RecordsPerAccount: 256, RetainedSeconds: 15000, Profiles: 2, SourceTransitions: 64, PurgeLeases: 2, ValidSeconds: 7200,
					Footprint: contracts.InstallerCapacityFootprint{RowBytes: 1 << 20, TransitionWALBytes: 1 << 20}}},
			// ADR-195: the operator's synthetic baseline retention values.
			RetentionBaseline: &contracts.InstallerRetentionBaseline{PurposeRef: "synthetic-baseline",
				Defaults:              contracts.InstallerRetentionDurations{EvidenceSeconds: 86400, CaseMetadataSeconds: 86400, AuditMetadataSeconds: 86400},
				Maxima:                contracts.InstallerRetentionDurations{EvidenceSeconds: 604800, CaseMetadataSeconds: 604800, AuditMetadataSeconds: 604800},
				DeletionBudgetSeconds: 3600},
			// ADR-194: the promoted launch.
			Promotion: &contracts.InstallerOwnerPromotion{BrowserAudience: "asservat-api", ProviderRootsPEM: providerRoots,
				// ADR-202: the public API's NodePort for the installed journey.
				Exposure:     &contracts.InstallerPublicExposure{ServiceType: "NodePort", NodePort: 31450},
				TransitMount: publicTransit, WorkerPKIMount: workerPKI, Version: "native-qualification"}}})
	return &installerContinuationFixture{providers: providers, document: document, identity: identity, issuer: issuer, origin: origin, consoleSecret: consoleSecret, evidenceBucket: evidenceBucket, keyServiceHost: keyServiceHost}
}

// Complete the actual five-command runner through both operator provider waits,
// then keep all installed process, SQL, regional and public journey assertions.
func qualifyInstallerContinuationNative(t *testing.T, ctx context.Context, kc *rest.Config, kubeconfig string, api kubernetes.Interface, admin *pgxpool.Pool, f fixture, desired contracts.InitialBootstrap, original contracts.InitialPreparer, unified *installedUnifiedRunner) {
	t.Helper()
	installation, namespace := original.Plan.InstallationID, desired.BootstrapNamespace
	setup := unified.continuation
	providers, identity := setup.providers, setup.identity
	issuer, origin, consoleSecret := setup.issuer, setup.origin, setup.consoleSecret
	evidenceBucket := setup.evidenceBucket
	providers.installation, providers.cluster = installation, original.Plan.ClusterID
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	t.Cleanup(func() { initialRuntimeNativeCleanup(t, api, desired.TargetNamespace, installation, prefix) })
	// Use the original compiled runner actor for guarded operator prerequisites;
	// fixture administration is not added to the product administrator list.
	runnerConfig := installedUnifiedRunnerConfig(kc, desired)
	runnerAPI, err := kubernetes.NewForConfig(runnerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer installerContinuationLaunchedCleanup(t, api, runnerAPI, desired, prefix)
	installNativeCapacityObjects(t, ctx, runnerAPI, desired.TargetNamespace, original.Plan.ClusterID)
	servingCA := installerFederationServingSecret(t, ctx, runnerAPI, desired.TargetNamespace, installation, "federation.synthetic.invalid")
	keyServingCA := installerServingSecret(t, ctx, runnerAPI, desired.TargetNamespace, contracts.KeyServiceServingSecretName(installation), setup.keyServiceHost)
	var publicRoot []byte // DER of the public listener's synthetic CA
	// The interruption/resume qualifies the installer itself; the fast feature
	// fixture continues the original runner through its provider waits.
	pod := unified.pod
	if !installedFastFixture() {
		pod = unified.interruptAndResume(t, ctx, api, kc, kubeconfig, desired, original)
	}
	defer installerContinuationLogs(t, api, pod)

	// The operator's side: own OpenBao administration and scoped storage only.
	work := t.TempDir()
	ca := filepath.Join(work, "provider-ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.NativeProviders.Root}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BAO_ADDR", f.NativeProviders.KMS)
	t.Setenv("BAO_CACERT", ca)
	t.Setenv("BAO_TOKEN", "synthetic-root")
	applied := map[int]bool{}
	var users []string
	limit, stop := context.WithTimeout(ctx, 25*time.Minute)
	defer stop()
	for {
		current, e := api.CoreV1().Pods(namespace).Get(limit, pod.Name, meta.GetOptions{})
		if e != nil || current.UID != pod.UID {
			t.Fatal("continuation Pod lost or replaced", e)
		}
		if current.Status.Phase == core.PodFailed {
			installedProcessDiagnostics(t, ctx, api, desired.TargetNamespace, prefix+"-worker", prefix+"-owner")
			var sequence int64
			var suspended bool
			e := admin.QueryRow(ctx, `SELECT sequence, suspended FROM retention_source WHERE cluster_id=$1 AND hub`, original.Plan.ClusterID).Scan(&sequence, &suspended)
			t.Log("diagnostics: hub retention source", sequence, suspended, e)
			t.Fatal("actual continuation failed")
		}
		if current.Status.Phase == core.PodSucceeded {
			break
		}
		outbox, e := kube.ReadInstallerOutbox(limit, kc, namespace, installation)
		if e == nil && !applied[outbox.Phase] {
			var artifact struct {
				AuditStorage struct {
					Prefix   string   `json:"prefix"`
					Prefixes []string `json:"prefixes"`
				} `json:"auditStorage"`
				FederationAuditStorage *struct {
					Prefixes []string `json:"prefixes"`
				} `json:"federationAuditStorage"`
				DownloadEvidenceReadStorage *struct {
					Bucket string `json:"bucket"`
				} `json:"downloadEvidenceReadStorage"`
				Publisher *struct {
					AuditStorage struct {
						Prefixes []string `json:"prefixes"`
					} `json:"auditStorage"`
					EvidenceReadStorage struct {
						Bucket string `json:"bucket"`
					} `json:"evidenceReadStorage"`
				} `json:"publisher"`
				EvidenceDeleteStorage *struct {
					Bucket   string   `json:"bucket"`
					Prefixes []string `json:"prefixes"`
				} `json:"evidenceDeleteStorage"`
				Public bool `json:"public"`
			}
			if json.Unmarshal(outbox.Recipe, &artifact) != nil {
				t.Fatal("outbox artifact unreadable")
			}
			scope := artifact.AuditStorage.Prefixes
			if artifact.AuditStorage.Prefix != "" {
				scope = []string{artifact.AuditStorage.Prefix}
			}
			user := strings.TrimSuffix(outbox.Purpose, "-provider")
			users = append(users, user)
			file := filepath.Join(work, user+"-audit.json")
			if e = os.WriteFile(file, installerOperatorStorage(t, limit, providers, user, installerAuditActions(providers, scope), users), 0o600); e != nil {
				t.Fatal(e)
			}
			args := []string{"--kubeconfig", kubeconfig, "--namespace", namespace, "--installation", installation, "--audit-credential", file}
			if a := artifact.FederationAuditStorage; a != nil {
				// ADR-193: the federation's separately scoped audit principal.
				users = append(users, "federation")
				federationFile := filepath.Join(work, "federation-audit.json")
				if e = os.WriteFile(federationFile, installerOperatorStorage(t, limit, providers, "federation", installerAuditActions(providers, a.Prefixes), users), 0o600); e != nil {
					t.Fatal(e)
				}
				args = append(args, "--federation-audit-credential", federationFile)
			}
			if a := artifact.DownloadEvidenceReadStorage; a != nil {
				// ADR-204 decision 5: the download workers' own reader of the
				// evidence bucket only.
				if a.Bucket != evidenceBucket {
					t.Fatal("download evidence storage section", a.Bucket)
				}
				users = append(users, "download-evidence")
				file := filepath.Join(work, "download-evidence.json")
				if e = os.WriteFile(file, installerOperatorStorage(t, limit, providers, "download-evidence", []string{"Read:" + evidenceBucket + "/*"}, users), 0o600); e != nil {
					t.Fatal(e)
				}
				args = append(args, "--download-evidence-credential", file)
			}
			if a := artifact.EvidenceDeleteStorage; a != nil {
				// ADR-205 decision 4: qualify the deletion child's exact
				// list/delete scope, without SeaweedFS's coarse Write grant.
				if a.Bucket != evidenceBucket || len(a.Prefixes) != 1 || a.Prefixes[0] != "v1/" {
					t.Fatal("evidence delete storage section", a.Bucket, a.Prefixes)
				}
				users = append(users, "evidence-delete")
				file := filepath.Join(work, "evidence-delete.json")
				if e = os.WriteFile(file, installerEvidenceDeleteCredential(t, limit, providers, evidenceBucket, users), 0o600); e != nil {
					t.Fatal(e)
				}
				args = append(args, "--evidence-delete-credential", file)
			}
			if a := artifact.Publisher; a != nil {
				// ADR-203: the publisher's audit writer under its own prefix and a
				// reader of the evidence bucket only.
				if a.EvidenceReadStorage.Bucket != evidenceBucket || len(a.AuditStorage.Prefixes) != 1 {
					t.Fatal("publisher storage section", a.EvidenceReadStorage.Bucket, a.AuditStorage.Prefixes)
				}
				users = append(users, "publisher", "publisher-evidence")
				for _, c := range []struct {
					user, flag string
					actions    []string
				}{{"publisher", "--publisher-audit-credential", installerAuditActions(providers, a.AuditStorage.Prefixes)}, {"publisher-evidence", "--evidence-read-credential", []string{"Read:" + evidenceBucket + "/*"}}} {
					file := filepath.Join(work, c.user+".json")
					if e = os.WriteFile(file, installerOperatorStorage(t, limit, providers, c.user, c.actions, users), 0o600); e != nil {
						t.Fatal(e)
					}
					args = append(args, c.flag, file)
				}
			}
			if artifact.Public {
				// ADR-194: the operator's OIDC client secret and public TLS pair.
				var certPEM, keyPEM []byte
				publicRoot, certPEM, keyPEM = syntheticServingPair(t, "asservat.synthetic.invalid")
				for name, b := range map[string][]byte{"oidc-client-secret": []byte(consoleSecret), "public-tls.crt": certPEM, "public-tls.key": keyPEM} {
					if e = os.WriteFile(filepath.Join(work, name), b, 0o600); e != nil {
						t.Fatal(e)
					}
				}
				args = append(args, "--oidc-client-secret", filepath.Join(work, "oidc-client-secret"), "--public-tls-certificate", filepath.Join(work, "public-tls.crt"), "--public-tls-key", filepath.Join(work, "public-tls.key"))
			}
			var out bytes.Buffer
			if e = bootstrap.RunInstallerProviderApply(limit, args, &out); e != nil {
				t.Fatal("actual applier", outbox.Phase, e, out.String())
			}
			t.Logf("applied phase %d %s:\n%s", outbox.Phase, outbox.Purpose, out.String())
			applied[outbox.Phase] = true
		}
		select {
		case <-limit.Done():
			t.Fatal("continuation did not finish within the original window", limit.Err())
		case <-time.After(time.Second):
		}
	}
	if !applied[1] || !applied[3] || len(applied) != 2 {
		t.Fatal("continuation finished without both provider waits", applied)
	}
	if _, err = api.CoreV1().Secrets(namespace).Get(ctx, contracts.InstallerInboxName(installation), meta.GetOptions{}); err == nil {
		t.Fatal("consumed inbox retained")
	}
	journal, err := api.CoreV1().Secrets(desired.TargetNamespace).Get(ctx, "asservat-runtime-resources-"+strings.ReplaceAll(installation, "-", ""), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	state, err := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(journal.Data["state.json"]))
	if err != nil || state.WorkerInputs == nil || state.WorkerInputs.Receipt == nil || state.OwnerIdentity == nil || state.OwnerIdentity.Receipt == nil || state.OwnerLaunch == nil || state.OwnerLaunch.Receipt == nil {
		t.Fatal("journal lacks acknowledged worker inputs, owner identity or owner launch", err)
	}
	// ADR-185 public sources: settings and the empty catalog with its guard.
	for _, name := range []string{contracts.OwnerBrowserSettingsName(installation), contracts.OwnerIdentitySettingsName(installation), contracts.OwnerClusterCatalogName(installation)} {
		if _, e := api.CoreV1().ConfigMaps(desired.TargetNamespace).Get(ctx, name, meta.GetOptions{}); e != nil {
			t.Fatal("public source missing", name, e)
		}
	}
	if _, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, contracts.OwnerClusterCatalogName(installation)+"-guard", meta.GetOptions{}); e != nil {
		t.Fatal("cluster catalog guard missing", e)
	}
	for _, name := range []string{prefix + "-worker", prefix + "-owner"} {
		d, e := api.AppsV1().Deployments(desired.TargetNamespace).Get(ctx, name, meta.GetOptions{})
		if e != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 {
			t.Fatal("runtime Deployment not launched", name, e)
		}
		installerContinuationRunning(t, ctx, api, d, desired.Image)
	}
	// ADR-189: the launched hub-worker runs the permission stream for the
	// owner selection's root: fresh, with every authority audit acknowledged.
	p := state.PermissionProjection
	if p == nil || p.Receipt == nil || state.OwnerBootstrap == nil {
		t.Fatal("journal lacks the acknowledged permission projection")
	}
	for until := time.Now().Add(5 * time.Minute); ; {
		var initial, fresh bool
		var pending, total int
		e := admin.QueryRow(ctx, `SELECT s.initial_audit_id IS NOT NULL, coalesce(s.fresh_until > clock_timestamp(), false),
			(SELECT count(*) FROM authority_audit a WHERE a.stream_id=s.id AND a.acknowledged_at IS NULL),
			(SELECT count(*) FROM authority_audit a WHERE a.stream_id=s.id)
			FROM permission_stream s WHERE s.id=$1`, p.RootID).Scan(&initial, &fresh, &pending, &total)
		if e == nil && initial && fresh && pending == 0 && total > 0 {
			t.Logf("permission stream %s fresh with %d acknowledged authority audits", p.RootID, total)
			break
		}
		if time.Now().After(until) {
			t.Fatal("permission stream not fresh and acknowledged", e, initial, fresh, pending, total)
		}
		time.Sleep(time.Second)
	}
	// ADR-190: capacity initialized for the same root before the owner launch.
	var sources int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM capacity_source WHERE root_id=$1`, p.RootID).Scan(&sources); e != nil || sources != 1 {
		t.Fatal("capacity setup missing for the permission root", e, sources)
	}
	t.Log("capacity source initialized for the permission root")
	// ADR-193 step 2a: the federation projection exists, immutable, with the
	// six federation logins and the audit keys bound to the permission root.
	federation, e := api.CoreV1().Secrets(desired.TargetNamespace).Get(ctx, contracts.FederationRuntimeProjectionName(installation), meta.GetOptions{})
	if e != nil || federation.Immutable == nil || !*federation.Immutable || len(federation.Data) != len(contracts.PublicRuntimeFederationPurposes())+1 {
		t.Fatal("federation projection missing or incomplete", e)
	}
	if keys, e := contracts.DecodeFederationAuditKeys(bytes.NewReader(federation.Data[contracts.FederationAuditKeysFile])); e != nil || keys.RootID != p.RootID {
		t.Fatal("federation audit keys not bound to the permission root", e)
	}
	t.Log("federation projection published for the permission root")
	// ADR-193 step 2b: the federation account exists and its audit Secret was
	// filled from the phase-3 inbox; the continuation verified its applied
	// provider roles through the inspection token before the owner launch.
	if a, e := api.CoreV1().ServiceAccounts(desired.TargetNamespace).Get(ctx, contracts.FederationServiceAccountName(installation), meta.GetOptions{}); e != nil || a.AutomountServiceAccountToken == nil || *a.AutomountServiceAccountToken {
		t.Fatal("federation account missing", e)
	}
	if s, e := api.CoreV1().Secrets(desired.TargetNamespace).Get(ctx, contracts.FederationAuditSecretName(installation), meta.GetOptions{}); e != nil || len(s.Data[contracts.FederationProviderAuditCredentialFile]) == 0 {
		t.Fatal("federation audit Secret not filled", e)
	}
	t.Log("federation provider roles applied and verified")
	// ADR-193 step 2d: the federation runs with Kubernetes-auth provider
	// credentials and zero peers, and the public offer names its endpoint.
	if d, e := api.AppsV1().Deployments(desired.TargetNamespace).Get(ctx, kube.FederationWorkloadName(installation), meta.GetOptions{}); e != nil || d.Status.AvailableReplicas != 1 {
		installedProcessDiagnostics(t, ctx, api, desired.TargetNamespace, kube.FederationWorkloadName(installation))
		t.Fatal("federation not available", e)
	}
	offerMap, e := api.CoreV1().ConfigMaps(desired.TargetNamespace).Get(ctx, contracts.RegionalOfferName(installation), meta.GetOptions{})
	if e != nil {
		t.Fatal("regional offer missing", e)
	}
	var offer contracts.RegionalOffer
	if json.Unmarshal([]byte(offerMap.Data[contracts.RegionalOfferFile]), &offer) != nil || offer.PermissionRootID != p.RootID || len(offer.Federation.Roots) != 1 || !bytes.Equal(offer.Federation.Roots[0], servingCA) ||
		offer.ConnectorServerSuffix != contracts.ConnectorServerSuffix(installation) || offer.Roles.Source == "" || !json.Valid(offer.ConnectorBacking) || !bytes.Contains(offer.ConnectorBacking, []byte(p.RootID)) {
		t.Fatal("regional offer incomplete")
	}
	t.Log("federation available with zero peers; regional offer published")
	installerOwnerExposed(t, ctx, api, desired.TargetNamespace, installation, offer)
	installerKeyServiceInstalled(t, ctx, api, admin, desired.TargetNamespace, installation, offer, keyServingCA)
	installerPublisherInstalled(t, ctx, api, desired.TargetNamespace, installation)
	// ADR-190 step 7: the continuation published the capacity projection after
	// the owner launch, and the hub-worker ran capacity to ReadyAt.
	if c := state.CapacityProjection; c == nil || c.Receipt == nil {
		t.Fatal("journal lacks the acknowledged capacity projection")
	}
	for until := time.Now().Add(5 * time.Minute); ; {
		// ReadyAt is the hub-worker's capacity root publication (ADR-190).
		var ready bool
		e := admin.QueryRow(ctx, `SELECT coalesce(root_configuration->'ReadyAt' <> 'null'::jsonb, false) FROM capacity_source WHERE root_id=$1`, p.RootID).Scan(&ready)
		if e == nil && ready {
			t.Log("capacity root ReadyAt set for the permission root")
			break
		}
		if time.Now().After(until) {
			var revision int64
			var suspended, fresh, planned, backed bool
			_ = admin.QueryRow(ctx, `SELECT accepted_revision, suspended, coalesce(fresh_until > clock_timestamp(), false), root_plan IS NOT NULL,
				coalesce(root_configuration->'CaptureBackedAt' <> 'null'::jsonb, false) FROM capacity_source WHERE root_id=$1`, p.RootID).Scan(&revision, &suspended, &fresh, &planned, &backed)
			t.Logf("capacity_source accepted revision %d suspended %v fresh %v planned %v capture-backed %v", revision, suspended, fresh, planned, backed)
			installedProcessDiagnostics(t, ctx, api, desired.TargetNamespace, prefix+"-worker", prefix+"-owner")
			t.Fatal("capacity root not ready", e)
		}
		time.Sleep(time.Second)
	}
	// ADR-194: the owner launched promoted. Its download sources exist, the
	// operator public Secret was written, and the owner Pod is Ready: capacity
	// readiness above already reached its observation handler through the
	// server-name split on 9444. ADR-204 decision 2: the worker profile source
	// lives beside the workers, configured by the installer; the hub
	// namespace has no worker marker.
	if _, e := api.CoreV1().ConfigMaps(desired.TargetNamespace).Get(ctx, contracts.OwnerWorkerConfigurationName(installation), meta.GetOptions{}); !apierrors.IsNotFound(e) {
		t.Fatal("hub namespace still holds a worker configuration marker", e)
	}
	worker, e := api.CoreV1().ConfigMaps(contracts.DownloadWorkerNamespaceName(installation)).Get(ctx, contracts.DownloadWorkerProfileName(installation), meta.GetOptions{})
	if e != nil || worker.Data["worker-profile.json"] == "" || worker.Data["worker-profile.json"] == contracts.UnconfiguredWorkerConfiguration(installation) {
		t.Fatal("worker profile source not configured", e)
	}
	if _, e = api.CoreV1().ConfigMaps(desired.TargetNamespace).Get(ctx, contracts.OwnerDownloadEnvironmentName(installation), meta.GetOptions{}); e != nil {
		t.Fatal("owner download environment missing", e)
	}
	if s, e := api.CoreV1().Secrets(desired.TargetNamespace).Get(ctx, contracts.OwnerPublicProjectionName(installation), meta.GetOptions{}); e != nil || len(s.Data) != 3 {
		t.Fatal("operator public Secret missing", e)
	}
	installerPromotedOwnerReady(t, ctx, api, desired.TargetNamespace, prefix+"-owner", desired.Image)
	// ADR-195: the hub retention source accepted the empty set and then the
	// baseline, and reads Ready through the product source reader.
	sequence, epoch := installerHubRetentionReady(t, ctx, api, admin, desired.TargetNamespace, installation, p.RootID, original.Plan.ClusterID, 2)
	// ADR-195 step 7: an administrator's baseline edit is accepted, and a
	// hub-worker restart returns the source to Ready under a new epoch. The
	// edit qualifies retention administration; the fast fixture skips it.
	if !installedFastFixture() {
		runner := rest.CopyConfig(kc)
		runner.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + namespace + ":" + desired.Name + "-bootstrap-runner", Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + namespace, "system:authenticated"}}
		edit, err := kubernetes.NewForConfig(runner)
		if err != nil {
			t.Fatal(err)
		}
		// The runner holds update, never patch (chart rule); read, modify, update.
		path := "/apis/asservat.io/v1alpha1/namespaces/" + desired.TargetNamespace + "/evidenceretentionpolicies/" + contracts.RetentionBaselineName(installation)
		raw, err := edit.CoreV1().RESTClient().Get().AbsPath(path).DoRaw(ctx)
		var policy map[string]any
		if err != nil || json.Unmarshal(raw, &policy) != nil {
			t.Fatal("baseline read", err)
		}
		policy["spec"].(map[string]any)["maxima"].(map[string]any)["auditMetadataSeconds"] = 1209600
		body, _ := json.Marshal(policy)
		if err = edit.CoreV1().RESTClient().Put().AbsPath(path).Body(body).Do(ctx).Error(); err != nil {
			t.Fatal("administrator baseline edit", err)
		}
		sequence, _ = installerHubRetentionReady(t, ctx, api, admin, desired.TargetNamespace, installation, p.RootID, original.Plan.ClusterID, sequence+1)
	}
	// The hub-worker crash costs about a minute; within the 20-minute split it
	// runs in the restart run (and the unsplit run) only.
	if focus := installedJourneyFocus(); focus == "" || focus == "restart" {
		installerCrashHubWorker(t, ctx, api, desired.TargetNamespace, prefix+"-worker")
		if _, restarted := installerHubRetentionReadyEpoch(t, ctx, api, admin, desired.TargetNamespace, installation, p.RootID, original.Plan.ClusterID, sequence, epoch); restarted == epoch {
			t.Fatal("restarted hub-worker kept the old retention epoch")
		}
		t.Log("hub-worker restart Ready under a new retention epoch; baseline edit accepted:", !installedFastFixture())
	}
	t.Log("promoted owner Ready with download sources, operator public Secret and observation on 9444")
	// ADR-193 step 5: a regional cluster installed by installer-cluster.
	// The first installed S-02 slice runs once the regional workload holds a
	// fresh binding; it reads the public root generated during provider apply.
	publicAddress := net.JoinHostPort(nodeInternalIP(t, ctx, api, f.Clusters[0].NodeUID), "31450")
	journey := func(cluster, namespace, workload string, deny func(bool), gone func(string)) {
		if installedFastFixture() {
			installedContextStandbyWindow(t, ctx, api, desired.TargetNamespace, prefix+"-owner")
		}
		t.Logf("installed focus %q starts (fast fixture %v)", installedJourneyFocus(), installedFastFixture())
		diagnose := func() {
			installedSQLActivityDiagnostics(ctx, admin.Query, installation, t.Logf)
			installedProcessDiagnostics(t, ctx, api, desired.TargetNamespace, prefix+"-owner", prefix+"-worker", contracts.PublisherName(installation))
			c, end := context.WithTimeout(ctx, 20*time.Second)
			defer end()
			installedPodDiagnostics(t, c, api, contracts.DownloadWorkerNamespaceName(installation), "download-worker", "")
		}
		if installedJourneyFocus() == "policy-recording" {
			t.Run("policy-recording", func(t *testing.T) {
				qualifyInstalledPolicyRecording(t, ctx, admin, p.RootID, identity, publicRoot, publicAddress, origin, f.Clusters[1].Config, diagnose)
			})
			return
		}
		if installedJourneyFocus() == "ongoing-save" {
			t.Run("ongoing-save", func(t *testing.T) {
				qualifyInstalledOngoingSave(t, ctx, admin, p.RootID, identity, publicRoot, publicAddress, origin, diagnose)
			})
			return
		}
		if installedRecordingFocus() {
			t.Run("approved-recording", func(t *testing.T) {
				var measurement *nativePacingMeasurement
				if installedJourneyFocus() == "native-paced" {
					if !f.NativeSQLStatistics {
						t.Fatal("native pacing SQL statistics not configured")
					}
					if _, err := admin.Exec(ctx, nativePacingStatisticsSetup); err != nil {
						t.Fatal("post-bootstrap private SQL statistics setup", err)
					}
					// Bootstrap DDL is outside this measurement. Reset the owned
					// fixture library once before the first baseline, never midphase.
					if _, err := admin.Exec(ctx, nativePacingStatisticsReset); err != nil {
						t.Fatal("pre-baseline private SQL statistics reset", err)
					}
					measurement = &nativePacingMeasurement{admin: admin, root: p.RootID, providers: providers, traffic: f.NativeTrafficHelper}
				}
				qualifyInstalledApprovedRecording(t, ctx, identity, publicRoot, publicAddress, origin, cluster, namespace, workload, f.Clusters[1].Config, diagnose, measurement, func(captureID string) { installedHistoryStorageDiagnostics(t, ctx, admin, p.RootID, captureID) }, func(previewID string) { installedInitialStorageDiagnostics(t, ctx, admin, p.RootID, previewID) })
			})
			return
		}
		if focus := installedJourneyFocus(); focus == "policy" || focus == "alert" || focus == "logresource" {
			// ADR-228: the restart-trigger policy journey (ADR-231: its alert
			// phase in the alert focus, ADR-241: its log and resource phases in
			// the logresource focus) replaces the manual journey.
			installedPolicyJourney(t, ctx, admin, p.RootID, identity, publicRoot, publicAddress, origin, diagnose)
			return
		}
		run := installedJourney(t, ctx, admin, p.RootID, identity, publicRoot, publicAddress, origin, diagnose,
			installedJourneyDeletion(t, ctx, admin, providers, evidenceBucket, p.RootID, diagnose), installedProjectionSQLCheck(t, ctx, admin, api, p.RootID))
		// The PostgreSQL restart (ADR-226) runs only in the focused restart
		// mode, so each run stays within the 20-minute limit and the full
		// journey's capacity budget is unchanged.
		focused := (installedJourneyFocus() == "restart" || installedJourneyFocus() == "upgrade") && deny != nil
		if focused || installedJourneyFocus() == "clusters" || installedJourneyFocus() == "chain" || installedJourneyFocus() == "share" {
			deny, gone = nil, nil
		}
		run(cluster, namespace, workload, deny, gone)
		if focused && installedJourneyFocus() == "upgrade" {
			// ADR-227: upgrade hub-api and hub-worker to a second release image
			// (the same build, another digest), capture again, then roll back.
			if f.UpgradeImage == "" || f.UpgradeImage == desired.Image {
				t.Fatal("upgrade run without a distinct second release image")
			}
			restarts := installedHubRestarts(t, ctx, api, desired.TargetNamespace)
			installedReleaseChange(t, ctx, api, desired, installation, f.UpgradeImage, 2)
			installedHubSettled(t, ctx, api, desired.TargetNamespace, restarts)
			run(cluster, namespace, workload, nil, nil)
			t.Log("installed journey: after the upgrade to a second release image a new capture was collected, published and downloaded")
			restarts = installedHubRestarts(t, ctx, api, desired.TargetNamespace)
			installedReleaseChange(t, ctx, api, desired, installation, desired.Image, 3)
			installedHubSettled(t, ctx, api, desired.TargetNamespace, restarts)
			t.Log("installed journey: image-only rollback settled both hub Deployments on the original image")
			return
		}
		if focused {
			// ADR-226: after a lossless PostgreSQL restart the installation
			// re-activates by itself and a new capture and download work.
			restarts := installedHubRestarts(t, ctx, api, desired.TargetNamespace)
			installedPostgresRestart(t, ctx, admin, f.PostgresContainer, installation)
			// Wait until every hub process has been Ready for 20 s without a
			// restart; log which ones restarted (native110/111: none for hub-api
			// within that window).
			installedHubSettled(t, ctx, api, desired.TargetNamespace, restarts)
			run(cluster, namespace, workload, nil, nil)
			t.Log("installed journey: after a PostgreSQL restart the installation re-activated without operator action; a new capture was collected, published and downloaded")
		}
	}
	hubKubeconfig := installedUnifiedRunnerKubeconfig(t, f.Clusters[0].Config, desired)
	qualifyRegionalInstall(t, ctx, f, 1, admin, runnerAPI, api, hubKubeconfig, desired.TargetNamespace, issuer, journey, providers, offerMap.Data[contracts.RegionalOfferFile], installation)
	if focus := installedJourneyFocus(); focus == "restart" || focus == "journey" || focus == "browser" || focus == "upgrade" || focus == "policy" || focus == "alert" || focus == "logresource" || focus == "chain" || focus == "share" || installedRecordingFocus() {
		t.Log("focused " + focus + " run complete: the second workload cluster and replay checks were not run")
		return
	}
	// S-02 exit: a second workload cluster through the same hub, product
	// installer path and offer. Its short journey (no Deny closure) stops after
	// the native download; the first cluster covers Stop, Deny, expiry and
	// deletion.
	short := func(cluster, namespace, workload string, _ func(bool), _ func(string)) {
		journey(cluster, namespace, workload, nil, nil)
	}
	qualifyRegionalInstall(t, ctx, f, 2, admin, runnerAPI, api, hubKubeconfig, desired.TargetNamespace, issuer, short, providers, offerMap.Data[contracts.RegionalOfferFile], installation)
	// After the guard bridge, the same five-command profile replays (as on
	// upgrade), finds the installation complete and preserves guard/journal state.
	guard, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, original.Plan.Workload.WorkloadGuard, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unified.replay(t, ctx, api, kubeconfig, desired)

	after, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, guard.Name, meta.GetOptions{})
	again, e := api.CoreV1().Secrets(desired.TargetNamespace).Get(ctx, journal.Name, meta.GetOptions{})
	if err != nil || e != nil || after.UID != guard.UID || after.Generation != guard.Generation || again.ResourceVersion != journal.ResourceVersion {
		t.Fatal("replay after the bridge changed the guard or the journal", err, e)
	}
	if installedFastFixture() {
		t.Log("actual fresh five-command runner (fast fixture: no interruption/resume), two actual provider waits and completed five-command replay; installed journey results are reported separately")
		return
	}
	t.Log("actual fresh five-command runner, positive-terminal interruption/resume of the same original journals, two actual provider waits and completed five-command replay; installed journey results are reported separately")
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
	command := exec.CommandContext(ctx, "docker", "exec", "-i", native.Container, "/usr/bin/weed", "shell", "-master=localhost:9333", "-filer=localhost:8888")
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
	runID := strings.TrimSuffix(strings.TrimPrefix(native.Container, "asservat-"), "-s3")
	label, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{ index .Config.Labels \"asservat.test\" }}", native.Container).Output()
	if err != nil || strings.TrimSpace(string(label)) != runID || len(actions) == 0 {
		t.Fatal("refuse non-owned S3 administration", err)
	}
	bucket := p.desired.AuditStore.Bucket
	key, secret := user+"-continuation", user+"-continuation-secret"
	shell := "s3.configure -user=administrator -access_key=synthetic-only -secret_key=synthetic-only-secret -actions=Admin,Read,Write,List -apply\n" +
		"s3.configure -user=" + user + " -access_key=" + key + " -secret_key=" + secret + " -actions=" + strings.Join(actions, ",") + " -apply\n"
	command := exec.CommandContext(ctx, "docker", "exec", "-i", native.Container, "/usr/bin/weed", "shell", "-master=localhost:9333", "-filer=localhost:8888")
	command.Stdin = strings.NewReader(shell)
	if output, e := command.CombinedOutput(); e != nil {
		clear(output)
		t.Fatal("owned exact IAM provisioning command unavailable", e)
	}
	var principals []string
	for _, u := range users {
		principals = append(principals, "arn:aws:iam::000000000000:user/"+u)
	}
	policy, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Sid": "DenyRuntimeDeletion", "Effect": "Deny", "Principal": map[string]any{"AWS": principals}, "Action": []string{"s3:DeleteObject", "s3:DeleteObjectVersion"}, "Resource": "arn:aws:s3:::" + bucket + "/*"}}})
	store := s3.New(s3.Options{Region: p.desired.AuditStore.Region, BaseEndpoint: aws.String(p.desired.AuditStore.Endpoint), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: p.client, RetryMaxAttempts: 1})
	if _, err = store.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: aws.String(string(policy))}); err != nil {
		t.Fatal("runtime deletion denial", err)
	}
	out, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: key, SecretAccessKey: secret})
	return out
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

// installShippedPermissionCRDs installs the chart's own AccessBinding and
// PermissionSource CRDs, as Helm does from crds/ (ADR-189), and waits until
// both are established.
func installShippedPermissionCRDs(t *testing.T, ctx context.Context, api kubernetes.Interface) {
	t.Helper()
	client := api.CoreV1().RESTClient()
	for _, file := range []string{"accessbindings.yaml", "permissionsources.yaml", "evidencestoragepools.yaml", "evidencebudgetpolicies.yaml", "evidenceretentionpolicies.yaml", "debugpolicies.yaml"} {
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
	return &contracts.InstallerCapacitySettings{Pool: "capacity", Policy: "applications", NamespaceKeys: []string{"team"}, Accounts: 16, Records: 4, AdmissionSeconds: 86400,
		Lanes:               contracts.InstallerCapacityLanes{CaptureRetainedSeconds: 10000, Normal: lane(4, 128), Resolution: lane(4, 8), Processing: lane(2, 16)},
		StopRetainedSeconds: 10000,
		Backup:              contracts.InstallerCapacityBackup{HorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 2, WALCopies: 3},
		Footprints:          contracts.InstallerCapacityFootprints{Capture: f(128<<10, 256<<10), Operation: f(128<<10, 256<<10), Processing: f(128<<10, 256<<10), Native: f(64<<10, 128<<10), Stop: f(128<<10, 256<<10), ProcessingState: f(16<<10, 64<<10)},
		PurgeLeases:         4,
		Processing:          contracts.InstallerCapacityProcessing{MaxRules: 2, MaxRootTransitions: 512},
		Metadata:            contracts.InstallerCapacityMetadata{FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, ConfigurationTransitions: 4096},
		Envelope:            contracts.InstallerCapacityEnvelope{SystemObjects: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1 << 50}, SQLBytes: 1 << 50, BackupBytes: 1 << 50, WALBytes: 1 << 50, KeyAttempts: 1 << 50},
		Backends:            []contracts.InstallerCapacityBackend{{StorageProfile: "dedicated", Usable: contracts.InstallerCapacityAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
}

// installNativeCapacityObjects creates the operator's pool and budget policy
// in the hub namespace, as the chart renders them from values (ADR-190).
func installNativeCapacityObjects(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, cluster string) {
	t.Helper()
	client := api.CoreV1().RESTClient()
	amount := func(bytes, objects int64) map[string]int64 {
		return map[string]int64{"bytes": bytes, "objects": objects}
	}
	upload := map[string]int64{"bytesPerSecond": 134217728, "burstBytes": 16777216}
	pool := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceStoragePool", "metadata": map[string]any{"name": "capacity"}, "spec": map[string]any{
		"storageProfileRef": "dedicated", "capacity": amount(137438953472, 100000), "safetyHeadroom": amount(17179869184, 10000), "systemReserve": amount(8589934592, 10000), "sharedBurst": amount(42949672960, 40000),
		"protectedAllocations": []any{map[string]any{"budgetPolicyRef": "applications", "workloadSlots": 4, "protectedPerWorkload": amount(17179869184, 10000)}},
		"upload":               upload, "maxUploadRequestsPerSecond": 100, "capacityAssurance": "qualifiedReservedBackend"}}
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceBudgetPolicy", "metadata": map[string]any{"name": "applications"}, "spec": map[string]any{
		"poolRef": "capacity", "scope": map[string]any{"clusterID": cluster, "namespaceSelector": map[string]any{"matchLabels": map[string]string{"team": "applications"}}},
		"namespaceEnvelope": map[string]int64{"maxWorkloadAccounts": 4, "maxStoredBytes": 111669149696, "maxObjects": 80000},
		"workload": map[string]any{"protected": amount(17179869184, 10000), "hardLimit": amount(34359738368, 20000), "contextReserve": amount(1073741824, 1000),
			"dump":                   map[string]int64{"burst": 1, "minimumIntervalSeconds": 900, "maxStartsPerRollingHour": 2, "maxInputBytesPerRollingHour": 4294967296},
			"maxConcurrentExpensive": 1, "maxQueuedExpensive": 1, "maxQueueAgeSeconds": 30, "upload": map[string]int64{"bytesPerSecond": 33554432, "burstBytes": 4194304}, "maxUploadRequestsPerSecond": 20, "maxSpoolBytes": 2147483648, "onFull": "RejectNewExpensive"},
		"node": map[string]any{"maxConcurrentExpensive": 2, "maxQueuedExpensive": 10, "upload": map[string]int64{"bytesPerSecond": 67108864, "burstBytes": 8388608}, "maxSpoolBytes": 4294967296, "impactProfileRef": "standard-node", "unhealthySamples": 3, "sampleIntervalSeconds": 5, "recoveryHealthySeconds": 60}}}
	for plural, object := range map[string]map[string]any{"evidencestoragepools": pool, "evidencebudgetpolicies": policy} {
		body, _ := json.Marshal(object)
		if err := client.Post().AbsPath("/apis/asservat.io/v1alpha1/namespaces/" + namespace + "/" + plural).Body(body).Do(ctx).Error(); err != nil {
			t.Fatal("operator capacity object", plural, err)
		}
	}
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
			t.Logf("diagnostics: %s pod %s container %s ready %v restarts %d last %q exit %d", name, pod.Name, s.Name, s.Ready, s.RestartCount, reason, exit)
			for _, previous := range []bool{true, false} {
				logs, e := api.CoreV1().Pods(namespace).GetLogs(pod.Name, &core.PodLogOptions{Container: s.Name, Previous: previous, TailLines: ptr.To(int64(400)), LimitBytes: ptr.To(int64(65536))}).DoRaw(c)
				if e == nil && len(logs) > 0 {
					t.Logf("diagnostics: %s previous=%v log:\n%s", pod.Name, previous, logs)
				}
			}
		}
	}
}

// installerFederationServingSecret creates the operator's synthetic federation
// TLS Secret (a self-signed CA and a serverAuth leaf for serverName) and
// returns the CA certificate.
func installerFederationServingSecret(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, installation, serverName string) []byte {
	t.Helper()
	return installerServingSecret(t, ctx, api, namespace, contracts.FederationServingSecretName(installation), serverName)
}

func installerServingSecret(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, name, serverName string) []byte {
	t.Helper()
	caDER, certPEM, keyPEM := syntheticServingPair(t, serverName)
	secret := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Type: core.SecretTypeTLS, Data: map[string][]byte{
		"tls.crt": certPEM, "tls.key": keyPEM, "ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}}
	if _, err := api.CoreV1().Secrets(namespace).Create(ctx, secret, meta.CreateOptions{}); err != nil {
		t.Fatal("serving Secret", name, err)
	}
	return caDER
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
		time.Sleep(time.Second)
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
			if a, e := sources.AcceptedRetentionSource(ctx, root, ref); e == nil && a.Ready && len(a.Snapshot.Policies) == 1 && a.Epoch != previous {
				t.Logf("hub retention source Ready at sequence %d with the baseline policy", sequence)
				return sequence, a.Epoch
			}
		}
		if time.Now().After(until) {
			t.Fatal("hub retention source not Ready", e, sequence)
		}
		time.Sleep(2 * time.Second)
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
	label, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{ index .Config.Labels \"io.x-k8s.kind.cluster\" }}", node).Output()
	if err != nil || strings.TrimSpace(string(label)) != cluster {
		t.Fatal("node container not owned by this harness cluster", err)
	}
	ids, err := exec.CommandContext(ctx, "docker", "exec", node, "crictl", "ps", "-q", "--label", "io.kubernetes.pod.uid="+string(pod.UID), "--name", pod.Status.ContainerStatuses[0].Name).Output()
	id := strings.TrimSpace(string(ids))
	if err != nil || id == "" || strings.Contains(id, "\n") {
		t.Fatal("hub-worker container", err)
	}
	if err = exec.CommandContext(ctx, "docker", "exec", node, "crictl", "stop", id).Run(); err != nil {
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
		time.Sleep(time.Second)
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
		time.Sleep(2 * time.Second)
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
		time.Sleep(2 * time.Second)
	}
}

// installedPostgresRestart restarts the owned PostgreSQL container (data on
// its volume, same address) and waits until the hub's own observation has
// re-activated the trust root: no fixture SQL writes activation.
func installedPostgresRestart(t *testing.T, ctx context.Context, admin *pgxpool.Pool, container, installation string) {
	t.Helper()
	ip := func() string {
		out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container).Output()
		if err != nil {
			t.Fatal("PostgreSQL container address", err)
		}
		return strings.TrimSpace(string(out))
	}
	before := ip()
	if container == "" || !strings.HasPrefix(container, "asservat-") || before == "" {
		t.Fatal("owned PostgreSQL container unknown", container)
	}
	if out, err := exec.CommandContext(ctx, "docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatal("PostgreSQL restart", err, string(out))
	}
	if after := ip(); after != before {
		t.Fatal("PostgreSQL address changed on restart", before, after)
	}
	// The fixture's own pooled connections died with the server.
	admin.Reset()
	started := time.Now()
	for until := started.Add(3 * time.Minute); ; time.Sleep(2 * time.Second) {
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
	for until := time.Now().Add(3 * time.Minute); ; time.Sleep(2 * time.Second) {
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
	for until := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
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
	for until := start.Add(5 * time.Minute); ; time.Sleep(2 * time.Second) {
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
