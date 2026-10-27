package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	authn "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// qualifyRegionalInstall is ADR-193 step 5 on top of the installed hub: a
// product BootstrapIssuer slot, the operator's read of the KV record, then
// `installer-cluster` against owned workload cluster f.Clusters[index]
// (index 1 or 2; Clusters[0] is the hub). Both leaves must
// activate, a Pod restart is readmitted, a rerun is idempotent and a
// non-administrator source write is denied. The issuance logins are the
// product fleet-bootstrap purposes the continuation provisioned; only the
// fleet operator authority is fixture setup. Hub operations use the accepted
// runner; the original observer retains diagnostic log access only.
func qualifyRegionalInstall(t *testing.T, ctx context.Context, f fixture, index int, admin *pgxpool.Pool, hub, hubObserver kubernetes.Interface, hubKubeconfig, namespace, issuer string, journey func(cluster, namespace, workload string, deny func(bool), gone func(string)), providers *initialRuntimeNativeProviders, offerJSON string, installation string) {
	t.Helper()
	var offer contracts.RegionalOffer
	if json.Unmarshal([]byte(offerJSON), &offer) != nil {
		t.Fatal("offer")
	}
	executor, err := offer.RegionalExecutorOffered()
	if err != nil {
		t.Fatal("partial executor offer", err)
	}
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[index].Config)
	if err != nil {
		t.Fatal(err)
	}
	region, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if executor {
		// Match the chart/operator prerequisite in each workload cluster,
		// before issuing the short-lived bootstrap. The product installer
		// reads discovery only and never installs or adopts a shared CRD.
		installRegionalStartCRD(t, ctx, region)
	}
	record := issueInstalledBootstrap(t, ctx, admin, hub, namespace, providers, installation, index)
	dir := t.TempDir()
	offerFile, recordFile := filepath.Join(dir, "regional-offer.json"), filepath.Join(dir, "bootstrap.json")
	if os.WriteFile(offerFile, []byte(offerJSON), 0o600) != nil || os.WriteFile(recordFile, record, 0o600) != nil {
		t.Fatal("operator files")
	}
	clear(record)
	args := []string{"--kubeconfig", f.Clusters[index].Config, "--offer", offerFile, "--bootstrap", recordFile, "--namespace", "asservat-connector"}
	envelope, err := kms.DecodeBootstrapRecord(mustRead(t, recordFile))
	if err != nil {
		t.Fatal(err)
	}
	var existing *regionalPrepared
	if executor && offer.Capacity != nil && installedFastFixture() {
		// The fast feature fixture's workload already runs when its cluster
		// joins, as most do, and the operator configures its budget and
		// maintainer for the cluster named by the bootstrap record before the
		// join. Discovery walks namespaces in name order, about 100 s per pass,
		// so a namespace sorting before the system ones is enrolled early in its
		// first pass instead of the second.
		w := createRegionalWorkload(t, ctx, region, offer.Image, "apps-regional")
		budget := newRegionalBudget(t, ctx, hub, namespace, issuer, envelope.Binding.ClusterID, index)
		budget.addPolicy()
		budget.addBinding(w)
		existing = &regionalPrepared{workload: w, budget: budget}
		t.Log("operator added the regional workload, budget policy, pool slot and maintainer binding before the join")
	}
	if executor {
		// ADR-196 decision 7: the operator's write-only evidence credential.
		evidenceFile := filepath.Join(dir, "evidence-storage.json")
		credential := installerEvidenceCredential(t, ctx, providers, offer.EvidenceStore.Bucket, envelope.Binding.ClusterID)
		if os.WriteFile(evidenceFile, credential, 0o600) != nil {
			t.Fatal("evidence credential file")
		}
		clear(credential)
		args = append(args, "--evidence-credential", evidenceFile)
		historyFile := filepath.Join(dir, contracts.RegionalHistoryCredentialFile)
		history := installerRegionalHistoryCredential(t, ctx, providers, offer.EvidenceStore.Bucket, offer.PermissionRootID, envelope.Binding.ClusterID)
		if os.WriteFile(historyFile, history, 0o600) != nil {
			t.Fatal("history credential file")
		}
		clear(history)
		args = append(args, "--history-credential", historyFile)
	}
	if executor && installedJourneyFocus() == "alert" && index == 1 {
		// ADR-231: the operator's in-cluster Alertmanager, named at install.
		args = append(args, "--alertmanager", installAlertmanager(t, ctx, region, f.AlertmanagerImage))
	}
	if executor && installedJourneyFocus() == "logresource" && index == 1 {
		// ADR-241: the workload cluster's metrics API, started early for its
		// warm-up (no installer input names it).
		installMetricsServer(t, ctx, region, f.MetricsServerImage)
	}
	var first bytes.Buffer
	if err := bootstrap.RunInstallerCluster(ctx, args, &first); err != nil {
		t.Fatal("installer-cluster", err)
	}
	var installed kube.RegionalInstallation
	if json.Unmarshal(first.Bytes(), &installed) != nil || installed.Secret.UID == "" {
		t.Fatal("installer-cluster result")
	}
	peer := envelope.Binding.PeerID
	waitActive := func(except string) string {
		t.Helper()
		for until := time.Now().Add(3 * time.Minute); time.Now().Before(until); time.Sleep(time.Second) {
			var pod string
			e := admin.QueryRow(ctx, `SELECT p.pod_uid::text FROM connector_identity_process p WHERE p.root_id=$1 AND p.peer_id=$2 AND p.accepted_at IS NOT NULL AND p.pod_uid::text<>$3
 AND EXISTS(SELECT 1 FROM connector_credential_attempt c WHERE c.id=p.client_current_id AND c.activated_at IS NOT NULL)
 AND EXISTS(SELECT 1 FROM connector_credential_attempt c WHERE c.id=p.server_current_id AND c.activated_at IS NOT NULL) LIMIT 1`, offer.PermissionRootID, peer, except).Scan(&pod)
			if e == nil {
				return pod
			}
		}
		regionalLogs(t, ctx, region)
		t.Fatal("regional connector not enrolled with both leaves")
		return ""
	}
	pod := waitActive("")
	t.Log("installer-cluster connector enrolled generation 1 and both leaves")
	if executor {
		qualifyRegionalExecutor(t, ctx, admin, region, offer, installed, peer)
		qualifyRegionalJoin(t, ctx, hub, hubObserver, hubKubeconfig, namespace, installation, *installed.Join, index)
		if offer.Capacity != nil {
			qualifyRegionalCapacity(t, ctx, admin, hub, hubObserver, region, namespace, issuer, journey, installation, offer, installed, index, existing)
		}
	}
	if !installedRegionalInstallerChecks(index) {
		// The rerun, restarted-connector readmission and source-write denial
		// qualify the regional installer; the chain run keeps them.
		return
	}
	// A rerun reopens every object unchanged.
	var second bytes.Buffer
	if err = bootstrap.RunInstallerCluster(ctx, args, &second); err != nil || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("installer-cluster rerun changed the installation", err)
	}
	// A restarted Pod is readmitted with the promoted credential alone.
	if err = region.CoreV1().Pods("asservat-connector").Delete(ctx, mustPodName(t, ctx, region, pod), meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitActive(pod)
	t.Log("restarted connector Pod readmitted without an administrator")
	// The connector account may dry-run the source but not change it.
	token, err := region.CoreV1().ServiceAccounts("asservat-connector").CreateToken(ctx, kube.RegionalAccount, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	minted := rest.AnonymousClientConfig(config)
	minted.BearerToken = token.Status.Token
	connector, err := kubernetes.NewForConfig(minted)
	if err != nil {
		t.Fatal(err)
	}
	source, err := connector.CoreV1().ConfigMaps("asservat-connector").Get(ctx, kube.RegionalSource, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source.Labels = map[string]string{"changed": "true"}
	if _, err = connector.CoreV1().ConfigMaps("asservat-connector").Update(ctx, source, meta.UpdateOptions{}); !apierrors.IsForbidden(err) && !apierrors.IsInvalid(err) {
		t.Fatal("non-administrator source write not denied", err)
	}
	t.Log("non-administrator source write denied by the source guard")
}

// installRegionalStartCRD is the owned fixture's operator setup, equivalent to
// applying the canonical chart CRD before a regional Helm hook or CLI install.
// The fresh regional cluster must not already contain a CRD to adopt.
func installRegionalStartCRD(t *testing.T, ctx context.Context, api kubernetes.Interface) {
	t.Helper()
	data, err := os.ReadFile("../../charts/asservat/crds/capacityreservations.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"
	client := api.CoreV1().RESTClient()
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := client.Post().AbsPath(path).MaxRetries(0).Body(data).Do(call).Error(); err != nil {
		t.Fatal("operator regional start CRD create", err)
	}
	path += "/capacityreservations.asservat.io"
	// The harness removes this owned cluster after the runtime has stopped.
	// Do not independently delete its start journal while producers may live.
	for {
		raw, err := client.Get().AbsPath(path).MaxRetries(0).DoRaw(call)
		var crd struct {
			Status struct {
				Conditions []struct{ Type, Status string } `json:"conditions"`
			} `json:"status"`
		}
		established := false
		if err == nil && json.Unmarshal(raw, &crd) == nil {
			for _, condition := range crd.Status.Conditions {
				established = established || condition.Type == "Established" && condition.Status == "True"
			}
		}
		if established {
			// Established precedes discovery propagation on the API server.
			var resources meta.APIResourceList
			raw, err = client.Get().AbsPath("/apis/asservat.io/v1alpha1").MaxRetries(0).DoRaw(call)
			if err == nil && json.Unmarshal(raw, &resources) == nil {
				main, status := false, false
				for _, resource := range resources.APIResources {
					main = main || resource.Name == "capacityreservations"
					status = status || resource.Name == "capacityreservations/status"
				}
				if main && status {
					t.Log("operator installed canonical regional CapacityReservation CRD")
					return
				}
			}
		}
		select {
		case <-call.Done():
			t.Fatal("operator regional start CRD was not established and served", call.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// issueInstalledBootstrap issues one slot through the product BootstrapIssuer
// on the installed hub's SQL trust with the projected product issuance
// logins, then reads the KV record as the operator would. It returns that
// record's data object. Each workload cluster index has its own operator key
// digest: the reservation is unique per actor and key.
func issueInstalledBootstrap(t *testing.T, ctx context.Context, admin *pgxpool.Pool, hub kubernetes.Interface, namespace string, p *initialRuntimeNativeProviders, installation string, index int) []byte {
	t.Helper()
	const profile = "regional-installer"
	id := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	mount, transit := "fleet-bootstrap-"+id, "fleet-issue-"+id
	p.admin(t, ctx, http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, http.StatusNoContent)
	for until := time.Now().Add(30 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		// The KV-v2 upgrade finishes asynchronously after mounting.
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+"/v1/"+mount+"/config", nil)
		request.Header.Set("X-Vault-Token", "synthetic-root")
		if r, e := p.client.Do(request); e == nil {
			r.Body.Close()
			if r.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(until) {
			t.Fatal("KV mount not ready")
		}
	}
	p.admin(t, ctx, http.MethodPost, mount+"/config", map[string]any{"cas_required": true, "max_versions": 1, "delete_version_after": "5m"}, http.StatusNoContent)
	p.admin(t, ctx, http.MethodPost, "sys/policies/acl/"+mount, map[string]any{"policy": `path "` + mount + `/data/connector/` + installation + `/*" { capabilities=["create","read"] }`}, http.StatusNoContent)
	var created struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	if json.Unmarshal(p.admin(t, ctx, http.MethodPost, "auth/token/create", map[string]any{"policies": []string{mount}, "no_default_policy": true, "ttl": "10m"}, http.StatusOK), &created) != nil || created.Auth.Token == "" {
		t.Fatal("channel token")
	}
	p.admin(t, ctx, http.MethodPost, "sys/mounts/"+transit, map[string]any{"type": "transit"}, http.StatusNoContent)
	p.admin(t, ctx, http.MethodPost, transit+"/keys/records", map[string]any{"type": "aes256-gcm96"}, http.StatusOK)
	channel, err := kms.NewBootstrapChannel(p.endpoint, created.Auth.Token, mount, "connector", profile, installation, p.client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	seal, err := kms.NewSealer(p.endpoint, "synthetic-root", transit, "records", p.client)
	if err != nil {
		t.Fatal(err)
	}
	open, err := kms.NewOpener(p.endpoint, "synthetic-root", transit, "records", p.client)
	if err != nil {
		t.Fatal(err)
	}
	a := p.desired.AuditStore
	store, err := objectstore.New(a.Endpoint, a.Region, a.Bucket, credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), p.client)
	if err != nil {
		t.Fatal(err)
	}
	c := admin.Config().ConnConfig
	address, tlsConfig := pgTLSBridge(t, net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))))
	projection, err := hub.CoreV1().Secrets(namespace).Get(ctx, contracts.PublicRuntimeProjectionName(installation), meta.GetOptions{})
	if err != nil {
		t.Fatal("public runtime projection", err)
	}
	// All four typed issuance facets share ADR-222's projected hub login.
	// This helper-owned single-connection pool closes before regional install
	// and its journey, so it consumes no later runtime allowance.
	var credential contracts.OwnerSQLCredential
	if json.Unmarshal(projection.Data["sql-public-hub-runtime.json"], &credential) != nil || credential.Username == "" {
		t.Fatal("projected issuance login missing")
	}
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword(credential.Username, credential.Password), Host: address, Path: "/" + c.Database, RawQuery: "sslmode=disable"}
	pc, err := pgxpool.ParseConfig(dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.TLSConfig, pc.ConnConfig.Fallbacks, pc.MaxConns = tlsConfig, nil, 1
	issuance, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer issuance.Close()
	reserve, err := postgres.NewBootstrapReservations(ctx, issuance, installation, uuid.NewString)
	if err != nil {
		t.Fatal(err)
	}
	var issues [3]*postgres.BootstrapIssues
	for i := range issues {
		if issues[i], err = postgres.NewBootstrapIssues(ctx, issuance, installation); err != nil {
			t.Fatal(err)
		}
	}
	authority := enrollmentAuthorityFunc(func(ctx context.Context, token, delivery string) (value.EnrollmentAuthority, error) {
		if token != "synthetic-operator" || delivery != profile {
			return value.EnrollmentAuthority{}, value.ErrDenied
		}
		var epoch string
		trust := identity.Revision{}
		var digest []byte
		if e := admin.QueryRow(ctx, `SELECT issuer_epoch::text, source_uid, source_generation, source_digest FROM fleet_trust WHERE installation_id=$1`, installation).Scan(&epoch, &trust.UID, &trust.Generation, &digest); e != nil {
			return value.EnrollmentAuthority{}, value.ErrUnavailable
		}
		copy(trust.Digest[:], digest)
		now := time.Now().UTC()
		return value.EnrollmentAuthority{InstallationID: installation, IssuerEpoch: epoch, DeliveryProfile: profile, Actor: identity.Principal{Issuer: "https://identity.example.test", Subject: "synthetic-operator", ClientID: "console", Kind: identity.Human},
			IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, AdministrationRevision: trust, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}, nil
	})
	issuer := fleetapp.BootstrapIssuer{Authority: authority, Reservations: reserve, Credentials: channel, Records: issues[0], Audits: issues[1], Objects: &objectstore.BootstrapIssueObjects{Store: store, Seal: seal, Open: open}, Activation: issues[2], Now: time.Now}
	intent, err := issuer.Issue(ctx, "synthetic-operator", fleetapp.BootstrapInput{KeyDigest: artifact.Digest{byte(1 + index)}, DisplayName: "synthetic region " + strconv.Itoa(index), Region: "eu-test", DeliveryProfile: profile})
	if err != nil || !intent.Issued {
		t.Fatal("audited bootstrap issuance on the installed hub", err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+"/v1/"+mount+"/data/connector/"+installation+"/"+intent.Slot.ID, nil)
	request.Header.Set("X-Vault-Token", created.Auth.Token)
	response, err := p.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var read struct {
		Data struct {
			Data json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&read) != nil || response.StatusCode != http.StatusOK {
		t.Fatal("operator bootstrap read")
	}
	return read.Data.Data
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPodName(t *testing.T, ctx context.Context, api kubernetes.Interface, uid string) string {
	t.Helper()
	list, err := api.CoreV1().Pods("asservat-connector").List(ctx, meta.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list.Items {
		if string(p.UID) == uid {
			return p.Name
		}
	}
	t.Fatal("enrolled connector Pod not found")
	return ""
}

func regionalLogs(t *testing.T, ctx context.Context, api kubernetes.Interface) {
	t.Helper()
	list, err := api.CoreV1().Pods("asservat-connector").List(ctx, meta.ListOptions{})
	if err != nil {
		return
	}
	for _, p := range list.Items {
		for _, s := range p.Status.ContainerStatuses {
			t.Logf("connector pod %s ready=%v restarts=%d waiting=%v", p.Name, s.Ready, s.RestartCount, s.State.Waiting != nil)
		}
		stream, err := api.CoreV1().Pods("asservat-connector").GetLogs(p.Name, &core.PodLogOptions{LimitBytes: ptr.To(int64(8 << 10))}).Stream(ctx)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(stream, 8<<10))
		stream.Close()
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "connector") || strings.HasPrefix(line, "regional") {
				t.Log("regional:", line)
			}
		}
	}
}

// qualifyRegionalExecutor checks the ADR-196 step 4 layout: the printed and
// stored join record agree, its connector protection digest is the one the
// hub staged at generation 1, and the executor composed from the settings it
// read by name (its fixed stderr line).
func qualifyRegionalExecutor(t *testing.T, ctx context.Context, admin *pgxpool.Pool, region kubernetes.Interface, offer contracts.RegionalOffer, installed kube.RegionalInstallation, peer string) {
	t.Helper()
	j := installed.Join
	if j == nil || j.Format != contracts.RegionalJoinFormat || j.PeerID != peer || j.Connector.SourceUID != installed.Source.UID || j.Executor.NamespaceUID != installed.Namespace.UID || j.Executor.AccountUID != installed.Account.UID || "sha256:"+j.Executor.ImageDigest != offer.Image[strings.Index(offer.Image, "@")+1:] {
		t.Fatal("join record does not name the installed executor", j)
	}
	stored, err := region.CoreV1().ConfigMaps("asservat-connector").Get(ctx, contracts.RegionalJoinName, meta.GetOptions{})
	if err != nil || stored.Immutable == nil || !*stored.Immutable {
		t.Fatal("join record ConfigMap", err)
	}
	if decoded, e := contracts.DecodeRegionalJoin(strings.NewReader(stored.Data[contracts.RegionalJoinFile])); e != nil || !reflect.DeepEqual(decoded, *j) {
		t.Fatal("stored join record differs from the printed one", e)
	}
	var raw string
	if err = admin.QueryRow(ctx, `SELECT configuration::text FROM connector_identity_profile WHERE root_id=$1 AND peer_id=$2`, offer.PermissionRootID, peer).Scan(&raw); err != nil {
		t.Fatal("staged profile", err)
	}
	var staged value.ConnectorCredentialProfile
	if json.Unmarshal([]byte(raw), &staged) != nil || hex.EncodeToString(staged.ProtectionDigest[:]) != j.Connector.ProtectionDigest || staged.Revision.UID != j.Connector.SourceUID {
		t.Fatal("join record's connector protection is not the staged generation 1")
	}
	t.Log("join record printed and stored; its connector protection is the staged generation 1")
	for until := time.Now().Add(2 * time.Minute); ; time.Sleep(2 * time.Second) {
		if regionalLogContains(ctx, region, "regional context start active") {
			t.Log("regional executor composed from the settings it read by name")
			// ADR-197 spike part B: the first hub conversation of each purpose.
			for _, line := range regionalLogLines(ctx, region, "connector lifecycle ") {
				t.Log("regional:", line)
			}
			return
		}
		if time.Now().After(until) {
			// Not fatal: the hub-side join does not depend on it, and still
			// runs and reports.
			regionalLogs(t, ctx, region)
			t.Error("regional executor did not compose")
			return
		}
	}
}

// qualifyRegionalJoin runs the hub-side join twice (ADR-196 step 5): the
// rerun is exact, the catalog holds the printed entry (one per joined
// workload cluster, so index entries), and the hub-api
// restarts its container in the same Pod, reads the entry at start and is
// Ready again.
func qualifyRegionalJoin(t *testing.T, ctx context.Context, hub, hubObserver kubernetes.Interface, hubKubeconfig, namespace, installation string, join contracts.RegionalJoin, index int) {
	t.Helper()
	raw, err := json.Marshal(join)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "regional-join.json")
	if os.WriteFile(file, raw, 0o600) != nil {
		t.Fatal("join file")
	}
	owner := "asservat-" + strings.ReplaceAll(installation, "-", "") + "-owner"
	before := hubAPIRestarts(t, ctx, hub, namespace, owner)
	args := []string{"--kubeconfig", hubKubeconfig, "--namespace", namespace, "--join", file}
	var first, second bytes.Buffer
	if err = bootstrap.RunInstallerClusterJoin(ctx, args, &first); err != nil {
		t.Fatal("installer-cluster-join", err)
	}
	if err = bootstrap.RunInstallerClusterJoin(ctx, args, &second); err != nil || !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("installer-cluster-join rerun changed the join", err)
	}
	var entry contracts.OwnerPublicCluster
	if json.Unmarshal(first.Bytes(), &entry) != nil || entry.ClusterID != join.ClusterID || entry.Topology.TargetClusterID != join.ClusterID || entry.Capability.Source.UID == "" || entry.WorkTrust.Source.UID == "" {
		t.Fatal("join output")
	}
	stored, err := hub.CoreV1().ConfigMaps(namespace).Get(ctx, contracts.OwnerClusterCatalogName(installation), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := contracts.DecodeOwnerClusterCatalog(strings.NewReader(stored.Data[contracts.OwnerClusterCatalogFile]))
	if err != nil || len(catalog.Clusters) != index || !slices.ContainsFunc(catalog.Clusters, func(c contracts.OwnerPublicCluster) bool { return reflect.DeepEqual(c, entry) }) {
		t.Fatal("catalog does not hold the joined entry", err)
	}
	t.Log("installer-cluster-join wrote the slot's sources, topology and catalog entry; the rerun was exact")
	for until := time.Now().Add(3 * time.Minute); ; time.Sleep(2 * time.Second) {
		restarts, ready := hubAPIState(t, ctx, hub, namespace, owner)
		if restarts > before && ready {
			t.Log("hub-api restarted its process on the catalog change and is Ready with the joined entry")
			return
		}
		if time.Now().After(until) {
			installedProcessDiagnostics(t, ctx, hubObserver, namespace, owner)
			t.Fatal("hub-api did not restart and accept the joined entry", restarts, before, ready)
		}
	}
}

func hubAPIRestarts(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, owner string) int32 {
	t.Helper()
	restarts, ready := hubAPIState(t, ctx, api, namespace, owner)
	if !ready {
		t.Fatal("hub-api not Ready before the join")
	}
	return restarts
}

// hubAPIState is the single owner Pod's container restart count and Ready.
func hubAPIState(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, owner string) (int32, bool) {
	t.Helper()
	d, err := api.AppsV1().Deployments(namespace).Get(ctx, owner, meta.GetOptions{})
	if err != nil {
		return -1, false
	}
	list, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: meta.FormatLabelSelector(d.Spec.Selector)})
	if err != nil || len(list.Items) != 1 || len(list.Items[0].Status.ContainerStatuses) == 0 {
		return -1, false
	}
	p := list.Items[0]
	ready := false
	for _, c := range p.Status.Conditions {
		if c.Type == core.PodReady && c.Status == core.ConditionTrue {
			ready = true
		}
	}
	return p.Status.ContainerStatuses[0].RestartCount, ready
}

func regionalLogLines(ctx context.Context, api kubernetes.Interface, prefix string) []string {
	var out []string
	list, err := api.CoreV1().Pods("asservat-connector").List(ctx, meta.ListOptions{})
	if err != nil {
		return nil
	}
	for _, p := range list.Items {
		b, err := api.CoreV1().Pods("asservat-connector").GetLogs(p.Name, &core.PodLogOptions{LimitBytes: ptr.To(int64(64 << 10))}).DoRaw(ctx)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, prefix) {
				out = append(out, line)
			}
		}
	}
	return out
}

func regionalLogContains(ctx context.Context, api kubernetes.Interface, want string) bool {
	list, err := api.CoreV1().Pods("asservat-connector").List(ctx, meta.ListOptions{})
	if err != nil {
		return false
	}
	for _, p := range list.Items {
		for _, previous := range []bool{false, true} {
			b, err := api.CoreV1().Pods("asservat-connector").GetLogs(p.Name, &core.PodLogOptions{Previous: previous, LimitBytes: ptr.To(int64(64 << 10))}).DoRaw(ctx)
			if err == nil && strings.Contains(string(b), want) {
				return true
			}
		}
	}
	return false
}

func nodeInternalIP(t *testing.T, ctx context.Context, api kubernetes.Interface, uid string) string {
	t.Helper()
	nodes, err := api.CoreV1().Nodes().List(ctx, meta.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes.Items {
		if string(n.UID) != uid {
			continue
		}
		for _, a := range n.Status.Addresses {
			if a.Type == core.NodeInternalIP && net.ParseIP(a.Address) != nil {
				return a.Address
			}
		}
	}
	t.Fatal("hub node address missing")
	return ""
}

// qualifyRegionalCapacity is ADR-197's native run: the hub-api recorded the
// join's write-once cluster qualification, the region holds a v2 standby on
// the owner's operation port, and after the operator adds a regional budget
// policy, a labeled regional workload and its maintainer binding, the
// hub-worker enrolls that workload through v2 to ready_at with a fresh binding.
// Workload cluster index n adds its own policy, binding and pool slot; the
// pool then holds n revisions.
func qualifyRegionalCapacity(t *testing.T, ctx context.Context, admin *pgxpool.Pool, hub, hubObserver, region kubernetes.Interface, namespace, issuer string, journey func(cluster, namespace, workload string, deny func(bool), gone func(string)), installation string, offer contracts.RegionalOffer, installed kube.RegionalInstallation, index int, existing *regionalPrepared) {
	t.Helper()
	j := installed.Join
	if j == nil || j.Capacity == nil || !slices.Equal(j.Capacity.Keys, slices.Sorted(slices.Values(offer.Capacity.Keys))) {
		t.Fatal("join record lacks the region's capacity assertion")
	}
	probe, guard := kube.RegionalCapacityNames("asservat-connector")
	if _, err := region.CoreV1().ServiceAccounts(probe).Get(ctx, kube.CapacityProbeAccount, meta.GetOptions{}); err != nil {
		t.Fatal("regional capacity probe account", err)
	}
	if _, err := region.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, guard, meta.GetOptions{}); err != nil {
		t.Fatal("regional capacity selector guard", err)
	}
	root, cluster := offer.PermissionRootID, j.ClusterID
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	var budget *regionalBudget
	var w regionalWorkload
	if existing != nil {
		if existing.budget.cluster != cluster {
			t.Fatal("the bootstrap record's cluster differs from the join's")
		}
		budget, w = existing.budget, existing.workload
	}
	for until := time.Now().Add(2 * time.Minute); ; time.Sleep(2 * time.Second) {
		var digest []byte
		if err := admin.QueryRow(ctx, `SELECT guard_digest FROM capacity_cluster_qualification WHERE root_id=$1 AND cluster_id=$2`, root, cluster).Scan(&digest); err == nil {
			if hex.EncodeToString(digest) != j.Capacity.NamespaceGuardDigest {
				t.Fatal("qualification does not hold the join's guard digest")
			}
			break
		}
		if time.Now().After(until) {
			installedProcessDiagnostics(t, ctx, hubObserver, namespace, prefix+"-owner")
			t.Fatal("hub-api did not record the regional capacity qualification")
		}
	}
	t.Log("hub-api recorded the join's write-once capacity qualification")
	for until := time.Now().Add(2 * time.Minute); !regionalLogContains(ctx, region, "regional capacity standby active"); time.Sleep(2 * time.Second) {
		if time.Now().After(until) {
			regionalLogs(t, ctx, region)
			t.Fatal("regional capacity standby did not compose")
		}
	}
	t.Log("regional capacity standby composed")
	if existing == nil {
		budget = newRegionalBudget(t, ctx, hub, namespace, issuer, cluster, index)
		budget.addPolicy()
		w = createRegionalWorkload(t, ctx, region, offer.Image, "regional-apps")
		budget.addBinding(w)
		t.Log("operator added the regional budget policy, pool slot, workload and maintainer binding")
	}
	ns, app := w.ns, w.app
	client, base, binding, bindingName := budget.client, budget.base, budget.binding, budget.bindingName
	diagnose := func() {
		installedProcessDiagnostics(t, ctx, hubObserver, namespace, prefix+"-worker", prefix+"-owner", kube.FederationWorkloadName(installation))
		regionalLogs(t, ctx, region)
		permissionScopeDiagnostics(t, ctx, admin, root)
	}
	bindingRow := `FROM capacity_workload w JOIN context_storage_binding b ON b.root_id=w.root_id AND b.allocation_id=w.allocation_id
 WHERE w.root_id=$1 AND w.cluster_id=$2 AND w.namespace_uid=$3 AND w.workload_uid=$4`
	for until := time.Now().Add(5 * time.Minute); ; time.Sleep(time.Second) {
		var ready bool
		e := admin.QueryRow(ctx, `SELECT w.ready_at IS NOT NULL `+bindingRow, root, cluster, string(ns.UID), string(app.UID)).Scan(&ready)
		if e == nil && ready {
			break
		}
		if time.Now().After(until) {
			diagnose()
			t.Fatal("regional workload did not reach ready_at", e, ready)
		}
	}
	// ADR-200: admission records a refresh demand for a ready workload, and the
	// hub-worker's demand lane refreshes its binding back to back. Discovery
	// refreshes a regional binding once per pass, which takes minutes. Over 15 s
	// the lane must refresh at least twice (a refresh takes about 3.3 s; three
	// left no margin in native108/118), and at least one sample must leave the
	// one second of freshness the investigation's wait asks for. The fast
	// feature fixture leaves the first cluster's demand lane to the chain run.
	demanded := installedRegionalInstallerChecks(index)
	if demanded {
		if _, err := admin.Exec(ctx, `SELECT demand_capacity_refresh($1,$2,$3,$4,'Deployment',$5,$6)`, root, cluster, string(ns.UID), ns.Name, app.Name, string(app.UID)); err != nil {
			t.Fatal("regional refresh demand", err)
		}
		observed, usable := map[time.Time]bool{}, 0
		for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(250 * time.Millisecond) {
			var at time.Time
			var left float64
			if err := admin.QueryRow(ctx, `SELECT b.observed_at,EXTRACT(EPOCH FROM b.fresh_until-clock_timestamp())::float8 `+bindingRow, root, cluster, string(ns.UID), string(app.UID)).Scan(&at, &left); err != nil {
				t.Fatal("regional binding sample", err)
			}
			observed[at.UTC()] = true
			if left >= 1 {
				usable++
			}
		}
		t.Logf("demand lane: %d distinct binding observations and %d samples with at least 1 s left in 15 s", len(observed), usable)
		if len(observed) < 3 || usable == 0 {
			diagnose()
			t.Fatal("regional binding was not refreshed on demand", len(observed), usable)
		}
	}
	var revisions int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM capacity_pool_revision WHERE root_id=$1`, root).Scan(&revisions); err != nil || revisions != index {
		t.Fatal("pool revision chain", revisions, err)
	}
	t.Logf("regional workload enrolled through v2 to ready_at; demand lane sampled: %v; the pool holds %d extension revision(s)", demanded, index)
	if journey != nil {
		// The real adapter rejects administrator/plaintext fixture pools. Read
		// through the installed scoped permission login and verified TLS,
		// as the hub does. This single monitoring connection uses the existing
		// operator/monitoring reserve and closes when this journey returns.
		permissions, closePermissions := installedPermissionObserver(t, ctx, admin, hub, namespace, installation, root)
		defer closePermissions()
		pods, err := region.CoreV1().Pods(ns.Name).List(ctx, meta.ListOptions{LabelSelector: "app=regional-app"})
		if err != nil || len(pods.Items) != 1 {
			t.Fatal("installed regional Pod observation", err)
		}
		target := authorization.Target{ClusterID: cluster, NamespaceUID: string(ns.UID), WorkloadUID: string(app.UID), PodUID: string(pods.Items[0].UID)}
		denyUID := ""
		observeDeny := func(on bool) {
			t.Helper()
			bounded, stop := context.WithTimeout(ctx, 2*time.Minute)
			defer stop()
			for bounded.Err() == nil {
				projection, err := permissions.Permissions(bounded, target)
				if err == nil && projection.DeniesComplete && time.Now().Before(projection.DeniesFreshUntil) {
					found, allowed := false, false
					for _, row := range projection.Denies {
						a := row.Audience
						if a.BasisUID == denyUID && a.Kind == "Group" && a.Issuer == issuer && a.SubjectID == installedIdentityGroup && a.Role == "workload-maintainer" {
							found = true
						}
					}
					for _, row := range projection.Allows {
						a := row.Audience
						if a.Kind == "Group" && a.Issuer == issuer && a.SubjectID == installedIdentityGroup && a.Role == "workload-maintainer" {
							allowed = true
						}
					}
					if found == on && allowed {
						return
					}
				}
				if installedJourneyPause(bounded, time.Second) != nil {
					break
				}
			}
			diagnose()
			t.Fatal("installed Deny change never reached a fresh accepted projection", on)
		}
		// The journey's revocation: a Deny binding for the same group, role
		// and scope, then its removal. The original Allow assignment stays.
		deny := func(on bool) {
			t.Helper()
			path := base + "accessbindings/" + bindingName + "-revoked"
			if !on {
				if err := client.Delete().AbsPath(path).Do(ctx).Error(); err != nil {
					t.Fatal("operator removes the revoking binding", err)
				}
				observeDeny(false)
				return
			}
			revoke := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": bindingName + "-revoked"}, "spec": map[string]any{"effect": "Deny",
				"subjects": binding["spec"].(map[string]any)["subjects"], "roles": []any{"workload-maintainer"}, "scope": binding["spec"].(map[string]any)["scope"], "reason": "installed journey revocation"}}
			body, _ := json.Marshal(revoke)
			raw, err := client.Post().AbsPath(base + "accessbindings").Body(body).DoRaw(ctx)
			var created struct {
				Metadata struct {
					UID string `json:"uid"`
				} `json:"metadata"`
			}
			if err != nil || json.Unmarshal(raw, &created) != nil || created.Metadata.UID == "" {
				t.Fatal("operator revokes the maintainer binding", err)
			}
			denyUID = created.Metadata.UID
			observeDeny(true)
		}
		func() {
			// Context-start has its own standby, separate from capacity. Retain
			// its existing closed diagnostics if the installed journey fails.
			defer func() {
				if t.Failed() {
					diagnostic, cancel := context.WithTimeout(ctx, 10*time.Second)
					defer cancel()
					regionalLogs(t, diagnostic, region)
				}
			}()
			// Deletes the reviewed Pod and waits until it is gone; the
			// Deployment replaces it under a new UID.
			gone := func(uid string) {
				pods, err := region.CoreV1().Pods(ns.Name).List(ctx, meta.ListOptions{LabelSelector: meta.FormatLabelSelector(app.Spec.Selector)})
				if err != nil {
					t.Fatal("reviewed Pod list", err)
				}
				for _, pod := range pods.Items {
					if string(pod.UID) != uid {
						continue
					}
					if err = region.CoreV1().Pods(ns.Name).Delete(ctx, pod.Name, meta.DeleteOptions{GracePeriodSeconds: ptr.To(int64(0)), Preconditions: &meta.Preconditions{UID: &pod.UID}}); err != nil {
						t.Fatal("reviewed Pod deletion", err)
					}
					for until := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
						current, err := region.CoreV1().Pods(ns.Name).Get(ctx, pod.Name, meta.GetOptions{})
						if apierrors.IsNotFound(err) || err == nil && current.UID != pod.UID {
							return
						}
						if time.Now().After(until) {
							t.Fatal("reviewed Pod not deleted", err)
						}
					}
				}
				t.Fatal("reviewed Pod not found", uid)
			}
			// ADR-228: the policy focus drives this workload and the operator's
			// hub access itself; recorded here, before its journey runs.
			installedPolicyTarget = &installedPolicyFixture{region: region, hub: client, base: base, cluster: cluster, namespace: ns.Name, workload: app.Name, binding: binding["spec"].(map[string]any)}
			journey(cluster, ns.Name, app.Name, deny, gone)
		}()
	}
}

// regionalBudget is the operator's capacity configuration for one workload
// cluster on the hub: its budget policy with a slot in the existing pool, and
// the workload's maintainer AccessBinding. Cluster index n uses its own names.
type regionalBudget struct {
	t                       *testing.T
	ctx                     context.Context
	client                  rest.Interface
	base, issuer, cluster   string
	policyName, bindingName string
	index                   int
	binding                 map[string]any
}

func newRegionalBudget(t *testing.T, ctx context.Context, hub kubernetes.Interface, namespace, issuer, cluster string, index int) *regionalBudget {
	suffix := ""
	if index > 1 {
		suffix = "-" + strconv.Itoa(index)
	}
	return &regionalBudget{t: t, ctx: ctx, client: hub.CoreV1().RESTClient(), base: "/apis/asservat.io/v1alpha1/namespaces/" + namespace + "/", issuer: issuer, cluster: cluster,
		policyName: "regional" + suffix, bindingName: "regional-maintainers" + suffix, index: index}
}

func (b *regionalBudget) amount(bytes, objects int64) map[string]int64 {
	return map[string]int64{"bytes": bytes, "objects": objects}
}

func (b *regionalBudget) addPolicy() {
	b.t.Helper()
	// The operator's regional budget: a policy for the joined cluster and its
	// slot in the existing pool, with the pool's capacity raised to fit.
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceBudgetPolicy", "metadata": map[string]any{"name": b.policyName}, "spec": map[string]any{
		"poolRef": "capacity", "scope": map[string]any{"clusterID": b.cluster, "namespaceSelector": map[string]any{"matchLabels": map[string]string{"team": "regional"}}},
		"namespaceEnvelope": map[string]int64{"maxWorkloadAccounts": 1, "maxStoredBytes": 2147483648, "maxObjects": 2000},
		// The context reserve fits the root's qualified protocol (Records: 4):
		// records = min(bytes/1544192, objects/4, 512) = 4, which is also the
		// workload's download sessions (MCP, browser, Stop). A larger reserve is
		// refused at reservation as above the qualified protocol ceiling.
		"workload": map[string]any{"protected": b.amount(1073741824, 1000), "hardLimit": b.amount(2147483648, 2000), "contextReserve": b.amount(4*1544192, 16),
			"dump":                   map[string]int64{"burst": 1, "minimumIntervalSeconds": 900, "maxStartsPerRollingHour": 2, "maxInputBytesPerRollingHour": 4294967296},
			"maxConcurrentExpensive": 1, "maxQueuedExpensive": 1, "maxQueueAgeSeconds": 30, "upload": map[string]int64{"bytesPerSecond": 33554432, "burstBytes": 4194304}, "maxUploadRequestsPerSecond": 20, "maxSpoolBytes": 2147483648, "onFull": "RejectNewExpensive"},
		"node": map[string]any{"maxConcurrentExpensive": 2, "maxQueuedExpensive": 10, "upload": map[string]int64{"bytesPerSecond": 67108864, "burstBytes": 8388608}, "maxSpoolBytes": 4294967296, "impactProfileRef": "standard-node", "unhealthySamples": 3, "sampleIntervalSeconds": 5, "recoveryHealthySeconds": 60}}}
	body, _ := json.Marshal(policy)
	if err := b.client.Post().AbsPath(b.base + "evidencebudgetpolicies").Body(body).Do(b.ctx).Error(); err != nil {
		b.t.Fatal("operator regional budget policy", err)
	}
	raw, err := b.client.Get().AbsPath(b.base + "evidencestoragepools/capacity").DoRaw(b.ctx)
	if err != nil {
		b.t.Fatal(err)
	}
	var pool map[string]any
	if json.Unmarshal(raw, &pool) != nil {
		b.t.Fatal("pool")
	}
	spec := pool["spec"].(map[string]any)
	spec["capacity"] = b.amount(137438953472+int64(b.index)*1073741824, 100000+int64(b.index)*1000)
	spec["protectedAllocations"] = append(spec["protectedAllocations"].([]any), map[string]any{"budgetPolicyRef": b.policyName, "workloadSlots": 1, "protectedPerWorkload": b.amount(1073741824, 1000)})
	body, _ = json.Marshal(pool)
	if err = b.client.Put().AbsPath(b.base + "evidencestoragepools/capacity").Body(body).Do(b.ctx).Error(); err != nil {
		b.t.Fatal("operator pool extension", err)
	}
}

func (b *regionalBudget) addBinding(w regionalWorkload) {
	b.t.Helper()
	roles := []any{"workload-maintainer"}
	if installedJourneyFocus() == "share" || installedJourneyFocus() == "browser" {
		// ADR-232: the developer group also owns the workload's evidence, so
		// its captures' retained audience includes the evidence-owner role.
		// The browser focus shares from the console session.
		roles = append(roles, "evidence-owner")
	}
	b.binding = map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": b.bindingName}, "spec": map[string]any{"effect": "Allow",
		"subjects": []any{map[string]any{"kind": "Group", "issuer": b.issuer, "id": "synthetic-group"}}, "roles": roles,
		"scope":  map[string]any{"clusterID": b.cluster, "namespaceRef": map[string]any{"name": w.ns.Name, "uid": string(w.ns.UID)}, "workloads": []any{map[string]any{"kind": "Deployment", "name": w.app.Name, "uid": string(w.app.UID)}}},
		"reason": "ADR-197 native regional capacity"}}
	body, _ := json.Marshal(b.binding)
	if err := b.client.Post().AbsPath(b.base + "accessbindings").Body(body).Do(b.ctx).Error(); err != nil {
		b.t.Fatal("operator regional maintainer binding", err)
	}
}

// regionalPrepared is the fast feature fixture's workload and budget, both in
// place before the workload cluster joins.
type regionalPrepared struct {
	workload regionalWorkload
	budget   *regionalBudget
}

// regionalWorkload is the operator's labeled regional namespace and its
// Deployment, the installed journey's capture target.
type regionalWorkload struct {
	ns  *core.Namespace
	app *apps.Deployment
}

func createRegionalWorkload(t *testing.T, ctx context.Context, region kubernetes.Interface, image, name string) regionalWorkload {
	t.Helper()
	// The regional workload: a labeled namespace (the selector guard admits
	// the administrator) and a Deployment with no replicas.
	ns, err := region.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"team": "regional"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("regional workload namespace", err)
	}
	labels := map[string]string{"app": "regional-app"}
	command := []string{"/provider-proxy", "http://127.0.0.1:1", "http://127.0.0.1:1", "127.0.0.1:1"}
	if installedJourneyFocus() == "logresource" {
		// ADR-241: the fixture's synthetic signal workload, which writes a
		// requested line or keeps its CPU busy on demand.
		command = []string{"/provider-proxy", "signals"}
	}
	// One running replica the installed journey captures from: the product
	// image's idle proxy under a restricted security context.
	app, err := region.AppsV1().Deployments(ns.Name).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "regional-app"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: labels},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{AutomountServiceAccountToken: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(3)),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Containers: []core.Container{{Name: "app", Image: image, ImagePullPolicy: core.PullIfNotPresent, Command: command,
				Resources:       core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("5m"), core.ResourceMemory: resource.MustParse("16Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}},
				SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("regional workload", err)
	}
	return regionalWorkload{ns: ns, app: app}
}

// permissionScopeDiagnostics shows why a maintainer scope may be missing from
// the capacity scope reader: a basis not seen in the current stream sequence,
// assignment churn, or unacknowledged activation audits (ADR-197 run 19b).
func permissionScopeDiagnostics(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT b.basis_key,b.resource_version,b.generation,b.seen_sequence,s.sequence,
 count(a.id) FILTER (WHERE a.retired_at IS NULL),count(a.id) FILTER (WHERE a.retired_at IS NOT NULL),
 count(a.id) FILTER (WHERE a.retired_at IS NULL AND au.acknowledged_at IS NULL)
 FROM permission_basis b JOIN permission_stream s ON s.id=b.stream_id
 LEFT JOIN permission_assignment a ON a.stream_id=b.stream_id AND a.basis_key=b.basis_key
 LEFT JOIN authority_audit au ON au.id=a.activation_audit_id
 WHERE b.stream_id=$1 GROUP BY b.basis_key,b.resource_version,b.generation,b.seen_sequence,s.sequence ORDER BY b.basis_key`, root)
	if err != nil {
		t.Log("diagnostics: permission bases", err)
		return
	}
	for rows.Next() {
		var key, version string
		var generation, seen, sequence, live, retired, unacknowledged int64
		if rows.Scan(&key, &version, &generation, &seen, &sequence, &live, &retired, &unacknowledged) == nil {
			t.Logf("diagnostics: basis %s rv=%s gen=%d seen=%d stream=%d live=%d retired=%d unacknowledged=%d", key, version, generation, seen, sequence, live, retired, unacknowledged)
		}
	}
	rows.Close()
	var pending int64
	if admin.QueryRow(ctx, `SELECT count(*) FROM authority_audit WHERE stream_id=$1 AND acknowledged_at IS NULL`, root).Scan(&pending) == nil {
		t.Logf("diagnostics: %d unacknowledged authority audits", pending)
	}
}
