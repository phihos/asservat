package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// One read-only snapshot of this exact bootstrap/peer names the last durable
// checkpoint. Only fixed labels, booleans and counts leave SQL: never records,
// identifiers, credentials, certificate bytes, payload digests or raw errors.
func regionalEnrollmentDiagnostics(t *testing.T, ctx context.Context, admin *pgxpool.Pool, installation, bootstrap, root, peer string) {
	t.Helper()
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var state []byte
	err := admin.QueryRow(call, `WITH
 intent AS (SELECT issued_at,credential_recorded_at,audit_acknowledged_at FROM fleet_bootstrap_intent WHERE installation_id=$1 AND id=$2),
 slot AS (SELECT revoked,not_before,not_after,claimed_at,claim_acknowledged_at FROM fleet_bootstrap WHERE installation_id=$1 AND id=$2),
 activation AS (SELECT lineage_id,audit_acknowledged_at,activated_at FROM cluster_bootstrap_activation WHERE installation_id=$1 AND bootstrap_id=$2),
 profile AS (SELECT accepted_id,suspended,fenced,blocked FROM connector_identity_profile WHERE root_id=$3 AND peer_id=$4),
 processes AS (SELECT id,accepted_at,serving,retired_at,run_until FROM connector_identity_process WHERE root_id=$3 AND peer_id=$4),
 leaves AS (SELECT usage,provider_started,issued IS NOT NULL AS certificate_issued,activated_at,detached_at,certificate_not_after FROM connector_credential_attempt WHERE root_id=$3 AND peer_id=$4),
 checkpoints AS (SELECT
  EXISTS(SELECT 1 FROM intent) AS intent_present,
  EXISTS(SELECT 1 FROM intent WHERE credential_recorded_at IS NOT NULL) AS credential_recorded,
  EXISTS(SELECT 1 FROM intent WHERE audit_acknowledged_at IS NOT NULL) AS issue_audited,
  EXISTS(SELECT 1 FROM intent WHERE issued_at IS NOT NULL) AS issued,
  EXISTS(SELECT 1 FROM slot) AS slot_present,
  EXISTS(SELECT 1 FROM slot WHERE revoked) AS revoked,
  EXISTS(SELECT 1 FROM slot WHERE clock_timestamp()>=not_before AND clock_timestamp()<not_after) AS original_slot_current,
  EXISTS(SELECT 1 FROM slot WHERE claimed_at IS NOT NULL) AS claimed,
  EXISTS(SELECT 1 FROM slot WHERE claim_acknowledged_at IS NOT NULL) AS claim_audited,
  EXISTS(SELECT 1 FROM activation) AS activation_reserved,
  EXISTS(SELECT 1 FROM activation WHERE audit_acknowledged_at IS NOT NULL) AS activation_audited,
  EXISTS(SELECT 1 FROM activation WHERE activated_at IS NOT NULL) AS activated,
  EXISTS(SELECT 1 FROM profile) AS profile_present,
  EXISTS(SELECT 1 FROM profile WHERE accepted_id IS NOT NULL AND NOT suspended AND NOT fenced AND NOT blocked) AS profile_accepted,
  EXISTS(SELECT 1 FROM processes WHERE accepted_at IS NOT NULL AND retired_at IS NULL AND clock_timestamp()<run_until) AS process_accepted,
  EXISTS(SELECT 1 FROM leaves WHERE usage='client' AND activated_at IS NOT NULL AND detached_at IS NULL AND clock_timestamp()<certificate_not_after) AS client_leaf_active,
  EXISTS(SELECT 1 FROM leaves WHERE usage='server' AND activated_at IS NOT NULL AND detached_at IS NULL AND clock_timestamp()<certificate_not_after) AS server_leaf_active)
 SELECT jsonb_build_object(
  'stage',CASE WHEN NOT slot_present THEN 'issued-slot-missing'
   WHEN NOT issued THEN 'issue-pending' WHEN revoked THEN 'bootstrap-revoked'
   WHEN NOT claimed THEN 'bootstrap-unclaimed' WHEN NOT claim_audited THEN 'claim-audit-pending'
   WHEN NOT activation_reserved THEN 'activation-reservation-missing'
   WHEN NOT activation_audited THEN 'activation-audit-pending' WHEN NOT activated THEN 'activation-pending'
   WHEN NOT profile_accepted THEN 'profile-acceptance-pending' WHEN NOT process_accepted THEN 'process-admission-pending'
   WHEN NOT client_leaf_active THEN 'client-leaf-pending' WHEN NOT server_leaf_active THEN 'server-leaf-pending'
   ELSE 'paired-process-not-observed' END,
  'intent_present',intent_present,'credential_recorded',credential_recorded,'issue_audited',issue_audited,'issued',issued,
  'slot_present',slot_present,'revoked',revoked,'original_slot_current',original_slot_current,'claimed',claimed,'claim_audited',claim_audited,
  'activation_reserved',activation_reserved,'activation_audited',activation_audited,'activated',activated,
  'fleet_trust_current',EXISTS(SELECT 1 FROM fleet_current_trust WHERE installation_id=$1 AND NOT suspended AND NOT recovery_blocked AND clock_timestamp()<fresh_until),
  'registered_peer',EXISTS(SELECT 1 FROM fleet_peer WHERE installation_id=$1 AND peer_id=$4 AND enabled),
  'profile_present',profile_present,'profile_accepted',profile_accepted,
  'profile_suspended',EXISTS(SELECT 1 FROM profile WHERE suspended),
  'profile_fenced',EXISTS(SELECT 1 FROM profile WHERE fenced),'profile_blocked',EXISTS(SELECT 1 FROM profile WHERE blocked),
  'source_capacity',(SELECT jsonb_build_object('root_present',true,'root_current',clock_timestamp()<valid_until,
    'profiles',profiles,'profile_limit',profile_limit,'source_transitions',source_transitions,
    'source_transition_limit',source_transition_limit,'backing_pending',pending_id IS NOT NULL)
    FROM connector_identity_root WHERE root_id=$3),
  'lineage_present',EXISTS(SELECT 1 FROM activation a JOIN cluster_enrollment_lineage l USING(lineage_id)),
  'lineage_fenced',EXISTS(SELECT 1 FROM activation a JOIN cluster_enrollment_lineage l USING(lineage_id) WHERE l.fenced IS NOT NULL),
  'generation_one_present',EXISTS(SELECT 1 FROM activation a JOIN cluster_enrollment_credential c USING(lineage_id) WHERE c.generation=1),
  'generation_one_used',EXISTS(SELECT 1 FROM activation a JOIN cluster_enrollment_credential c USING(lineage_id) WHERE c.generation=1 AND c.first_used_at IS NOT NULL),
  'legacy_public_sign_attempts',(SELECT count(*) FROM fleet_certificate_issue WHERE installation_id=$1 AND bootstrap_id=$2),
  'processes',(SELECT count(*) FROM processes),'process_accepted',process_accepted,
  'serving_processes',(SELECT count(*) FROM processes WHERE serving AND retired_at IS NULL),
  'client_sign_attempts',(SELECT count(*) FROM leaves WHERE usage='client'),
  'server_sign_attempts',(SELECT count(*) FROM leaves WHERE usage='server'),
  'provider_started',(SELECT count(*) FROM leaves WHERE provider_started),
  'certificates_issued',(SELECT count(*) FROM leaves WHERE certificate_issued),
  'client_leaf_active',client_leaf_active,'server_leaf_active',server_leaf_active) FROM checkpoints`, installation, bootstrap, root, peer).Scan(&state)
	if err != nil {
		code := "unavailable"
		var sqlError *pgconn.PgError
		if errors.As(err, &sqlError) {
			code = sqlError.Code
		}
		t.Logf("regional enrollment checkpoint: diagnostic=%s canceled=%v", code, call.Err() != nil)
		return
	}
	t.Logf("regional enrollment checkpoint: %s", state)
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
		// The head holds startup; the tail holds the events at the failure.
		for _, o := range []core.PodLogOptions{{Timestamps: true, LimitBytes: ptr.To(int64(8 << 10))}, {Timestamps: true, TailLines: ptr.To(int64(300)), LimitBytes: ptr.To(int64(64 << 10))}} {
			stream, err := api.CoreV1().Pods("asservat-connector").GetLogs(p.Name, &o).Stream(ctx)
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(stream, 64<<10))
			stream.Close()
			for _, line := range strings.Split(string(b), "\n") {
				// Kubelet timestamps prefix each line; filter on the text after it.
				_, text, _ := strings.Cut(line, " ")
				if strings.HasPrefix(text, "connector") || strings.HasPrefix(text, "regional") {
					t.Log("regional:", line)
				}
			}
		}
		// Live lines from the whole log: capacity polling pushes them out of
		// the head and tail windows above.
		if stream, err := api.CoreV1().Pods("asservat-connector").GetLogs(p.Name, &core.PodLogOptions{Timestamps: true, LimitBytes: ptr.To(int64(16 << 20))}).Stream(ctx); err == nil {
			b, _ := io.ReadAll(io.LimitReader(stream, 16<<20))
			stream.Close()
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, " live") {
					t.Log("regional live:", line)
				}
			}
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

// regionalBudget is the operator's capacity configuration for one workload
// cluster on the hub: its budget policy with a slot in the existing pool, and
// the workload's maintainer AccessBinding. Cluster index n uses its own names.
type regionalBudget struct {
	t                       *testing.T
	ctx                     context.Context
	client                  rest.Interface
	base, issuer, cluster   string
	subjectKind, subjectID  string
	policyName, bindingName string
	index                   int
	binding                 map[string]any
}

func newRegionalBudget(t *testing.T, ctx context.Context, hub kubernetes.Interface, namespace, issuer, cluster string, index int) *regionalBudget {
	suffix := ""
	if index > 1 {
		suffix = "-" + strconv.Itoa(index)
	}
	b := &regionalBudget{t: t, ctx: ctx, client: hub.CoreV1().RESTClient(), base: "/apis/asservat.io/v1alpha1/namespaces/" + namespace + "/", issuer: issuer, cluster: cluster,
		policyName: "regional" + suffix, bindingName: "regional-maintainers" + suffix, index: index}
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") == "1" || os.Getenv("ASSERVAT_HELM_BUNDLED_IDENTITY") == "1" {
		if index != 1 {
			t.Fatal("the declared context trial covers one regional cluster")
		}
		b.policyName = "trial-region"
	}
	return b
}

func (b *regionalBudget) amount(bytes, objects int64) map[string]int64 {
	return map[string]int64{"bytes": bytes, "objects": objects}
}

// installedRegionalContextReserve is the workload's context reserve: each
// focus of a multi-focus run adds its own (installedEachFocus).
func installedRegionalContextReserve() (bytes, objects int64) {
	installedEachFocus(func() {
		b, o := installedFocusContextReserve()
		bytes, objects = bytes+b, objects+o
	})
	return bytes, objects
}

func installedFocusContextReserve() (bytes, objects int64) {
	bytes, objects = 8*1544192, 32
	if installedLogsFocus() {
		return installedKeptRuns() * installedLogsQueryUnits * 1544192, installedKeptRuns() * installedLogsQueryUnits * 4
	}
	if installedRecordingFocus() {
		bytes = 8 * (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	}
	if installedJourneyFocus() == "manual-raw" {
		// Existing byte reserve already covers sixteen protocol records;
		// accept their sixty-four object slots before any capture/query.
		objects = 64
	}
	if installedJourneyFocus() == "manual-profile" {
		// Fund four independently approved 16MiB captures (CPU, busy, missing,
		// Stop), including each immutable history artifact. Multipart backing
		// remains charged after successful/refused collection until cleanup.
		profile := artifact.Registration{NativeLimit: 16 << 20}
		stream := artifact.StreamingPlan{Registration: profile}
		history := artifact.Registration{NativeLimit: capture.MaxHistoryParameters}
		bytes = 4 * (profile.ReservedBytes() + stream.TemporaryBytes() + history.ReservedBytes())
		objects = 4 * (4 + 1 + int64(stream.PartLimit()) + 4)
	}
	return bytes, objects
}

func (b *regionalBudget) addPolicy() {
	b.t.Helper()
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") == "1" || os.Getenv("ASSERVAT_HELM_BUNDLED_IDENTITY") == "1" {
		b.addDeclaredPolicy()
		return
	}
	// The operator's regional budget: a policy for the joined cluster and its
	// slot in the existing pool, with the pool's capacity raised to fit.
	// Ongoing sources, re-arms, Saves and incident snapshots share the default
	// eight-record/32-object reserve. Manual profiles explicitly fund their
	// four-capture journey and history before any admission takes place.
	reserveBytes, reserveObjects := installedRegionalContextReserve()
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceBudgetPolicy", "metadata": map[string]any{"name": b.policyName}, "spec": map[string]any{
		"poolRef": "capacity", "scope": map[string]any{"clusterID": b.cluster, "namespaceSelector": map[string]any{"matchLabels": map[string]string{"team": "regional"}}},
		"namespaceEnvelope": map[string]int64{"maxWorkloadAccounts": 1, "maxStoredBytes": 2147483648, "maxObjects": 2000},
		// records = min(bytes/1544192, objects/4, 512): normally 8, manual
		// profile 12. Both fit their configured root's qualified record ceiling;
		// enrollment refuses any reserve above that ceiling.
		"workload": map[string]any{"protected": b.amount(1073741824, 1000), "hardLimit": b.amount(2147483648, 2000), "contextReserve": b.amount(reserveBytes, reserveObjects),
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
	spec["capacity"] = b.amount(137438953472+int64(b.index)*1073741824, installedPoolCapacityObjects()+int64(b.index)*1000)
	spec["protectedAllocations"] = append(spec["protectedAllocations"].([]any), map[string]any{"budgetPolicyRef": b.policyName, "workloadSlots": 1, "protectedPerWorkload": b.amount(1073741824, 1000)})
	body, _ = json.Marshal(pool)
	if err = b.client.Put().AbsPath(b.base + "evidencestoragepools/capacity").Body(body).Do(b.ctx).Error(); err != nil {
		b.t.Fatal("operator pool extension", err)
	}
}

// The guide's operator step derives a regional policy from the original public
// policy and spends one pre-reserved pool slot. It never raises backend/pool
// capacity to make the test fit or changes the root's accepted record ceiling.
func (b *regionalBudget) addDeclaredPolicy() {
	b.t.Helper()
	profile := helmContextTrialProfile(b.t).Public.Capacity
	spec := *profile.PolicySpec
	spec.Scope.ClusterID = b.cluster
	spec.NamespaceEnvelope = wire.CapacityNamespaceEnvelope{MaxWorkloadAccounts: 1, MaxStoredBytes: spec.Workload.HardLimit.Bytes, MaxObjects: spec.Workload.HardLimit.Objects}
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceBudgetPolicy", "metadata": map[string]any{"name": b.policyName}, "spec": spec}
	body, err := json.Marshal(policy)
	if err != nil {
		b.t.Fatal("declared regional policy", err)
	}
	if err = b.client.Post().AbsPath(b.base + "evidencebudgetpolicies").Body(body).Do(b.ctx).Error(); err != nil {
		b.t.Fatal("operator declared regional policy", err)
	}
	path := b.base + "evidencestoragepools/" + profile.Pool
	raw, err := b.client.Get().AbsPath(path).DoRaw(b.ctx)
	var pool map[string]any
	if err != nil || json.Unmarshal(raw, &pool) != nil {
		b.t.Fatal("operator declared pool read", err)
	}
	poolSpec, ok := pool["spec"].(map[string]any)
	if !ok {
		b.t.Fatal("operator declared pool spec")
	}
	allocations, ok := poolSpec["protectedAllocations"].([]any)
	if !ok {
		b.t.Fatal("operator declared pool allocations")
	}
	poolSpec["protectedAllocations"] = append(allocations, wire.CapacityProtectedAllocation{BudgetPolicyRef: b.policyName, WorkloadSlots: 1, ProtectedPerWorkload: spec.Workload.Protected})
	body, err = json.Marshal(pool)
	if err != nil {
		b.t.Fatal("operator declared pool update", err)
	}
	if err = b.client.Put().AbsPath(path).Body(body).Do(b.ctx).Error(); err != nil {
		b.t.Fatal("operator declared pool slot", err)
	}
}

// installedRegionalBindingRoles are the maintainer binding's roles. Share,
// browser and privacy inventory focuses add evidence-owner before capture.
func installedRegionalBindingRoles() []any {
	roles := []any{"workload-maintainer"}
	if installedRecordingFocus() || installedLogsFocus() {
		roles = append(roles, "action-approver")
	}
	if installedAnyFocus("share") || installedAnyFocus("browser") || installedAnyFocus("privacy-inventory") || installedAnyFocus("share-retirement") {
		// ADR-232: the developer group also owns the workload's evidence, so
		// its captures' retained audience includes the evidence-owner role.
		// Browser and inventory focuses also create actual artifact shares.
		roles = append(roles, "evidence-owner")
	}
	return roles
}

func (b *regionalBudget) subjectKindValue() string {
	if b.subjectKind != "" {
		return b.subjectKind
	}
	return "Group"
}
func (b *regionalBudget) subjectIDValue() string {
	if b.subjectID != "" {
		return b.subjectID
	}
	return installedIdentityGroup
}

func (b *regionalBudget) addBinding(w regionalWorkload) {
	b.t.Helper()
	roles := installedRegionalBindingRoles()
	b.binding = map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": b.bindingName}, "spec": map[string]any{"effect": "Allow",
		"subjects": []any{map[string]any{"kind": b.subjectKindValue(), "issuer": b.issuer, "id": b.subjectIDValue()}}, "roles": roles,
		"workloads": []any{map[string]any{"kind": "Deployment", "name": w.app.Name, "uid": string(w.app.UID)}},
		"reason":    "ADR-197 native regional capacity"}}
	body, _ := json.Marshal(b.binding)
	// ADR-329: the binding lives in the workload's namespace it grants.
	if err := b.client.Post().AbsPath("/apis/asservat.io/v1alpha1/namespaces/" + w.ns.Name + "/accessbindings").Body(body).Do(b.ctx).Error(); err != nil {
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

// Only the explicit native-paced target uses the 200m qualification profile.
// Default synthetic workloads retain their original 5m request/100m limit.
func regionalWorkloadResources(nativePaced bool) core.ResourceRequirements {
	out := core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("5m"), core.ResourceMemory: resource.MustParse("16Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}}
	if nativePaced {
		out.Requests[core.ResourceCPU] = resource.MustParse("200m")
		out.Limits[core.ResourceCPU] = resource.MustParse("200m")
	}
	return out
}

func createRegionalWorkload(t *testing.T, ctx context.Context, region kubernetes.Interface, image, name string, nativePaced bool, tlsDirectories ...string) regionalWorkload {
	t.Helper()
	// The regional workload: a labeled namespace (the selector guard admits
	// the administrator) and a Deployment with no replicas.
	labels := map[string]string{"team": "regional"}
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") == "1" || os.Getenv("ASSERVAT_HELM_BUNDLED_IDENTITY") == "1" {
		selector := helmContextTrialProfile(t).Public.Capacity.PolicySpec.Scope.NamespaceSelector
		if len(selector.MatchLabels) == 0 {
			t.Fatal("context trial requires its exact declared namespace labels")
		}
		labels = selector.MatchLabels
	}
	if installedRecordingFocus() || installedLogsFocus() || os.Getenv("ASSERVAT_HELM_BUNDLED_IDENTITY") == "1" {
		labels["pod-security.kubernetes.io/enforce"] = "restricted"
	}
	ns, err := region.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: labels}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("regional workload namespace", err)
	}
	labels = map[string]string{"app": "regional-app"}
	command := []string{"/provider-proxy", "http://127.0.0.1:1", "http://127.0.0.1:1", "127.0.0.1:1"}
	if installedAnyFocus("logresource") || installedRecordingFocus() || installedLogsFocus() {
		// ADR-241: the fixture's synthetic signal workload, which writes a
		// requested line or keeps its CPU busy on demand. A pod-status focus
		// sharing the logresource installation reads the same idle workload.
		command = []string{"/provider-proxy", "signals"}
	}
	var initContainers []core.Container
	if installedLogsFocus() {
		initContainers = []core.Container{{Name: "log-init", Image: image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/provider-proxy", "signals-once"}, Resources: regionalWorkloadResources(false), SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}
	}
	var ports []core.ContainerPort
	var volumes []core.Volume
	var volumeMounts []core.VolumeMount
	if installedAnyFocusMatch(func() bool { return installedProfileFocus() || installedJourneyFocus() == "policy-profile" }) {
		command = []string{"/profile-native"}
		if installedAcceptedHeavyComparison() {
			command = append(command, "--accepted-heavy")
		}
		ports = []core.ContainerPort{{Name: "diagnostics", ContainerPort: 6060}}
	}
	if installedProfileFocus() && installedTLSProfileTransport() {
		if len(tlsDirectories) != 1 {
			t.Fatal("private TLS application fixture directory missing")
		}
		material := manualProfileTLSFixture(t, tlsDirectories[0])
		defer clear(material.Key)
		appData := map[string][]byte{"tls.crt": material.Certificate, "tls.key": material.Key}
		if installedProfileAuthorization() {
			appData["authorization"] = []byte(manualProfileAuthorizationSentinel)
		}
		if _, err := region.CoreV1().Secrets(ns.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "profile-application-tls"}, Type: core.SecretTypeTLS, Immutable: ptr.To(true), Data: appData}, meta.CreateOptions{}); err != nil {
			t.Fatal("synthetic app-only TLS Secret", err)
		}
		command = append(command, "--tls", "/run/profile-tls/tls.crt", "/run/profile-tls/tls.key")
		if installedProfileAuthorization() {
			command = append(command, "--authorization", "/run/profile-tls/authorization")
		}
		volumes = []core.Volume{{Name: "profile-tls", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "profile-application-tls", DefaultMode: ptr.To(int32(0444))}}}}
		volumeMounts = []core.VolumeMount{{Name: "profile-tls", MountPath: "/run/profile-tls", ReadOnly: true}}
	}

	// One running replica the installed journey captures from: the product
	// image's idle proxy under a restricted security context.
	app, err := region.AppsV1().Deployments(ns.Name).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "regional-app"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: labels},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{AutomountServiceAccountToken: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(3)),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Volumes:         volumes, InitContainers: initContainers, Containers: []core.Container{{Name: "app", Image: image, ImagePullPolicy: core.PullIfNotPresent, Command: command, Ports: ports, VolumeMounts: volumeMounts,
				Resources:       regionalWorkloadResources(nativePaced),
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
