package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

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
func regionalEnrollmentDiagnostics(t *testing.T, ctx context.Context, admin *pgxpool.Pool, installation, root, peer string) {
	t.Helper()
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var state []byte
	err := admin.QueryRow(call, `WITH
 profile AS (SELECT accepted_id,suspended,fenced,blocked FROM connector_identity_profile WHERE root_id=$2 AND peer_id=$3),
 processes AS (SELECT id,accepted_at,serving,retired_at,run_until FROM connector_identity_process WHERE root_id=$2 AND peer_id=$3),
 leaves AS (SELECT usage,provider_started,issued IS NOT NULL AS certificate_issued,activated_at,detached_at,certificate_not_after FROM connector_credential_attempt WHERE root_id=$2 AND peer_id=$3),
 checkpoints AS (SELECT
  EXISTS(SELECT 1 FROM profile) AS profile_present,
  EXISTS(SELECT 1 FROM profile WHERE accepted_id IS NOT NULL AND NOT suspended AND NOT fenced AND NOT blocked) AS profile_accepted,
  EXISTS(SELECT 1 FROM processes WHERE accepted_at IS NOT NULL AND retired_at IS NULL AND clock_timestamp()<run_until) AS process_accepted,
  EXISTS(SELECT 1 FROM leaves WHERE usage='client' AND activated_at IS NOT NULL AND detached_at IS NULL AND clock_timestamp()<certificate_not_after) AS client_leaf_active,
  EXISTS(SELECT 1 FROM leaves WHERE usage='server' AND activated_at IS NOT NULL AND detached_at IS NULL AND clock_timestamp()<certificate_not_after) AS server_leaf_active)
 SELECT jsonb_build_object(
  'stage',CASE WHEN NOT profile_accepted THEN 'profile-acceptance-pending' WHEN NOT process_accepted THEN 'process-admission-pending'
   WHEN NOT client_leaf_active THEN 'client-leaf-pending' WHEN NOT server_leaf_active THEN 'server-leaf-pending'
   ELSE 'paired-process-not-observed' END,
  'fleet_trust_current',EXISTS(SELECT 1 FROM fleet_current_trust WHERE installation_id=$1 AND NOT suspended AND NOT recovery_blocked AND clock_timestamp()<fresh_until),
  'profile_present',profile_present,'profile_accepted',profile_accepted,
  'profile_suspended',EXISTS(SELECT 1 FROM profile WHERE suspended),
  'profile_fenced',EXISTS(SELECT 1 FROM profile WHERE fenced),'profile_blocked',EXISTS(SELECT 1 FROM profile WHERE blocked),
  'source_capacity',(SELECT jsonb_build_object('root_present',true,'root_current',clock_timestamp()<valid_until,
    'profiles',profiles,'profile_limit',profile_limit,'source_transitions',source_transitions,
    'source_transition_limit',source_transition_limit,'backing_pending',pending_id IS NOT NULL)
    FROM connector_identity_root WHERE root_id=$2),
  'processes',(SELECT count(*) FROM processes),'process_accepted',process_accepted,
  'serving_processes',(SELECT count(*) FROM processes WHERE serving AND retired_at IS NULL),
  'client_sign_attempts',(SELECT count(*) FROM leaves WHERE usage='client'),
  'server_sign_attempts',(SELECT count(*) FROM leaves WHERE usage='server'),
  'provider_started',(SELECT count(*) FROM leaves WHERE provider_started),
  'certificates_issued',(SELECT count(*) FROM leaves WHERE certificate_issued),
  'client_leaf_active',client_leaf_active,'server_leaf_active',server_leaf_active) FROM checkpoints`, installation, root, peer).Scan(&state)
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

// regionalBudget is the operator's capacity configuration for one workload
// cluster on the hub: its budget policy with a slot in the existing pool, and
// the workload's maintainer AccessBinding. Cluster index n uses its own names.
type regionalBudget struct {
	t                      *testing.T
	ctx                    context.Context
	client                 rest.Interface
	base, issuer, cluster  string
	subjectKind, subjectID string
	bindingName            string
	index                  int
	binding                map[string]any
}

func newRegionalBudget(t *testing.T, ctx context.Context, hub kubernetes.Interface, namespace, issuer, cluster string, index int) *regionalBudget {
	suffix := ""
	if index > 1 {
		suffix = "-" + strconv.Itoa(index)
	}
	b := &regionalBudget{t: t, ctx: ctx, client: hub.CoreV1().RESTClient(), base: "/apis/asservat.io/v1alpha1/namespaces/" + namespace + "/", issuer: issuer, cluster: cluster,
		bindingName: "regional-maintainers" + suffix, index: index}
	return b
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
