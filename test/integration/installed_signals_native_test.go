package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

// installMetricsServer runs the official metrics-server image in the
// workload cluster's restricted metrics namespace, with the upstream
// manifest's RBAC and APIService and --kubelet-insecure-tls (kind's kubelet
// serving certificates are self-signed), for the ADR-241 resource phase.
func installMetricsServer(t *testing.T, ctx context.Context, region kubernetes.Interface, image string) {
	t.Helper()
	if image == "" {
		t.Fatal("logresource focus without the harness's metrics-server image")
	}
	const ns, name = "metrics", "metrics-server"
	if _, err := region.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: ns, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{}); err != nil {
		t.Fatal("metrics namespace", err)
	}
	if _, err := region.CoreV1().ServiceAccounts(ns).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{}); err != nil {
		t.Fatal("metrics-server account", err)
	}
	subject := []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: ns}}
	if _, err := region.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "fixture:metrics-server"}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"nodes/metrics"}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods", "nodes"}, Verbs: []string{"get", "list", "watch"}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal("metrics-server role", err)
	}
	for binding, role := range map[string]string{"fixture:metrics-server": "fixture:metrics-server", "fixture:metrics-server:auth-delegator": "system:auth-delegator"} {
		if _, err := region.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: binding}, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: role}, Subjects: subject}, meta.CreateOptions{}); err != nil {
			t.Fatal("metrics-server binding", binding, err)
		}
	}
	if _, err := region.RbacV1().RoleBindings("kube-system").Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "fixture-metrics-server-auth-reader"}, RoleRef: rbac.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "extension-apiserver-authentication-reader"}, Subjects: subject}, meta.CreateOptions{}); err != nil {
		t.Fatal("metrics-server auth reader", err)
	}
	labels := map[string]string{"app": name}
	if _, err := region.AppsV1().Deployments(ns).Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: labels},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{ServiceAccountName: name,
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(1000)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Volumes:         []core.Volume{{Name: "tmp", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{}}}},
			Containers: []core.Container{{Name: name, Image: image, ImagePullPolicy: core.PullIfNotPresent,
				Args:            []string{"--cert-dir=/tmp", "--secure-port=10250", "--kubelet-preferred-address-types=InternalIP", "--kubelet-use-node-status-port", "--metric-resolution=15s", "--kubelet-insecure-tls"},
				Ports:           []core.ContainerPort{{Name: "https", ContainerPort: 10250}},
				VolumeMounts:    []core.VolumeMount{{Name: "tmp", MountPath: "/tmp"}},
				ReadinessProbe:  &core.Probe{ProbeHandler: core.ProbeHandler{HTTPGet: &core.HTTPGetAction{Path: "/readyz", Port: intstr.FromString("https"), Scheme: core.URISchemeHTTPS}}, PeriodSeconds: 5},
				SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal("metrics-server Deployment", err)
	}
	if _, err := region.CoreV1().Services(ns).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: core.ServiceSpec{Selector: labels, Ports: []core.ServicePort{{Name: "https", Port: 443, TargetPort: intstr.FromString("https")}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal("metrics-server Service", err)
	}
	service, _ := json.Marshal(map[string]any{"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService", "metadata": map[string]any{"name": "v1beta1.metrics.k8s.io"},
		"spec": map[string]any{"service": map[string]any{"name": name, "namespace": ns}, "group": "metrics.k8s.io", "version": "v1beta1", "insecureSkipTLSVerify": true, "groupPriorityMinimum": 100, "versionPriority": 100}})
	if err := region.CoreV1().RESTClient().Post().AbsPath("/apis/apiregistration.k8s.io/v1/apiservices").SetHeader("Content-Type", "application/json").Body(service).Do(ctx).Error(); err != nil {
		t.Fatal("metrics APIService", err)
	}
}

const (
	installedLogPolicyName      = "regional-logs"
	installedResourcePolicyName = "regional-resources"
)

// installedLogResourcePhase qualifies the ADR-241 log and resource detectors
// on the installed product against the synthetic signal workload: a log
// policy captures exactly the Pod that writes a matching line, once, and
// re-arms after its eventWindow; a resource policy (cpuQuotaRatio above 0.5
// from the real metrics API) captures exactly the Pod whose CPU is kept busy.
// No log text appears in status. Both occurrences fit the shared workload
// burst of two.
func installedLogResourcePhase(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, f *installedPolicyFixture, digest artifact.Digest, read func(context.Context, string, any) (installedJourneyEnvelope, error), wait func(string, time.Duration, func(context.Context) bool), runningPods func() []core.Pod, started time.Time) {
	t.Helper()
	activate := func(name string, detector map[string]any) string {
		t.Helper()
		policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": name}, "spec": map[string]any{
			"target":    map[string]any{"cluster": f.cluster, "namespace": f.namespace, "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": f.workload}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
			"detectors": []any{detector},
			"when":      map[string]any{"detector": detector["id"]},
			"recipeRef": map[string]any{"name": planning.ContextRecipeName, "digest": hex.EncodeToString(digest[:])},
			"budgets":   map[string]any{"cooldown": "5m", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
			"retention": fmt.Sprintf("%ds", installedJourneyRetention), "suspended": false,
			"observation": map[string]any{"mode": "allAuthorized"},
			"evaluation":  map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"}}}
		body, _ := json.Marshal(policy)
		if err := f.hub.Post().AbsPath(f.base + "debugpolicies").Body(body).Do(ctx).Error(); err != nil {
			t.Fatal("maintainer applies the hub-held DebugPolicy", name, err)
		}
		var activated struct {
			PolicyUID string `json:"policy_uid"`
			State     string `json:"state"`
		}
		activation := map[string]string{"policy_name": name, "idempotency_key": "installed-" + name + "-activation"}
		// DelegationRequired while the envelope propagates; DetectorUnavailable
		// while the metrics API is still registering.
		wait("an active "+name+" policy", 3*time.Minute, func(poll context.Context) bool {
			reply, err := read(poll, "activate_policy", activation)
			if err != nil || reply.Status != "ok" {
				if err == nil {
					t.Logf("installed activate_policy (%s): %s", name, reply.Data)
				}
				return false
			}
			if installedJourneyDecode(reply.Data, &activated) != nil {
				t.Fatal("activation data", name)
			}
			return activated.State == "active"
		})
		t.Logf("installed signal journey: %s policy %s activated %s after start", name, activated.PolicyUID, time.Since(started).Round(time.Second))
		return activated.PolicyUID
	}
	scalar := func(query string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := admin.QueryRow(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(query, err)
		}
		return n
	}
	occurrences := func(policy string) int64 {
		return scalar(`SELECT count(*) FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2`, root, policy)
	}
	armed := func(policy, detector string, pods ...string) int64 {
		return scalar(`SELECT count(*) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2 AND detector=$3 AND armed AND pod_uid=ANY($4::text[])`, root, policy, detector, pods)
	}
	signal := func(pod core.Pod, path string, params map[string]string) {
		t.Helper()
		r := f.region.CoreV1().RESTClient().Get().AbsPath("/api/v1/namespaces/" + f.namespace + "/pods/" + pod.Name + ":8080/proxy" + path)
		for k, v := range params {
			r.Param(k, v)
		}
		if err := r.Do(ctx).Error(); err != nil {
			t.Fatal("synthetic workload signal", path, err)
		}
	}
	// One occurrence of exactly this Pod and its policy-executed capture.
	captured := func(policy, detector string, pod core.Pod, from time.Time) {
		t.Helper()
		var captureID string
		var second int64
		wait("a "+detector+" policy capture", 3*time.Minute, func(poll context.Context) bool {
			err := admin.QueryRow(poll, `SELECT coalesce(capture_id::text,''),restarts FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3 AND detector=$4`, root, policy, string(pod.UID), detector).Scan(&captureID, &second)
			return err == nil && captureID != ""
		})
		if second < from.Unix()-1 || second > time.Now().Unix() {
			t.Fatal(detector, "occurrence second outside the signal", second, from.Unix())
		}
		var executor string
		var pinned bool
		if err := admin.QueryRow(ctx, `SELECT convert_from(scope_json,'UTF8')::jsonb#>>'{executor,subject}',position($2 in convert_from(pod_pin_json,'UTF8'))>0 FROM context_capture WHERE id=$1`, captureID, string(pod.UID)).Scan(&executor, &pinned); err != nil || executor != "policy:"+policy || !pinned {
			t.Fatal(detector, "capture provenance", executor, pinned, err)
		}
		if got := occurrences(policy); got != 1 {
			t.Fatal(detector, "occurrences", got)
		}
		var status struct {
			Detector struct {
				Kind string `json:"kind"`
			} `json:"detector"`
			Recent []struct {
				Detector  string `json:"detector"`
				CaptureID string `json:"capture_id"`
				FailedAt  string `json:"failed_at"`
			} `json:"recent"`
		}
		name := installedLogPolicyName
		if detector == "resource" {
			name = installedResourcePolicyName
		}
		reply, err := read(ctx, "get_policy_status", map[string]string{"policy_name": name})
		if err != nil || reply.Status != "ok" || installedJourneyDecode(reply.Data, &status) != nil {
			t.Fatal(detector, "policy status", err, reply.Status)
		}
		if status.Detector.Kind != detector || len(status.Recent) != 1 || status.Recent[0].Detector != detector || status.Recent[0].CaptureID != captureID || status.Recent[0].FailedAt == "" || strings.Contains(string(reply.Data), "MUST-NOT-LEAK") || strings.Contains(string(reply.Data), "SYNTHETIC-PANIC") {
			t.Fatal(detector, "status", string(reply.Data))
		}
		t.Logf("installed signal journey: %s occurrence on Pod %s yielded capture %s by policy:%s, %s after start", detector, pod.Name, captureID, policy, time.Since(started).Round(time.Second))
	}
	pods := runningPods()
	var uids []string
	for _, p := range pods {
		uids = append(uids, string(p.UID))
	}

	// Log: a quiet baseline (a non-matching line), then one matching line on
	// one Pod.
	logs := activate(installedLogPolicyName, map[string]any{"id": "panics", "kind": "log", "eventWindow": "30s",
		"options": map[string]any{"stream": "both", "pattern": "SYNTHETIC-PANIC [0-9]+", "match": "regexp", "maxRecordBytes": 4096}})
	signal(pods[0], "/log", map[string]string{"line": "INFO synthetic request ok"})
	wait("the armed log baseline of all Pods", time.Minute, func(context.Context) bool { return armed(logs, "log", uids...) == int64(len(uids)) })
	if occurrences(logs) != 0 {
		t.Fatal("log policy fired without a matching line")
	}
	victim := pods[len(pods)-1]
	emitted := time.Now()
	signal(victim, "/log", map[string]string{"line": "ERROR SYNTHETIC-PANIC 42 MUST-NOT-LEAK"})
	captured(logs, "log", victim, emitted)
	// The record stays within the window for 30 s (no second occurrence),
	// then a poll with an empty window re-arms the Pod.
	wait("the re-armed log Pod after its window", 2*time.Minute, func(context.Context) bool { return armed(logs, "log", string(victim.UID)) == 1 })
	if occurrences(logs) != 1 {
		t.Fatal("log level fired twice")
	}

	// Resource: an armed baseline from real metrics, then one Pod's CPU kept
	// at its 100m limit.
	resources := activate(installedResourcePolicyName, map[string]any{"id": "busy", "kind": "resource",
		"options": map[string]any{"metric": "cpuQuotaRatio", "operator": "gt", "threshold": 0.5, "sampleInterval": "60s"}})
	wait("the armed resource baseline of all Pods", 3*time.Minute, func(context.Context) bool {
		return armed(resources, "resource", uids...) == int64(len(uids))
	})
	if occurrences(resources) != 0 {
		t.Fatal("resource policy fired on idle Pods")
	}
	busy := pods[0]
	burning := time.Now()
	signal(busy, "/burn", map[string]string{"seconds": "150"})
	captured(resources, "resource", busy, burning)
	t.Logf("installed signal journey: complete %s after start", time.Since(started).Round(time.Second))
}
