package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	domaincapture "asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// installedPolicyFixture is the first workload cluster's regional workload
// and the operator's hub access, recorded before its journey runs, for the
// ADR-228 policy focus (ASSERVAT_JOURNEY_FOCUS=policy).
type installedPolicyFixture struct {
	region                       kubernetes.Interface
	hub                          rest.Interface
	base                         string
	cluster, namespace, workload string
	binding                      map[string]any
}

var installedPolicyTarget *installedPolicyFixture

const installedPolicyName = "regional-restarts"

// installedPolicyJourney qualifies the first S-03 increment on the installed
// product: an administrator adds an automation envelope, a maintainer applies a
// hub-held restart DebugPolicy and activates it over MCP as the Keycloak user;
// one killed container yields one policy-executed pod-status capture that the
// user downloads; a three-replica crash storm is bounded by the shared workload
// budget, with content-free suppression counts and bounded rows.
func installedPolicyJourney(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, identity *installedIdentity, publicRoot []byte, address, origin string, diagnose func()) {
	t.Helper()
	f := installedPolicyTarget
	if f == nil || identity == nil {
		t.Fatal("policy journey requires the regional fixture and the harness identity provider")
	}
	started := time.Now()
	cert, err := x509.ParseCertificate(publicRoot)
	if err != nil {
		t.Fatal("public listener root", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	dial := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial.DialContext(ctx, network, address)
		}}
	defer transport.CloseIdleConnections()
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	identity.initializeProcessing(t, ctx, cert, address, origin, diagnose)
	tokens := identity.mcpTokenSource(origin)
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-policy", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, tokens.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("installed MCP session", err)
	}
	defer session.Close()
	read := func(callCtx context.Context, name string, arguments any) (installedJourneyEnvelope, error) {
		result, err := session.CallTool(callCtx, &sdk.CallToolParams{Name: name, Arguments: arguments})
		if err != nil {
			return installedJourneyEnvelope{}, err
		}
		// Policy operations have their own closed failure codes
		// (DelegationRequired while the envelope propagates).
		reply, _, err := installedJourneyReplyCode(wire, name, result)
		if err != nil {
			diagnose()
			t.Fatal("installed response contract", name, err)
		}
		return reply, nil
	}
	wait := func(what string, limit time.Duration, done func(context.Context) bool) {
		t.Helper()
		bounded, stop := context.WithTimeout(ctx, limit)
		defer stop()
		for bounded.Err() == nil {
			if done(bounded) && bounded.Err() == nil {
				return
			}
			if installedJourneyPause(bounded, 2*time.Second) != nil {
				break
			}
		}
		diagnose()
		t.Fatal("installed policy journey: timed out waiting for", what)
	}
	observe := func(poll context.Context, name string, arguments, data any) bool {
		reply, err := read(poll, name, arguments)
		if err != nil || reply.Status != "ok" {
			return false
		}
		if installedJourneyDecode(reply.Data, data) != nil {
			t.Fatal("installed status data", name)
		}
		return true
	}
	scalar := func(query string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := admin.QueryRow(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(query, err)
		}
		return n
	}

	// Three running replicas of the regional workload.
	scale, err := f.region.AppsV1().Deployments(f.namespace).GetScale(ctx, f.workload, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	scale.Spec.Replicas = 3
	if _, err = f.region.AppsV1().Deployments(f.namespace).UpdateScale(ctx, f.workload, scale, meta.UpdateOptions{}); err != nil {
		t.Fatal("scale regional workload", err)
	}
	runningPods := func() []core.Pod {
		t.Helper()
		pods, err := f.region.CoreV1().Pods(f.namespace).List(ctx, meta.ListOptions{LabelSelector: "app=" + f.workload})
		if err != nil {
			t.Fatal(err)
		}
		var out []core.Pod
		for _, p := range pods.Items {
			if p.DeletionTimestamp == nil && p.Status.Phase == core.PodRunning && len(p.Status.ContainerStatuses) == 1 {
				out = append(out, p)
			}
		}
		return out
	}
	wait("three running replicas", 2*time.Minute, func(context.Context) bool { return len(runningPods()) == 3 })

	// The administrator's automation envelope for the team: the existing
	// maintainer binding's group and scope, kubernetesSnapshot only.
	binding := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": "policy-automation"}, "spec": map[string]any{
		"effect": "Allow", "subjects": f.binding["subjects"], "roles": []any{"workload-maintainer"}, "scope": f.binding["scope"], "reason": "ADR-228 installed policy journey",
		"automation": map[string]any{"allowedActions": []any{"kubernetesSnapshot"}, "maxLifetimeSeconds": 3600, "maxExecutions": 10, "maxBytes": 1073741824, "maxObservedBytes": 0}}}
	body, _ := json.Marshal(binding)
	if err = f.hub.Post().AbsPath(f.base + "accessbindings").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("administrator automation binding", err)
	}
	digest := planning.RecipeDigest()
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": installedPolicyName}, "spec": map[string]any{
		"target":    map[string]any{"cluster": f.cluster, "namespace": f.namespace, "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": f.workload}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "crashed", "kind": "exit", "options": map[string]any{"reasons": []any{"Error", "OOMKilled"}}}},
		"when":      map[string]any{"detector": "crashed"},
		"recipeRef": map[string]any{"name": planning.ContextRecipeName, "digest": hex.EncodeToString(digest[:])},
		"budgets":   map[string]any{"cooldown": "5m", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": fmt.Sprintf("%ds", installedJourneyRetention), "suspended": false,
		"observation": map[string]any{"mode": "allAuthorized"},
		"evaluation":  map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"}}}
	body, _ = json.Marshal(policy)
	if err = f.hub.Post().AbsPath(f.base + "debugpolicies").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("maintainer applies the hub-held DebugPolicy", err)
	}
	t.Log("installed policy journey: administrator automation envelope and hub-held DebugPolicy applied")

	// The Keycloak user activates it; the envelope reaches the accepted
	// permission projection asynchronously, so DelegationRequired retries.
	var activated struct {
		PolicyUID     string    `json:"policy_uid"`
		AcceptanceID  string    `json:"acceptance_id"`
		State         string    `json:"state"`
		ExpiresAt     time.Time `json:"expires_at"`
		MaxExecutions int64     `json:"max_executions"`
	}
	activation := map[string]string{"policy_name": installedPolicyName, "idempotency_key": "installed-policy-activation"}
	wait("an active policy", 3*time.Minute, func(poll context.Context) bool {
		reply, err := read(poll, "activate_policy", activation)
		if err != nil {
			t.Logf("installed activate_policy transport: %v", err)
			return false
		}
		if reply.Status != "ok" {
			var failure struct{ Code, Message string }
			_ = json.Unmarshal(reply.Data, &failure)
			t.Logf("installed activate_policy %s: %s (request %s)", failure.Code, failure.Message, reply.RequestID)
			return false
		}
		if installedJourneyDecode(reply.Data, &activated) != nil {
			t.Fatal("activation data")
		}
		return activated.State == "active"
	})
	if activated.MaxExecutions != 10 || !activated.ExpiresAt.After(time.Now()) || activated.ExpiresAt.After(time.Now().Add(time.Hour)) {
		t.Fatal("activation did not take the envelope's finite limits", activated)
	}
	t.Logf("installed policy journey: policy %s activated (acceptance %s) %s after start", activated.PolicyUID, activated.AcceptanceID, time.Since(started).Round(time.Second))
	watched := func() int64 {
		return scalar(`SELECT count(*) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	}
	wait("the restart baseline of all three Pods", time.Minute, func(context.Context) bool { return watched() == 3 })
	occurrences := func() int64 {
		return scalar(`SELECT count(*) FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	}
	if occurrences() != 0 {
		t.Fatal("activation fired without a restart")
	}

	// Phase A: one killed container, one capture by the policy executor.
	pods := runningPods()
	victim := pods[0]
	before := victim.Status.ContainerStatuses[0].RestartCount
	if !installedKillContainer(t, ctx, victim) {
		t.Fatal("regional container not running")
	}
	wait("the container restart", time.Minute, func(context.Context) bool {
		p, err := f.region.CoreV1().Pods(f.namespace).Get(ctx, victim.Name, meta.GetOptions{})
		return err == nil && len(p.Status.ContainerStatuses) == 1 && p.Status.ContainerStatuses[0].RestartCount > before
	})
	var captureID string
	var restarts int64
	wait("a policy capture", 2*time.Minute, func(poll context.Context) bool {
		err := admin.QueryRow(poll, `SELECT coalesce(capture_id::text,''),restarts FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3`, root, activated.PolicyUID, string(victim.UID)).Scan(&captureID, &restarts)
		return err == nil && captureID != ""
	})
	var executor, kind string
	if err = admin.QueryRow(ctx, `SELECT convert_from(scope_json,'UTF8')::jsonb#>>'{executor,subject}',convert_from(scope_json,'UTF8')::jsonb#>>'{executor,identityType}' FROM context_capture WHERE id=$1`, captureID).Scan(&executor, &kind); err != nil || executor != "policy:"+activated.PolicyUID || kind != "workload" || restarts < 1 {
		t.Fatal("policy capture provenance", executor, kind, restarts, err)
	}
	var status struct {
		State    string `json:"state"`
		Executor struct {
			Kind      string `json:"kind"`
			PolicyUID string `json:"policy_uid"`
		} `json:"executor"`
		WatchedPods int64 `json:"watched_pods"`
		Captured    int64 `json:"captured"`
		Recent      []struct {
			CaptureID string `json:"capture_id"`
			Outcome   string `json:"outcome"`
		} `json:"recent"`
		Suppressions []struct {
			Reason string `json:"reason"`
			Count  int64  `json:"count"`
		} `json:"suppressions"`
	}
	wait("the policy status", time.Minute, func(poll context.Context) bool {
		return observe(poll, "get_policy_status", map[string]string{"policy_name": installedPolicyName}, &status)
	})
	if status.State != "active" || status.Executor.Kind != "policy" || status.Executor.PolicyUID != activated.PolicyUID || status.WatchedPods != 3 || status.Captured != 1 || len(status.Recent) != 1 || status.Recent[0].CaptureID != captureID || status.Recent[0].Outcome != "captured" {
		t.Fatal("content-free policy status", status)
	}
	t.Logf("installed policy journey: the killed container yielded capture %s by policy:%s (restart %d)", captureID, activated.PolicyUID, restarts)

	// The user reads and downloads the policy capture through its audience.
	var progress installedJourneyCaptureProgress
	wait("the policy capture's case", 5*time.Minute, func(poll context.Context) bool {
		if !observe(poll, "get_capture", map[string]string{"capture_id": captureID}, &progress) {
			return false
		}
		ready, err := installedJourneyCaptureCaseReady(poll, captureID, progress)
		if err != nil {
			diagnose()
			t.Fatal(err)
		}
		return ready
	})
	var investigation struct {
		Artifacts []struct {
			ArtifactID string `json:"artifact_id"`
		} `json:"artifacts"`
	}
	wait("the published policy artifact", 2*time.Minute, func(poll context.Context) bool {
		return observe(poll, "get_case", map[string]string{"case_id": progress.CaseID}, &investigation) && len(investigation.Artifacts) == 1
	})
	prepare := map[string]string{"artifact_id": investigation.Artifacts[0].ArtifactID, "idempotency_key": "installed-policy-download"}
	var download installedJourneyDownload
	wait("a prepared policy download", 3*time.Minute, func(poll context.Context) bool {
		name, args := "get_artifact_download", any(map[string]string{"download_id": download.DownloadID})
		if download.DownloadID == "" || download.ContinuePreparation {
			name, args = "prepare_artifact_download", prepare
		}
		return observe(poll, name, args, &download) && download.State != "Preparing"
	})
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil {
		diagnose()
		t.Fatal("policy download not prepared", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: 2 * time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	native, err := io.ReadAll(io.LimitReader(response.Body, artifact.MaxContextBytes+1))
	response.Body.Close()
	sum := sha256.Sum256(native)
	var projected struct {
		PodUID string `json:"podUID"`
	}
	if err != nil || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(sum[:]) != download.SHA256 || json.Unmarshal(native, &projected) != nil || projected.PodUID != string(victim.UID) {
		diagnose()
		t.Fatal("policy capture native download", response.StatusCode, err, projected.PodUID)
	}
	t.Logf("installed policy journey: the Keycloak user downloaded the policy capture (%d bytes) of the killed Pod, %s after start", len(native), time.Since(started).Round(time.Second))

	// Phase B: all three replicas crash repeatedly for 90 s (cut from 150 s so the run fits the 20-minute rule with margin; three Pods still restart several times under the backoff).
	baseline := scalar(`SELECT coalesce(sum(restarts),0) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	admittedBefore := occurrences()
	suppressed := func() int64 {
		return scalar(`SELECT coalesce(sum(count),0) FROM policy_suppression WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	}
	suppressedBefore := suppressed()
	kills := 0
	for storm := time.Now().Add(90 * time.Second); time.Now().Before(storm); {
		for _, p := range runningPods() {
			if installedKillContainer(t, ctx, p) {
				kills++
			}
		}
		if installedJourneyPause(ctx, 5*time.Second) != nil {
			t.Fatal(ctx.Err())
		}
	}
	stormEnd := occurrences()
	// Thirty seconds of quiet: later polls catch up, but no new capture.
	if installedJourneyPause(ctx, 30*time.Second) != nil {
		t.Fatal(ctx.Err())
	}
	final := scalar(`SELECT coalesce(sum(restarts),0) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	admitted, rows, marks, quiet := occurrences(), scalar(`SELECT count(*) FROM policy_suppression WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID), watched(), occurrences()
	observedRestarts, suppressedDelta := final-baseline, suppressed()-suppressedBefore
	t.Logf("installed policy journey: storm of %d kills, %d observed restarts, %d occurrences before and %d after (at storm end %d), %d suppressed, %d suppression rows, %d watermark rows", kills, observedRestarts, admittedBefore, admitted, stormEnd, suppressedDelta, rows, marks)
	if admitted > 2 || admitted < admittedBefore || marks > 3 || rows > 6 || quiet != stormEnd || observedRestarts < 3 || suppressedDelta < observedRestarts-(admitted-admittedBefore) {
		diagnose()
		t.Fatal("restart storm exceeded the shared workload budget or lost suppression counts")
	}
	if scalar(`SELECT count(*) FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND outcome IS NULL`, root, activated.PolicyUID) != 0 {
		t.Fatal("an occurrence has no recorded outcome")
	}

	// Phase C (ADR-229): the user deactivates the policy. A deactivated policy
	// is no longer polled, so a further kill changes no watermark, occurrence
	// or suppression count (an active policy would at least count a cooldown);
	// spend and the existing capture stay.
	deactivation := map[string]string{"policy_name": installedPolicyName, "idempotency_key": "installed-policy-deactivation"}
	var stopped struct {
		AcceptanceID string `json:"acceptance_id"`
		State        string `json:"state"`
		Replay       bool   `json:"replay"`
	}
	wait("a deactivated policy", time.Minute, func(poll context.Context) bool {
		return observe(poll, "deactivate_policy", deactivation, &stopped)
	})
	if stopped.State != "deactivated" || stopped.AcceptanceID != activated.AcceptanceID {
		t.Fatal("deactivation", stopped)
	}
	stoppedAt := time.Now()
	spent := scalar(`SELECT executions_spent FROM policy_acceptance WHERE id=$1`, activated.AcceptanceID)
	// A cycle that listed the policy just before deactivation may still be in
	// its tick; the next cycle no longer lists it.
	if installedJourneyPause(ctx, domaincapture.TriggerPollInterval) != nil {
		t.Fatal(ctx.Err())
	}
	marksBefore, occurrencesBefore, suppressedAt := scalar(`SELECT coalesce(sum(restarts),0) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID), occurrences(), suppressed()
	killed := 0
	wait("a running replica to kill", 2*time.Minute, func(context.Context) bool {
		for _, p := range runningPods() {
			if installedKillContainer(t, ctx, p) {
				killed++
				return true
			}
		}
		return false
	})
	// Two full poll periods after the kill.
	if installedJourneyPause(ctx, 2*domaincapture.TriggerPollInterval+5*time.Second) != nil {
		t.Fatal(ctx.Err())
	}
	marksAfter := scalar(`SELECT coalesce(sum(restarts),0) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	if marksAfter != marksBefore || occurrences() != occurrencesBefore || suppressed() != suppressedAt || scalar(`SELECT executions_spent FROM policy_acceptance WHERE id=$1`, activated.AcceptanceID) != spent ||
		scalar(`SELECT count(*) FROM policy_source WHERE root_id=$1 AND policy_uid=$2 AND active_id IS NULL`, root, activated.PolicyUID) != 1 || scalar(`SELECT count(*) FROM context_capture WHERE id=$1`, captureID) != 1 {
		diagnose()
		t.Fatal("deactivated policy still observed or spent", marksBefore, marksAfter, occurrencesBefore, occurrences(), suppressedAt, suppressed(), spent)
	}
	var again struct {
		State  string `json:"state"`
		Replay bool   `json:"replay"`
	}
	if !observe(ctx, "deactivate_policy", deactivation, &again) || !again.Replay || again.State != "deactivated" {
		t.Fatal("repeated deactivation", again)
	}
	status.State = ""
	if !observe(ctx, "get_policy_status", map[string]string{"policy_name": installedPolicyName}, &status) || status.State != "deactivated" || status.Captured != 1 {
		t.Fatal("deactivated policy status", status)
	}
	t.Logf("installed policy journey: deactivated %s after start; %d kill(s) %s later changed no watermark, occurrence, suppression or spend", stoppedAt.Sub(started).Round(time.Second), killed, time.Since(stoppedAt).Round(time.Second))
	t.Logf("installed policy journey complete %s after start", time.Since(started).Round(time.Second))
}

// installedKillContainer SIGKILLs the regional app container of one Pod on
// its owned kind node (exit 137, reason Error) and reports whether it ran.
func installedKillContainer(t *testing.T, ctx context.Context, pod core.Pod) bool {
	t.Helper()
	node := pod.Spec.NodeName
	cluster := strings.TrimSuffix(strings.TrimSuffix(node, "-control-plane"), "-worker")
	if !strings.HasPrefix(node, "asservat-") || cluster == node {
		t.Fatal("regional Pod not on an owned harness node", node)
	}
	label, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{ index .Config.Labels \"io.x-k8s.kind.cluster\" }}", node).Output()
	if err != nil || strings.TrimSpace(string(label)) != cluster {
		t.Fatal("node container not owned by this harness cluster", err)
	}
	ids, err := exec.CommandContext(ctx, "docker", "exec", node, "crictl", "ps", "-q", "--state", "running", "--label", "io.kubernetes.pod.uid="+string(pod.UID), "--name", "app").Output()
	id := strings.TrimSpace(string(ids))
	if err != nil || id == "" || strings.Contains(id, "\n") {
		return false
	}
	return exec.CommandContext(ctx, "docker", "exec", node, "crictl", "stop", "--timeout", "0", id).Run() == nil
}
