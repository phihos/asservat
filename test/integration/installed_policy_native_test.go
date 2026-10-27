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
	"maps"
	"net"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	domaincapture "asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
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

// installedPolicyJourney qualifies the S-03 increments on the installed
// product: an administrator adds an automation envelope; a readiness-probe
// policy (ADR-230) captures the Pod whose probe starts failing, once; a
// maintainer applies a hub-held restart DebugPolicy and activates it over MCP
// as the Keycloak user;
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
	// ADR-239: the same user activates the restart policy with evidence:share
	// (its recurring sharing), and the unrelated principal is the recipient.
	connect := func(name string, token func(context.Context) (string, error)) *sdk.ClientSession {
		t.Helper()
		c := sdk.NewClient(&sdk.Implementation{Name: name, Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
		s, err := c.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal("installed MCP session", name, err)
		}
		return s
	}
	sharer := connect("installed-policy-sharer", identity.shareTokenSource(origin).Token)
	defer sharer.Close()
	outsiderTokens := identity.unrelated().mcpTokenSource(origin)
	if _, err := outsiderTokens.Token(ctx); err != nil || outsiderTokens.subject == "" {
		t.Fatal("installed recurring-share recipient token", err)
	}
	recipient := connect("installed-policy-share-recipient", outsiderTokens.Token)
	defer recipient.Close()
	readWith := func(session *sdk.ClientSession, callCtx context.Context, name string, arguments any) (installedJourneyEnvelope, error) {
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
	read := func(callCtx context.Context, name string, arguments any) (installedJourneyEnvelope, error) {
		return readWith(session, callCtx, name, arguments)
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
		"effect": "Allow", "subjects": f.binding["subjects"], "roles": []any{"workload-maintainer", "evidence-owner"}, "scope": f.binding["scope"], "reason": "ADR-228 installed policy journey",
		"automation": map[string]any{"allowedActions": []any{"kubernetesSnapshot"}, "maxLifetimeSeconds": 3600, "maxExecutions": 10, "maxBytes": 1073741824, "maxObservedBytes": 0}}}
	body, _ := json.Marshal(binding)
	if err = f.hub.Post().AbsPath(f.base + "accessbindings").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("administrator automation binding", err)
	}
	digest := planning.RecipeDigest()
	if installedJourneyFocus() == "alert" {
		installedAlertPhase(t, ctx, admin, root, f, digest, read, wait, runningPods, started)
		return
	}
	installedProbePhase(t, ctx, admin, root, f, digest, read, wait, observe, runningPods, started)
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": installedPolicyName}, "spec": map[string]any{
		"target":    map[string]any{"cluster": f.cluster, "namespace": f.namespace, "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": f.workload}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "crashed", "kind": "exit", "options": map[string]any{"reasons": []any{"Error", "OOMKilled"}}}},
		"when":      map[string]any{"detector": "crashed"},
		"recipeRef": map[string]any{"name": planning.ContextRecipeName, "digest": hex.EncodeToString(digest[:])},
		"budgets":   map[string]any{"cooldown": "5m", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": fmt.Sprintf("%ds", installedJourneyRetention), "suspended": false,
		"observation": map[string]any{"mode": "allAuthorized"},
		"evaluation":  map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"},
		// ADR-239: the first capture is shared with the unrelated principal.
		"sharing": map[string]any{"recipients": []any{map[string]any{"kind": "User", "issuer": identity.Issuer, "id": outsiderTokens.subject}},
			"futureCaptures": map[string]any{"enabled": true, "maxCaptures": 1}, "notAfter": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}}
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
		Sharing       *struct {
			Statement   string `json:"statement"`
			Recipients  int    `json:"recipients"`
			MaxCaptures int    `json:"max_captures"`
		} `json:"sharing"`
	}
	// ADR-239: the first activation returns the sharing review; the user then
	// activates with sharing_reviewed.
	activation := map[string]any{"policy_name": installedPolicyName, "idempotency_key": "installed-policy-activation"}
	reviewed := ""
	wait("an active policy", 3*time.Minute, func(poll context.Context) bool {
		reply, err := readWith(sharer, poll, "activate_policy", activation)
		if err != nil {
			t.Logf("installed activate_policy transport: %v", err)
			return false
		}
		if reply.Status != "ok" {
			var failure struct{ Code, Message string }
			_ = json.Unmarshal(reply.Data, &failure)
			t.Logf("installed activate_policy %s: %s (request %s)", failure.Code, failure.Message, reply.RequestID)
			if failure.Code == "SharingReviewRequired" {
				if reviewed != "" || !strings.HasPrefix(failure.Message, "Repeated collections will be shared with User "+outsiderTokens.subject+": at most the next 1 capture(s)") {
					t.Fatal("installed sharing review", failure.Message)
				}
				reviewed = failure.Message
				activation["sharing_reviewed"] = true
			}
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
	if reviewed == "" {
		t.Fatal("the sharing policy was activated without a review")
	}
	if activated.Sharing == nil || activated.Sharing.Statement != "Repeated collections will be shared" || activated.Sharing.Recipients != 1 || activated.Sharing.MaxCaptures != 1 {
		t.Fatal("activation does not state its recurring sharing", activated.Sharing)
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
	// ADR-239: the policy's first capture was shared at publication with the
	// recipient, who reads exactly that case; the one-capture limit is reached.
	var sharedProgress struct {
		Sharing struct {
			State   string `json:"state"`
			ShareID string `json:"share_id"`
		} `json:"sharing"`
	}
	wait("the policy capture's recurring share", time.Minute, func(poll context.Context) bool {
		return observe(poll, "get_capture", map[string]string{"capture_id": captureID}, &sharedProgress) && sharedProgress.Sharing.State == "Shared"
	})
	var sharedCase struct {
		Case struct {
			Access string `json:"access"`
		} `json:"case"`
		Artifacts []struct {
			ArtifactID string `json:"artifact_id"`
		} `json:"artifacts"`
	}
	if reply, err := readWith(recipient, ctx, "get_case", map[string]string{"case_id": progress.CaseID}); err != nil || reply.Status != "ok" || installedJourneyDecode(reply.Data, &sharedCase) != nil || sharedCase.Case.Access != "shared" || len(sharedCase.Artifacts) != 1 || sharedCase.Artifacts[0].ArtifactID != investigation.Artifacts[0].ArtifactID {
		diagnose()
		t.Fatal("installed recurring-share recipient could not read the policy capture", reply.Status, err, sharedCase)
	}
	var sharingStatus struct {
		Sharing *struct {
			State          string `json:"state"`
			SharedCaptures int    `json:"shared_captures"`
		} `json:"sharing"`
	}
	if !observe(ctx, "get_policy_status", map[string]string{"policy_name": installedPolicyName}, &sharingStatus) || sharingStatus.Sharing == nil || sharingStatus.Sharing.State != "limitReached" || sharingStatus.Sharing.SharedCaptures != 1 {
		t.Fatal("installed policy sharing status", sharingStatus.Sharing)
	}
	t.Logf("installed policy journey: the policy capture was shared with the unrelated principal (share %s), %s after start", sharedProgress.Sharing.ShareID, time.Since(started).Round(time.Second))
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

	// Phase B: all three replicas crash repeatedly for 60 s (150 s in ADR-228, 90 s in its CI fix; since ADR-230 the probe occurrence and the first exit capture already hold the shared workload burst, so every storm restart meets a saturated budget and three Pods still restart several times under the backoff).
	baseline := scalar(`SELECT coalesce(sum(restarts),0) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	admittedBefore := occurrences()
	suppressed := func() int64 {
		return scalar(`SELECT coalesce(sum(count),0) FROM policy_suppression WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	}
	suppressedBefore := suppressed()
	kills := 0
	for storm := time.Now().Add(60 * time.Second); time.Now().Before(storm); {
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
	if !observe(ctx, "get_policy_status", map[string]string{"policy_name": installedPolicyName}, &status) || status.State != "deactivated" || status.Captured != scalar(`SELECT count(capture_id) FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID) {
		t.Fatal("deactivated policy status", status)
	}
	t.Logf("installed policy journey: deactivated %s after start; %d kill(s) %s later changed no watermark, occurrence, suppression or spend", stoppedAt.Sub(started).Round(time.Second), killed, time.Since(stoppedAt).Round(time.Second))
	t.Logf("installed policy journey complete %s after start", time.Since(started).Round(time.Second))
}

const installedProbePolicyName = "regional-readiness"

// installedProbePhase qualifies the ADR-230 probe detector before the restart
// phases: a hub-held readiness-probe DebugPolicy is activated, the workload's
// template gains a readiness probe that fails after a 30-second delay (one
// surge Pod of a stuck rollout), and the first failures yield exactly one
// policy-executed pod-status capture of that Pod; the continuing failures
// create no second occurrence and no Event text reaches status. The template
// is then restored, so the restart phases see the original three replicas.
func installedProbePhase(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, f *installedPolicyFixture, digest artifact.Digest, read func(context.Context, string, any) (installedJourneyEnvelope, error), wait func(string, time.Duration, func(context.Context) bool), observe func(context.Context, string, any, any) bool, runningPods func() []core.Pod, started time.Time) {
	t.Helper()
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": installedProbePolicyName}, "spec": map[string]any{
		"target":    map[string]any{"cluster": f.cluster, "namespace": f.namespace, "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": f.workload}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "unready", "kind": "probe", "options": map[string]any{"probeType": "Readiness", "minimumFailures": 2, "window": "30s", "source": "events"}}},
		"when":      map[string]any{"detector": "unready"},
		"recipeRef": map[string]any{"name": planning.ContextRecipeName, "digest": hex.EncodeToString(digest[:])},
		"budgets":   map[string]any{"cooldown": "5m", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": fmt.Sprintf("%ds", installedJourneyRetention), "suspended": false,
		"observation": map[string]any{"mode": "allAuthorized"},
		"evaluation":  map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"}}}
	body, _ := json.Marshal(policy)
	if err := f.hub.Post().AbsPath(f.base + "debugpolicies").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("maintainer applies the hub-held probe DebugPolicy", err)
	}
	// The envelope reaches the accepted permission projection asynchronously,
	// so DelegationRequired retries.
	var activated struct {
		PolicyUID string `json:"policy_uid"`
		State     string `json:"state"`
	}
	activation := map[string]string{"policy_name": installedProbePolicyName, "idempotency_key": "installed-probe-activation"}
	wait("an active probe policy", 3*time.Minute, func(poll context.Context) bool {
		reply, err := read(poll, "activate_policy", activation)
		if err != nil || reply.Status != "ok" {
			if err == nil {
				t.Logf("installed activate_policy (probe): %s", reply.Data)
			}
			return false
		}
		if installedJourneyDecode(reply.Data, &activated) != nil {
			t.Fatal("probe activation data")
		}
		return activated.State == "active"
	})
	t.Logf("installed policy journey: probe policy %s activated %s after start", activated.PolicyUID, time.Since(started).Round(time.Second))
	scalar := func(query string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := admin.QueryRow(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(query, err)
		}
		return n
	}
	// A readiness probe that fails 30 s after the container starts: the
	// rollout surges one Pod that the policy first sees healthy (armed), well
	// within the 15-second poll.
	original := map[string]bool{}
	for _, p := range runningPods() {
		original[string(p.UID)] = true
	}
	template := func(probe *core.Probe) {
		t.Helper()
		for attempt := 0; ; attempt++ {
			d, err := f.region.AppsV1().Deployments(f.namespace).Get(ctx, f.workload, meta.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			d.Spec.Template.Spec.Containers[0].ReadinessProbe = probe
			if _, err = f.region.AppsV1().Deployments(f.namespace).Update(ctx, d, meta.UpdateOptions{}); err == nil {
				return
			} else if attempt == 5 {
				t.Fatal("regional workload template", err)
			}
		}
	}
	template(&core.Probe{ProbeHandler: core.ProbeHandler{TCPSocket: &core.TCPSocketAction{Port: intstr.FromInt32(1)}}, InitialDelaySeconds: 30, PeriodSeconds: 2, TimeoutSeconds: 1, FailureThreshold: 1})
	wait("the armed probe baseline of the original Pods", time.Minute, func(context.Context) bool {
		return scalar(`SELECT count(*) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2 AND detector='probe' AND armed AND pod_uid=ANY($3::text[])`, root, activated.PolicyUID, slices.Collect(maps.Keys(original))) == 3
	})
	var surge core.Pod
	wait("the surge Pod with the failing readiness probe", time.Minute, func(context.Context) bool {
		for _, p := range runningPods() {
			if !original[string(p.UID)] {
				surge = p
				return true
			}
		}
		return false
	})
	var captureID string
	var failedAt int64
	wait("a probe policy capture", 3*time.Minute, func(poll context.Context) bool {
		err := admin.QueryRow(poll, `SELECT coalesce(capture_id::text,''),restarts FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3 AND detector='probe'`, root, activated.PolicyUID, string(surge.UID)).Scan(&captureID, &failedAt)
		return err == nil && captureID != ""
	})
	var executor string
	if err := admin.QueryRow(ctx, `SELECT convert_from(scope_json,'UTF8')::jsonb#>>'{executor,subject}' FROM context_capture WHERE id=$1`, captureID).Scan(&executor); err != nil || executor != "policy:"+activated.PolicyUID || failedAt < 1000000000 {
		t.Fatal("probe capture provenance", executor, failedAt, err)
	}
	// The probe keeps failing: a poll after the occurrence (usually already
	// during the capture) leaves the level fired once and disarmed.
	wait("a probe poll after the occurrence", time.Minute, func(poll context.Context) bool {
		var later bool
		err := admin.QueryRow(poll, `SELECT w.last_seen>o.created_at+interval '2 seconds' FROM policy_pod_watermark w JOIN policy_occurrence o ON o.root_id=w.root_id AND o.policy_uid=w.policy_uid AND o.pod_uid=w.pod_uid WHERE w.root_id=$1 AND w.policy_uid=$2 AND w.pod_uid=$3`, root, activated.PolicyUID, string(surge.UID)).Scan(&later)
		return err == nil && later
	})
	failures := scalar(`SELECT count(*) FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	disarmed := scalar(`SELECT count(*) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3 AND NOT armed`, root, activated.PolicyUID, string(surge.UID))
	var status struct {
		Detector struct {
			Kind      string `json:"kind"`
			ProbeType string `json:"probe_type"`
		} `json:"detector"`
		Recent []struct {
			Detector  string `json:"detector"`
			CaptureID string `json:"capture_id"`
			FailedAt  string `json:"failed_at"`
		} `json:"recent"`
	}
	reply, err := read(ctx, "get_policy_status", map[string]string{"policy_name": installedProbePolicyName})
	if err != nil || reply.Status != "ok" || installedJourneyDecode(reply.Data, &status) != nil {
		t.Fatal("probe policy status", err, reply.Status)
	}
	if failures != 1 || disarmed != 1 || status.Detector.Kind != "probe" || status.Detector.ProbeType != "Readiness" || len(status.Recent) != 1 || status.Recent[0].Detector != "probe" || status.Recent[0].CaptureID != captureID || status.Recent[0].FailedAt == "" ||
		strings.Contains(string(reply.Data), "refused") || strings.Contains(string(reply.Data), "probe failed") {
		t.Fatal("probe occurrence", failures, disarmed, string(reply.Data))
	}
	t.Logf("installed policy journey: the failing readiness probe yielded capture %s by policy:%s (one occurrence), %s after start", captureID, activated.PolicyUID, time.Since(started).Round(time.Second))
	// Restore the template: the surge Pod goes, the original replicas remain.
	template(nil)
	wait("the original three replicas", 2*time.Minute, func(context.Context) bool {
		pods := runningPods()
		for _, p := range pods {
			if !original[string(p.UID)] {
				return false
			}
		}
		return len(pods) == 3
	})
}

const installedAlertPolicyName = "regional-alerts"

// installAlertmanager runs the official Alertmanager image (its default
// configuration; no Prometheus) in the workload cluster's monitoring
// namespace and returns its in-cluster URL for installer-cluster --alertmanager.
func installAlertmanager(t *testing.T, ctx context.Context, region kubernetes.Interface, image string) string {
	t.Helper()
	if image == "" {
		t.Fatal("alert focus without the harness's Alertmanager image")
	}
	if _, err := region.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "monitoring", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{}); err != nil {
		t.Fatal("monitoring namespace", err)
	}
	labels := map[string]string{"app": "alertmanager"}
	if _, err := region.AppsV1().Deployments("monitoring").Create(ctx, &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "alertmanager"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Selector: &meta.LabelSelector{MatchLabels: labels},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{AutomountServiceAccountToken: ptr.To(false),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65534)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Volumes:         []core.Volume{{Name: "data", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{}}}},
			Containers: []core.Container{{Name: "alertmanager", Image: image, ImagePullPolicy: core.PullIfNotPresent,
				Args:            []string{"--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/alertmanager", "--cluster.listen-address="},
				Ports:           []core.ContainerPort{{Name: "web", ContainerPort: 9093}},
				VolumeMounts:    []core.VolumeMount{{Name: "data", MountPath: "/alertmanager"}},
				ReadinessProbe:  &core.Probe{ProbeHandler: core.ProbeHandler{HTTPGet: &core.HTTPGetAction{Path: "/-/ready", Port: intstr.FromString("web")}}, PeriodSeconds: 2},
				SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal("Alertmanager Deployment", err)
	}
	if _, err := region.CoreV1().Services("monitoring").Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: "alertmanager"}, Spec: core.ServiceSpec{Selector: labels, Ports: []core.ServicePort{{Name: "web", Port: 9093, TargetPort: intstr.FromString("web")}}}}, meta.CreateOptions{}); err != nil {
		t.Fatal("Alertmanager Service", err)
	}
	return "http://alertmanager.monitoring.svc:9093"
}

// installedAlertPhase qualifies the ADR-231 alert detector against the real
// Alertmanager of installAlertmanager: no occurrence before an alert; a
// synthetic alert posted to Alertmanager's own v2 API for one Pod yields one
// occurrence keyed by its startsAt and one policy capture of exactly that Pod;
// polls while it keeps firing add none; after it is resolved and a clean poll
// re-arms the Pod, a new episode (later startsAt) yields a second occurrence.
func installedAlertPhase(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, f *installedPolicyFixture, digest artifact.Digest, read func(context.Context, string, any) (installedJourneyEnvelope, error), wait func(string, time.Duration, func(context.Context) bool), runningPods func() []core.Pod, started time.Time) {
	t.Helper()
	proxy := "/api/v1/namespaces/monitoring/services/alertmanager:web/proxy"
	wait("a ready Alertmanager", 2*time.Minute, func(poll context.Context) bool {
		return f.region.CoreV1().RESTClient().Get().AbsPath(proxy+"/-/ready").Do(poll).Error() == nil
	})
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": installedAlertPolicyName}, "spec": map[string]any{
		"target":    map[string]any{"cluster": f.cluster, "namespace": f.namespace, "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": f.workload}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "alerting", "kind": "alert", "options": map[string]any{"receiverRef": "alertmanager", "status": "firing", "matchLabels": map[string]any{"alertname": "SyntheticAlert"}}}},
		"when":      map[string]any{"detector": "alerting"},
		"recipeRef": map[string]any{"name": planning.ContextRecipeName, "digest": hex.EncodeToString(digest[:])},
		"budgets":   map[string]any{"cooldown": "5m", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": fmt.Sprintf("%ds", installedJourneyRetention), "suspended": false,
		"observation": map[string]any{"mode": "allAuthorized"},
		"evaluation":  map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"}}}
	body, _ := json.Marshal(policy)
	if err := f.hub.Post().AbsPath(f.base + "debugpolicies").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("maintainer applies the hub-held alert DebugPolicy", err)
	}
	var activated struct {
		PolicyUID string `json:"policy_uid"`
		State     string `json:"state"`
	}
	activation := map[string]string{"policy_name": installedAlertPolicyName, "idempotency_key": "installed-alert-activation"}
	wait("an active alert policy", 3*time.Minute, func(poll context.Context) bool {
		reply, err := read(poll, "activate_policy", activation)
		if err != nil || reply.Status != "ok" {
			if err == nil {
				t.Logf("installed activate_policy (alert): %s", reply.Data)
			}
			return false
		}
		if installedJourneyDecode(reply.Data, &activated) != nil {
			t.Fatal("alert activation data")
		}
		return activated.State == "active"
	})
	t.Logf("installed alert journey: alert policy %s activated %s after start", activated.PolicyUID, time.Since(started).Round(time.Second))
	scalar := func(query string, args ...any) int64 {
		t.Helper()
		var n int64
		if err := admin.QueryRow(ctx, query, args...).Scan(&n); err != nil {
			t.Fatal(query, err)
		}
		return n
	}
	occurrences := func() int64 {
		return scalar(`SELECT count(*) FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2`, root, activated.PolicyUID)
	}
	armed := func(pods ...string) int64 {
		return scalar(`SELECT count(*) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2 AND detector='alert' AND armed AND pod_uid=ANY($3::text[])`, root, activated.PolicyUID, pods)
	}
	pods := runningPods()
	var uids []string
	for _, p := range pods {
		uids = append(uids, string(p.UID))
	}
	wait("the armed alert baseline of all Pods", time.Minute, func(context.Context) bool { return armed(uids...) == int64(len(uids)) })
	if occurrences() != 0 {
		t.Fatal("alert policy fired without an alert")
	}
	victim := pods[len(pods)-1]
	post := func(startsAt, endsAt time.Time) {
		t.Helper()
		alert, _ := json.Marshal([]any{map[string]any{"labels": map[string]string{"alertname": "SyntheticAlert", "namespace": f.namespace, "pod": victim.Name},
			"annotations": map[string]string{"summary": "synthetic MUST-NOT-LEAK"}, "startsAt": startsAt.UTC().Format(time.RFC3339), "endsAt": endsAt.UTC().Format(time.RFC3339)}})
		if err := f.region.CoreV1().RESTClient().Post().AbsPath(proxy+"/api/v2/alerts").SetHeader("Content-Type", "application/json").Body(alert).Do(ctx).Error(); err != nil {
			t.Fatal("post the synthetic alert to Alertmanager", err)
		}
	}
	// One episode: an occurrence keyed by its startsAt second and one capture
	// pinned to the alert's Pod.
	episode := func(n int64, startsAt time.Time) string {
		t.Helper()
		var captureID string
		wait("an alert policy capture", 3*time.Minute, func(poll context.Context) bool {
			err := admin.QueryRow(poll, `SELECT coalesce(capture_id::text,'') FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3 AND detector='alert' AND restarts=$4`, root, activated.PolicyUID, string(victim.UID), startsAt.Unix()).Scan(&captureID)
			return err == nil && captureID != ""
		})
		var executor string
		var pinned bool
		if err := admin.QueryRow(ctx, `SELECT convert_from(scope_json,'UTF8')::jsonb#>>'{executor,subject}',position($2 in convert_from(pod_pin_json,'UTF8'))>0 FROM context_capture WHERE id=$1`, captureID, string(victim.UID)).Scan(&executor, &pinned); err != nil || executor != "policy:"+activated.PolicyUID || !pinned {
			t.Fatal("alert capture provenance", executor, pinned, err)
		}
		if got := occurrences(); got != n {
			t.Fatal("alert occurrences", got, "want", n)
		}
		return captureID
	}
	firstStart := time.Now().Add(-2 * time.Second).Truncate(time.Second)
	post(firstStart, firstStart.Add(10*time.Minute))
	first := episode(1, firstStart)
	t.Logf("installed alert journey: the posted alert on Pod %s yielded capture %s by policy:%s, %s after start", victim.Name, first, activated.PolicyUID, time.Since(started).Round(time.Second))
	// The alert keeps firing: a poll after the occurrence leaves one
	// occurrence and the Pod disarmed.
	wait("an alert poll after the occurrence", time.Minute, func(poll context.Context) bool {
		var later bool
		err := admin.QueryRow(poll, `SELECT w.last_seen>o.created_at+interval '2 seconds' FROM policy_pod_watermark w JOIN policy_occurrence o ON o.root_id=w.root_id AND o.policy_uid=w.policy_uid AND o.pod_uid=w.pod_uid WHERE w.root_id=$1 AND w.policy_uid=$2 AND w.pod_uid=$3 AND w.detector='alert'`, root, activated.PolicyUID, string(victim.UID)).Scan(&later)
		return err == nil && later
	})
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
	reply, err := read(ctx, "get_policy_status", map[string]string{"policy_name": installedAlertPolicyName})
	if err != nil || reply.Status != "ok" || installedJourneyDecode(reply.Data, &status) != nil {
		t.Fatal("alert policy status", err, reply.Status)
	}
	if occurrences() != 1 || armed(string(victim.UID)) != 0 || status.Detector.Kind != "alert" || len(status.Recent) != 1 || status.Recent[0].Detector != "alert" || status.Recent[0].CaptureID != first || status.Recent[0].FailedAt == "" || strings.Contains(string(reply.Data), "MUST-NOT-LEAK") {
		t.Fatal("alert occurrence while firing", occurrences(), string(reply.Data))
	}
	// Resolved (endsAt now): a clean poll re-arms the Pod; a new episode
	// (later startsAt) is a second occurrence within the shared burst.
	post(firstStart, time.Now())
	wait("the re-armed Pod after resolution", time.Minute, func(context.Context) bool { return armed(string(victim.UID)) == 1 })
	if occurrences() != 1 {
		t.Fatal("resolution fired an occurrence")
	}
	secondStart := time.Now().Truncate(time.Second)
	post(secondStart, secondStart.Add(10*time.Minute))
	second := episode(2, secondStart)
	t.Logf("installed alert journey: after resolution and re-arm the re-posted alert yielded capture %s; complete %s after start", second, time.Since(started).Round(time.Second))
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
