package integration

import (
	"bytes"
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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// This is an installed production-path qualification, never an authority
// provider or alternate start route. Only its guarded native focus may call it.
func qualifyInstalledPolicyRecording(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, identity *installedIdentity, publicRoot []byte, address, origin, regionalConfig string, diagnose func()) {
	t.Helper()
	if st, err := os.Stat("/etc/asservat-disposable-host"); err != nil || !st.Mode().IsRegular() {
		t.Fatal("policy recording requires a fresh disposable runner")
	}
	f := installedPolicyTarget
	if f == nil || identity == nil || identity.ReviewerSubject == "" {
		t.Fatal("policy recording lacks installed target or independent reviewer")
	}
	cert, err := x509.ParseCertificate(publicRoot)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	dial := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
		return dial.DialContext(c, network, address)
	}}
	defer transport.CloseIdleConnections()
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	identity.initializeProcessing(t, ctx, cert, address, origin, diagnose)
	connect := func(name string, i *installedIdentity) *sdk.ClientSession {
		c := sdk.NewClient(&sdk.Implementation{Name: name, Version: "1"}, nil)
		tokens := i.mcpTokenSource(origin)
		s, err := c.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, tokens.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal("policy recording MCP", name, err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	requester := connect("policy-recording-requester", identity)
	kc := *identity.kc
	kc.username = "reviewer"
	reviewer := &installedIdentity{kc: &kc, Issuer: identity.Issuer, RootPEM: identity.RootPEM, ReviewerSubject: identity.ReviewerSubject}
	manager := connect("policy-recording-manager", reviewer)
	browser := reviewer.consoleSession(t, ctx, cert, address, origin)
	invoke := func(call context.Context, s *sdk.ClientSession, name string, args any) (installedJourneyEnvelope, string, error) {
		raw, err := json.Marshal(args)
		if err != nil {
			return installedJourneyEnvelope{}, "", err
		}
		if err = wire.ValidateInput(name, raw); err != nil {
			return installedJourneyEnvelope{}, "", fmt.Errorf("native authored %s: %w", name, err)
		}
		out, err := s.CallTool(call, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			return installedJourneyEnvelope{}, "", err
		}
		return installedJourneyReplyCode(wire, name, out)
	}
	wait := func(what string, limit time.Duration, done func(context.Context) bool) {
		t.Helper()
		call, stop := context.WithTimeout(ctx, limit)
		defer stop()
		for call.Err() == nil {
			if done(call) && call.Err() == nil {
				return
			}
			if installedJourneyPause(call, time.Second) != nil {
				break
			}
		}
		diagnose()
		t.Fatal("installed policy recording timed out", what)
	}
	read := func(call context.Context, s *sdk.ClientSession, name string, args, out any) bool {
		reply, code, err := invoke(call, s, name, args)
		if err != nil || reply.Status != "ok" || code != "" {
			return false
		}
		if out != nil && json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("policy recording response", name)
		}
		return true
	}
	must := func(s *sdk.ClientSession, name string, args, out any) {
		t.Helper()
		reply, code, err := invoke(ctx, s, name, args)
		if err != nil || reply.Status != "ok" || code != "" {
			diagnose()
			t.Fatal("policy recording public operation", name, code, err)
		}
		if out != nil && json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("policy recording public data", name)
		}
	}
	browserCall := func(name string, args, out any) {
		t.Helper()
		raw, err := json.Marshal(args)
		if err == nil {
			err = wire.ValidateInput(name, raw)
		}
		if err != nil {
			t.Fatal("native authored browser input disagrees with production contract", name, err)
		}
		fields, _ := args.(map[string]any)
		key, _ := fields["idempotency_key"].(string)
		reply, status, err := browser.operation(ctx, name, args, key)
		if err != nil || status != http.StatusOK || reply.Status != "ok" {
			diagnose()
			t.Fatal("policy reviewer operation", name, status, reply.Status, err)
		}
		if out != nil && json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("policy reviewer data", name)
		}
	}
	// The operator grants this existing team a finite envelope. No grant row,
	// acceptance, occurrence, capture, observation receipt or writer is seeded.
	// This LSN includes all later shared fixture writes, not attributable packet
	// WAL. The baseline has no invented allocation: use the real capture below.
	var beforeGraph policyObservationGraphSample
	if err = admin.QueryRow(ctx, "SELECT pg_current_wal_insert_lsn()::text").Scan(&beforeGraph.WAL); err != nil {
		t.Fatal("native policy graph baseline", err)
	}
	binding := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": "policy-packet-automation"}, "spec": map[string]any{"effect": "Allow", "subjects": f.binding["subjects"], "roles": []any{"workload-maintainer", "evidence-owner"}, "scope": f.binding["scope"], "reason": "finite installed policy packet qualification", "automation": map[string]any{"allowedActions": []any{"packetCapture"}, "maxLifetimeSeconds": 3600, "maxExecutions": 2, "maxBytes": 16 << 20, "maxObservedBytes": 128 << 20}}}
	body, _ := json.Marshal(binding)
	if err = f.hub.Post().AbsPath(f.base + "accessbindings").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("operator packet automation envelope", err)
	}
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": installedPolicyRecordingName}, "spec": installedPolicyRecordingSpec(f.cluster, f.namespace, f.workload)}
	body, _ = json.Marshal(policy)
	if err = f.hub.Post().AbsPath(f.base + "debugpolicies").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("operator finite policy", err)
	}
	var object struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	body, err = f.hub.Get().AbsPath(f.base + "debugpolicies/" + installedPolicyRecordingName).DoRaw(ctx)
	if err != nil || json.Unmarshal(body, &object) != nil || object.Metadata.UID == "" {
		t.Fatal("actual policy UID", err)
	}
	var active struct {
		PolicyUID    string `json:"policy_uid"`
		AcceptanceID string `json:"acceptance_id"`
		State        string `json:"state"`
	}
	activate := map[string]any{"policy_name": installedPolicyRecordingName, "idempotency_key": "native-policy-activate"}
	wait("independently audited policy acceptance", 2*time.Minute, func(call context.Context) bool {
		return read(call, requester, "activate_policy", activate, &active) && active.State == "active"
	})
	if active.PolicyUID != object.Metadata.UID || active.AcceptanceID == "" {
		t.Fatal("activation changed source identity", active)
	}
	type policyGrant struct {
		ID          string     `json:"grant_id"`
		Kind        string     `json:"kind"`
		Phase       string     `json:"phase"`
		Revision    int64      `json:"revision"`
		RequestedAt time.Time  `json:"requested_at"`
		NotAfter    *time.Time `json:"not_after"`
		CaptureID   string     `json:"capture_id"`
		PreviewID   string     `json:"preview_id"`
		CanRevoke   bool       `json:"can_revoke"`
		CanResume   *bool      `json:"can_resume"`
		Decision    *struct {
			By struct {
				Subject string `json:"subject"`
			} `json:"decided_by"`
		} `json:"decision"`
	}
	requestReview := func(key string, tiny bool) policyGrant {
		t.Helper()
		args := installedPolicyRecordingGrantArguments(active.PolicyUID, key)
		if tiny {
			args["limits"].(map[string]any)["max_observed_bytes"] = 1
			args["observation_limits"].(map[string]any)["max_observed_bytes"] = 1
		}
		var g policyGrant
		must(requester, "request_policy_grant", args, &g)
		if g.ID == "" || g.Kind != "policy" || g.CaptureID != "" || g.PreviewID != "" || g.NotAfter == nil || !g.NotAfter.Equal(g.RequestedAt.Add(600*time.Second)) || (g.CanResume != nil && *g.CanResume) {
			t.Fatal("policy request lost original finite workload scope", g)
		}
		browser.approvedRecordingStepUp(t, ctx, reviewer, g.ID)
		browserCall("decide_review", installedPolicyRecordingDecisionArguments(g.ID), nil)
		var approved policyGrant
		must(requester, "get_grant", map[string]any{"grant_id": g.ID}, &approved)
		if approved.Phase != "Approved" || approved.Decision == nil || approved.Decision.By.Subject != identity.ReviewerSubject || approved.NotAfter == nil || !approved.NotAfter.Equal(*g.NotAfter) {
			t.Fatal("policy decision renewed or changed authority", approved)
		}
		return approved
	}
	attach := func(s *sdk.ClientSession, g policyGrant) {
		must(s, "activate_policy", map[string]any{"policy_name": installedPolicyRecordingName, "grant_id": g.ID, "idempotency_key": "native-attach-" + g.ID}, nil)
	}
	var podName, podUID string
	pods, err := f.region.CoreV1().Pods(f.namespace).List(ctx, meta.ListOptions{LabelSelector: "app=" + f.workload})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pods.Items {
		if p.DeletionTimestamp == nil && p.Status.Phase == "Running" {
			podName, podUID = p.Name, string(p.UID)
			break
		}
	}
	if podUID == "" {
		t.Fatal("actual running policy target missing")
	}
	traffic, endTraffic := context.WithCancel(ctx)
	trafficJoined := make(chan struct{})
	go func() {
		defer close(trafficJoined)
		for traffic.Err() == nil {
			call, stop := context.WithTimeout(traffic, 2*time.Second)
			_, _ = f.region.CoreV1().RESTClient().Get().Namespace(f.namespace).Resource("pods").Name(podName+":8080").SubResource("proxy").Suffix("log").Param("line", "synthetic-policy-payload-marker").DoRaw(call)
			stop()
			if installedJourneyPause(traffic, 100*time.Millisecond) != nil {
				return
			}
		}
	}()
	defer func() { endTraffic(); <-trafficJoined }()
	restart := func() {
		t.Helper()
		before, err := f.region.CoreV1().Pods(f.namespace).Get(ctx, podName, meta.GetOptions{})
		if err != nil || string(before.UID) != podUID {
			t.Fatal("original policy Pod before restart", err)
		}
		var original int32
		for _, status := range before.Status.ContainerStatuses {
			original += status.RestartCount
		}
		kill, stop := context.WithTimeout(ctx, 15*time.Second)
		killed := installedKillContainer(t, kill, *before)
		stop()
		if !killed {
			t.Fatal("owned actual policy workload did not stop")
		}
		// Require the same-Pod counter increase independently of the existing
		// owned-node CRI stop helper; the restricted workload has no shell.
		wait("the original Pod restart counter", time.Minute, func(call context.Context) bool {
			current, err := f.region.CoreV1().Pods(f.namespace).Get(call, podName, meta.GetOptions{})
			if err != nil {
				return false
			}
			if string(current.UID) != podUID {
				t.Fatal("policy fixture replaced its pinned Pod")
			}
			var restarted int32
			for _, status := range current.Status.ContainerStatuses {
				restarted += status.RestartCount
			}
			return restarted > original
		})

	}
	captureAfter := func(previous string) string {
		t.Helper()
		var id string
		wait("one real triggering occurrence", 2*time.Minute, func(call context.Context) bool {
			err := admin.QueryRow(call, `SELECT coalesce(capture_id::text,'') FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3 AND capture_id IS NOT NULL AND capture_id::text<>$4 ORDER BY created_at DESC LIMIT 1`, root, active.PolicyUID, podUID, previous).Scan(&id)
			return err == nil && id != ""
		})
		return id
	}
	// A one-byte real allowance proves that the native source cannot pass even
	// its first whole frame to the predicate. Its failed attempt stays prepaid.
	alpha := requestReview("native-policy-one-byte", true)
	attach(requester, alpha)
	wait("initial real restart watermark", time.Minute, func(call context.Context) bool {
		var n int
		return admin.QueryRow(call, `SELECT count(*) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3`, root, active.PolicyUID, podUID).Scan(&n) == nil && n == 1
	})
	restart()
	first := captureAfter("")
	var lastPublicStatus, lastPublicCode, lastPublicPhase, lastSQLPhase string
	var lastPublicErr, lastSQLErr error
	oneByteWaitFinished := false
	defer func() {
		if !oneByteWaitFinished {
			t.Logf("native one-byte refusal last facts: public status=%q code=%q last-successful-phase=%q error=%v; SQL last-successful-phase=%q error=%v", lastPublicStatus, lastPublicCode, lastPublicPhase, lastPublicErr, lastSQLPhase, lastSQLErr)
		}
	}()
	wait("native one-byte refusal", time.Minute, func(call context.Context) bool {
		reply, code, publicErr := invoke(call, requester, "get_capture", map[string]any{"capture_id": first})
		lastPublicStatus, lastPublicCode, lastPublicErr = reply.Status, code, publicErr
		var p installedJourneyCaptureProgress
		if publicErr == nil && reply.Status == "ok" && code == "" {
			lastPublicErr = json.Unmarshal(reply.Data, &p)
		}
		if lastPublicErr == nil && reply.Status == "ok" && code == "" {
			lastPublicPhase = p.Phase
		}
		var phase string
		lastSQLErr = admin.QueryRow(call, `SELECT phase FROM context_execution WHERE root_id=$1 AND capture_id=$2`, root, first).Scan(&phase)
		if lastSQLErr == nil {
			lastSQLPhase = phase
		}
		return lastPublicErr == nil && reply.Status == "ok" && code == "" && lastSQLErr == nil && phase == "captureFailed" && p.Phase == "Failed"
	})
	oneByteWaitFinished = true
	var firstUntil time.Time
	var firstCredit int64
	var firstCollectorUID, firstNodeUID string
	if err = admin.QueryRow(ctx, `SELECT lease_until,credit,collector_pod_uid,node_uid FROM policy_observation_session WHERE root_id=$1 AND capture_id=$2`, root, first).Scan(&firstUntil, &firstCredit, &firstCollectorUID, &firstNodeUID); err != nil || firstCredit != 1 {
		t.Fatal("native refusal lost original one-byte spend", firstCredit, err)
	}
	// A generic failure can also mean stale source, target or provider failure.
	// Require the existing node meter's exact reason from the originally bound
	// collector, rather than misreporting any failed capture as input enforcement.
	boundCollectors, err := f.region.CoreV1().Pods("").List(ctx, meta.ListOptions{LabelSelector: "app.kubernetes.io/name=asservat-node", Limit: 64})
	if err != nil || boundCollectors.Continue != "" {
		t.Fatal("bounded owned collector inventory", err)
	}
	var boundCollector *core.Pod
	for i := range boundCollectors.Items {
		p := &boundCollectors.Items[i]
		if string(p.UID) == firstCollectorUID {
			boundCollector = p
		}
	}
	if boundCollector == nil || boundCollector.DeletionTimestamp != nil || boundCollector.Spec.NodeName == "" {
		t.Fatal("original observation collector Pod missing")
	}
	boundNode, err := f.region.CoreV1().Nodes().Get(ctx, boundCollector.Spec.NodeName, meta.GetOptions{})
	if err != nil || string(boundNode.UID) != firstNodeUID {
		t.Fatal("observation collector changed original Node UID", err)
	}
	wait("exact native one-byte meter refusal", 30*time.Second, func(call context.Context) bool {
		before, err := f.region.CoreV1().Pods(boundCollector.Namespace).Get(call, boundCollector.Name, meta.GetOptions{})
		if err != nil || before.UID != boundCollector.UID || before.Spec.NodeName != boundNode.Name || before.DeletionTimestamp != nil {
			t.Fatal("original collector identity before log read", err)
		}
		logs, err := f.region.CoreV1().Pods(before.Namespace).GetLogs(before.Name, &core.PodLogOptions{Container: "node", LimitBytes: ptr.To(int64(64 << 10)), TailLines: ptr.To(int64(256))}).DoRaw(call)
		if err != nil {
			return false
		}
		after, err := f.region.CoreV1().Pods(before.Namespace).Get(call, before.Name, meta.GetOptions{})
		if err != nil || after.UID != before.UID || after.Spec.NodeName != before.Spec.NodeName || after.DeletionTimestamp != nil {
			t.Fatal("original collector identity after log read", err)
		}
		if !policyRecordingCreditRefusal(logs, first) {
			return false
		}
		afterNode, err := f.region.CoreV1().Nodes().Get(call, boundNode.Name, meta.GetOptions{})
		if err != nil || afterNode.UID != boundNode.UID {
			t.Fatal("original Node identity after meter proof", err)
		}
		return true
	})
	beta := requestReview("native-policy-payload-headers", false)
	// Disable the real creator account after both original requests. Team
	// execution/settings provenance and current sponsor management must survive.
	var requesterSubject string
	if err = admin.QueryRow(ctx, `SELECT requester_subject FROM access_grant WHERE root_id=$1 AND id=$2`, root, beta.ID).Scan(&requesterSubject); err != nil || requesterSubject == "" {
		t.Fatal(err)
	}
	installedPolicyDisableCreator(t, identity.kc, requesterSubject)
	var managerView policyGrant
	must(manager, "get_grant", map[string]any{"grant_id": beta.ID}, &managerView)
	if !managerView.CanRevoke || managerView.NotAfter == nil || !managerView.NotAfter.Equal(*beta.NotAfter) {
		t.Fatal("remaining sponsor lost policy management or renewed bounds", managerView)
	}
	attach(manager, beta)
	browserCall("revoke_grant", installedPolicyRecordingRevocationArguments(alpha.ID, alpha.Revision), nil)
	// Closing the native engine does not refund or prematurely end its original
	// session. Wait that declared interval before admitting the next occurrence.
	if delay := time.Until(firstUntil.Add(100 * time.Millisecond)); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
	restart()
	second := captureAfter(first)
	var progress installedJourneyCaptureProgress
	wait("actual policy packet publication", 2*time.Minute, func(call context.Context) bool {
		if !read(call, manager, "get_capture", map[string]any{"capture_id": second}, &progress) {
			return false
		}
		ready, err := installedJourneyCaptureCaseReady(call, second, progress)
		if err != nil {
			diagnose()
			t.Fatal(err)
		}
		return ready
	})
	var investigation struct {
		Artifacts []struct {
			ID string `json:"artifact_id"`
		} `json:"artifacts"`
	}
	must(manager, "get_case", map[string]any{"case_id": progress.CaseID}, &investigation)
	if len(investigation.Artifacts) != 1 {
		t.Fatal("policy PCAPNG case", len(investigation.Artifacts))
	}
	var status struct {
		Kind       string `json:"collection_kind"`
		Grant      string `json:"attached_grant_id"`
		Executions int64  `json:"executions_spent"`
		Output     int64  `json:"collected_bytes_spent"`
		Input      int64  `json:"observed_bytes_spent"`
	}
	must(manager, "get_policy_status", map[string]any{"policy_name": installedPolicyRecordingName}, &status)
	const expectedInput = int64(48<<20) + 1
	if status.Kind != "packetCapture" || status.Grant != beta.ID || status.Executions != 2 || status.Output != 16<<20 || status.Input != expectedInput {
		t.Fatal("actual shared finite policy reservations", status)
	}
	var secondCredit int64
	var originalGrant string
	if err = admin.QueryRow(ctx, `SELECT o.credit,g.id::text FROM policy_observation_session o JOIN access_grant g ON g.id=o.grant_id AND g.root_id=o.root_id WHERE o.root_id=$1 AND o.capture_id=$2`, root, second).Scan(&secondCredit, &originalGrant); err != nil || secondCredit != 48<<20 || originalGrant != beta.ID {
		t.Fatal("native policy original grant/credit", secondCredit, originalGrant, err)
	}
	var download installedJourneyDownload
	prepare := map[string]any{"artifact_id": investigation.Artifacts[0].ID, "idempotency_key": "native-policy-pcap-download"}
	wait("real policy native download", 2*time.Minute, func(call context.Context) bool {
		name, args := "get_artifact_download", any(map[string]any{"download_id": download.DownloadID})
		if download.DownloadID == "" || download.ContinuePreparation {
			name, args = "prepare_artifact_download", prepare
		}
		return read(call, manager, name, args, &download) && download.State != "Preparing"
	})
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil {
		t.Fatal("policy native download unavailable", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: 2 * time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, reviewer.downloadToken(), nil)
	native, err := io.ReadAll(io.LimitReader(response.Body, artifact.RecordingNativeLimit+1))
	response.Body.Close()
	digest := sha256.Sum256(native)
	if err != nil || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || int64(len(native)) > artifact.RecordingNativeLimit || hex.EncodeToString(digest[:]) != download.SHA256 || bytes.Contains(native, []byte("synthetic-policy-payload-marker")) {
		t.Fatal("policy native byte/privacy proof", response.StatusCode, len(native), err)
	}
	// Preserve the authenticated, already capped native bytes for failure analysis.
	// Only this owned synthetic fixture writes this private artifact; no row or
	// raw payload is rendered in logs. The existing workflow archives results.
	file := filepath.Join("..", "results", "policy-recording.pcapng")
	if err = os.WriteFile(file, native, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(ctx, "tshark", policyRecordingFieldArgs(file)...).Output()
	if err != nil {
		t.Fatal("offline native Wireshark read", err)
	}
	packets, err := policyRecordingPacketFields(out)
	if err != nil {
		t.Logf("native ACK/header evidence retained: policy-recording.pcapng bytes=%d SHA256=%x", len(native), digest)
		t.Fatal("native ACK/header privacy scope", err)
	}
	if packets < 1 {
		t.Fatal("native policy PCAPNG has no actual ACK packets")
	}
	var allocation, pool string
	var protectedMetadata []byte
	if err = admin.QueryRow(ctx, `SELECT a.allocation_id::text,ca.pool_id::text,s.qualification->'RootBacking'->'Metadata'
FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id
JOIN custody_allocation ca ON ca.id=a.allocation_id JOIN capacity_source s ON s.root_id=c.root_id
WHERE c.root_id=$1 AND c.id=$2`, root, second).Scan(&allocation, &pool, &protectedMetadata); err != nil || !json.Valid(protectedMetadata) || string(protectedMetadata) == "null" {
		t.Fatal("actual protected native metadata profile", err)
	}
	graph := samplePolicyObservationGraph(t, ctx, admin, root, allocation, pool)
	logPolicyObservationGraph(t, ctx, admin, "installed-native-published-download", &beforeGraph, graph)
	report := map[string]any{
		"policyUID": active.PolicyUID, "acceptanceID": active.AcceptanceID, "podUID": podUID,
		"failedCaptureID": first, "publishedCaptureID": second, "caseID": progress.CaseID,
		"originalGrantID": alpha.ID, "replacementGrantID": beta.ID, "replacementGrantNotAfter": beta.NotAfter,
		"originalInputCredit": firstCredit, "originalLeaseUntil": firstUntil, "replacementInputCredit": secondCredit,
		"originalCollectorPodUID": firstCollectorUID, "originalNodeUID": firstNodeUID, "oneByteFailureReason": collector.ErrObservationBudgetExhausted.Error(),
		"executionsSpent": status.Executions, "outputReservations": status.Output, "inputReservations": status.Input,
		"nativeBytes": len(native), "nativeSHA256": hex.EncodeToString(digest[:]), "tsharkACKHeaderPackets": packets,
		"creatorDisabled": true, "currentSponsorManaged": true, "originalGrantRevoked": true,
		"protectedMetadataProfile": json.RawMessage(protectedMetadata), "graphSample": graph,
		"backingScope":     "31-table component sample and fixture-global WAL since before policy creation; shared physical relations; operation-audit/lifecycle/download/processing graphs and largest accepted shapes not qualified; no complete backing fit claim",
		"authorization":    "installed public policy request, independent decision, attachment, real restart and production observation permit; no fixture grant or capture rows",
		"measurementScope": "native retained bytes and decoded packet count; input credits are conservative reservations, not measured input; protected worst-case backing remains separate",
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("../results/policy-recording-report.json", append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("UNPUBLISHED installed finite policy proof: native one-byte input refusal, creator departure, current sponsoring-manager replacement, original grant revocation, actual ACK headers PCAPNG %dB/%dpackets SHA256=%x; conservative input reservations=%d, output reservations=%d, no measured-input claim", len(native), packets, digest, status.Input, status.Output)
}

func policyRecordingCreditRefusal(logs []byte, captureID string) bool {
	expected := "node collector: capture " + captureID + " stopped: " + collector.ErrObservationBudgetExhausted.Error()
	for _, line := range strings.Split(string(logs), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), expected) {
			return true
		}
	}
	return false
}

// The offline regression and actual installed read use identical field options.
func policyRecordingFieldArgs(file string) []string {
	return []string{"-r", file, "-T", "fields", "-E", "occurrence=f", "-e", "frame.number", "-e", "tcp.flags.ack", "-e", "tcp.payload"}
}

// Keep the trailing empty payload column; TrimSpace would silently discard a
// valid last packet or hide malformed decoder output during expensive native work.
func policyRecordingPacketFields(out []byte) (int, error) {
	count := 0
	for row, line := range strings.Split(strings.TrimRight(string(out), "\r\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		// The actual maintained tshark fields exporter emits True/False for
		// this boolean, rather than the numeric spelling assumed by the old
		// synthetic rows. Keep a strict ACK-true and empty-payload predicate.
		class := ""
		switch {
		case len(fields) != 3:
			class = "columns"
		case fields[0] == "":
			class = "frame-number"
		case fields[1] != "True":
			class = "ack"
		case fields[2] != "":
			class = "payload"
		}
		if class != "" {
			return 0, fmt.Errorf("native packet violates ACK-only header projection: row %d (%s)", row+1, class)
		}
		count++
	}
	return count, nil
}
