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
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/transport/presentation"
	"github.com/google/pprof/profile"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"mime"
	"os/exec"
)

// This is an installed production-path qualification, never an authority
// provider or alternate start route. Only its guarded native focus may call it.
func qualifyInstalledPolicyArguments(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, identity *installedIdentity, publicRoot []byte, address, origin, regionalConfig string, diagnose func()) {
	qualifyInstalledFiniteRawPolicy(t, ctx, admin, root, identity, publicRoot, address, origin, regionalConfig, diagnose, false)
}

func qualifyInstalledPolicyProfile(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, identity *installedIdentity, publicRoot []byte, address, origin, regionalConfig string, diagnose func()) {
	qualifyInstalledFiniteRawPolicy(t, ctx, admin, root, identity, publicRoot, address, origin, regionalConfig, diagnose, true)
}

func qualifyInstalledFiniteRawPolicy(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, identity *installedIdentity, publicRoot []byte, address, origin, regionalConfig string, diagnose func(), profileMode bool) {
	t.Helper()
	if st, err := os.Stat("/etc/asservat-disposable-host"); err != nil || !st.Mode().IsRegular() {
		t.Fatal("finite policy requires a fresh disposable runner")
	}
	f := installedPolicyTarget
	if f == nil || identity == nil || identity.ReviewerSubject == "" {
		t.Fatal("finite policy lacks installed target or independent reviewer")
	}
	name, kind, prefix, nativeLimit := installedPolicyArgumentsName, "syscallTrace", "policy-arguments", int64(artifact.RecordingNativeLimit)
	policySpec := installedPolicyArgumentsSpec(f.cluster, f.namespace, f.workload)
	binding := installedPolicyArgumentsBinding(f.binding)
	grantInput, rawInput := installedPolicyArgumentsGrantInput, installedPolicyArgumentsRawInput
	if profileMode {
		name, kind, prefix, nativeLimit = installedPolicyProfileName, "profile", "policy-profile", installedPolicyProfileLimit
		policySpec = installedPolicyProfileSpec(f.cluster, f.namespace, f.workload)
		binding = installedPolicyProfileBinding(f.binding)
		grantInput, rawInput = installedPolicyProfileGrantInput, installedPolicyProfileRawInput
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
			t.Fatal("finite policy MCP", name, err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	requester := connect(prefix+"-requester", identity)
	kc := *identity.kc
	kc.username = "reviewer"
	reviewer := &installedIdentity{kc: &kc, Issuer: identity.Issuer, RootPEM: identity.RootPEM, ReviewerSubject: identity.ReviewerSubject}
	manager := connect(prefix+"-manager", reviewer)
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
		t.Fatal("installed finite policy timed out", what)
	}
	readFailures := map[string]int{}
	read := func(call context.Context, s *sdk.ClientSession, name string, args, out any) bool {
		reply, code, err := invoke(call, s, name, args)
		if err != nil || reply.Status != "ok" || code != "" {
			readFailures[name]++
			if n := readFailures[name]; n&(n-1) == 0 {
				t.Logf("policy public read %s refused: status=%s code=%s transport_error=%t count=%d", name, reply.Status, code, err != nil, n)
			}
			return false
		}
		if out != nil && json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("finite policy response", name)
		}
		return true
	}
	must := func(s *sdk.ClientSession, name string, args, out any) {
		t.Helper()
		reply, code, err := invoke(ctx, s, name, args)
		if err != nil || reply.Status != "ok" || code != "" {
			diagnose()
			t.Fatal("finite policy public operation", name, code, err)
		}
		if out != nil && json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("finite policy public data", name)
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
	started := time.Now()
	if !profileMode {
		definition, err := manualArgumentsProfileDefinition()
		if err != nil {
			t.Fatal(err)
		}
		publishNamespaceCaptureProfile(t, ctx, regionalConfig, f.namespace, manualArgumentsProfile, "v1", definition)
	}
	body, _ := json.Marshal(binding)
	if err = f.hub.Post().AbsPath(f.base + "accessbindings").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("operator finite automation envelope", err)
	}
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": name}, "spec": policySpec}
	body, _ = json.Marshal(policy)
	if err = f.hub.Post().AbsPath(f.base + "debugpolicies").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("operator finite raw policy", err)
	}
	var object struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	body, err = f.hub.Get().AbsPath(f.base + "debugpolicies/" + name).DoRaw(ctx)
	if err != nil || json.Unmarshal(body, &object) != nil || object.Metadata.UID == "" {
		t.Fatal("actual policy UID", err)
	}
	var active struct {
		PolicyUID    string `json:"policy_uid"`
		AcceptanceID string `json:"acceptance_id"`
		State        string `json:"state"`
	}
	wait("independently audited finite policy acceptance", 2*time.Minute, func(call context.Context) bool {
		return read(call, requester, "activate_policy", map[string]any{"policy_name": name, "idempotency_key": "argument-policy-activate"}, &active) && active.State == "active"
	})
	if active.PolicyUID != object.Metadata.UID || active.AcceptanceID == "" {
		t.Fatal("activation changed source identity", active)
	}
	type grantView struct {
		ID       string     `json:"grant_id"`
		Kind     string     `json:"kind"`
		Phase    string     `json:"phase"`
		NotAfter *time.Time `json:"not_after"`
		Actions  []struct {
			Kind     string                        `json:"kind"`
			MaxBytes int64                         `json:"max_bytes"`
			Profile  *installedPolicyProfileReview `json:"profile"`
		} `json:"actions"`
		Decision *struct {
			By struct {
				Subject string `json:"subject"`
			} `json:"decided_by"`
		} `json:"decision"`
		RawAccess *struct {
			CaseID         string    `json:"case_id"`
			NotAfter       time.Time `json:"not_after"`
			BytesUsed      int64     `json:"bytes_used"`
			OperationsUsed int64     `json:"operations_used"`
			MaxBytes       int64     `json:"max_bytes"`
			Artifacts      []struct {
				ArtifactID  string                             `json:"artifact_id"`
				CaptureID   string                             `json:"capture_id"`
				Target      presentation.ContextCaseTargetData `json:"target"`
				Digest      string                             `json:"digest"`
				NativeBytes int64                              `json:"native_bytes"`
			} `json:"artifacts"`
		} `json:"raw_access"`
	}
	var collection grantView
	must(requester, "request_policy_grant", grantInput(active.PolicyUID), &collection)
	if collection.ID == "" || collection.Kind != "policy" || collection.Phase != "Pending" || collection.NotAfter == nil {
		t.Fatal("finite policy review", collection)
	}
	if profileMode {
		if len(collection.Actions) != 1 || collection.Actions[0].Kind != "profile" || collection.Actions[0].MaxBytes != nativeLimit || collection.Actions[0].Profile == nil {
			t.Fatal("profile approval has no exact action review")
		}
		p := collection.Actions[0].Profile
		if !installedPolicyProfileReviewMatches(*p, installedPolicyProfileExpectedBinding(t, policySpec)) {
			t.Fatal("profile review lost stable definition/parameters or invented a concrete Pod endpoint", p)
		}
	}
	originalUntil := *collection.NotAfter
	browser.approvedRecordingStepUp(t, ctx, reviewer, collection.ID)
	browserCall("decide_review", installedPolicyRecordingDecisionArguments(collection.ID), nil)
	must(requester, "get_grant", map[string]any{"grant_id": collection.ID}, &collection)
	if collection.Phase != "Approved" || collection.Decision == nil || collection.Decision.By.Subject != identity.ReviewerSubject || collection.NotAfter == nil || !collection.NotAfter.Equal(originalUntil) || collection.RawAccess != nil {
		t.Fatal("policy approval changed collection-only authority", collection)
	}
	must(requester, "activate_policy", map[string]any{"policy_name": name, "grant_id": collection.ID, "idempotency_key": "argument-policy-attach"}, nil)
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
	if !profileMode {
		traffic, endTraffic := context.WithCancel(ctx)
		trafficJoined := make(chan struct{})
		go func() {
			defer close(trafficJoined)
			for traffic.Err() == nil {
				call, stop := context.WithTimeout(traffic, 2*time.Second)
				_, _ = f.region.CoreV1().RESTClient().Get().Namespace(f.namespace).Resource("pods").Name(podName+":8080").SubResource("proxy").Suffix("log").Param("line", "synthetic-approved-recording").DoRaw(call)
				stop()
				if installedJourneyPause(traffic, 100*time.Millisecond) != nil {
					return
				}
			}
		}()
		defer func() { endTraffic(); <-trafficJoined }()
	}
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
	wait("original restart watermark", time.Minute, func(call context.Context) bool {
		var n int
		return admin.QueryRow(call, `SELECT count(*) FROM policy_pod_watermark WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3`, root, active.PolicyUID, podUID).Scan(&n) == nil && n == 1
	})
	if installedPublisherSettled != nil {
		installedPublisherSettled(ctx)
	}
	triggeredAt := time.Now()
	restart()
	var captureID string
	wait("one production finite policy occurrence", 2*time.Minute, func(call context.Context) bool {
		return admin.QueryRow(call, `SELECT coalesce(capture_id::text,'') FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3 AND capture_id IS NOT NULL ORDER BY created_at DESC LIMIT 1`, root, active.PolicyUID, podUID).Scan(&captureID) == nil && captureID != ""
	})
	var progress installedJourneyCaptureProgress
	wait("verified raw policy publication", 2*time.Minute, func(call context.Context) bool {
		if !read(call, requester, "get_capture", map[string]any{"capture_id": captureID}, &progress) {
			return false
		}
		ready, err := installedJourneyCaptureCaseReady(call, captureID, progress)
		if err != nil {
			diagnose()
			t.Fatal(err)
		}
		return ready
	})
	var investigation presentation.ContextCaseData
	must(requester, "get_case", map[string]any{"case_id": progress.CaseID}, &investigation)
	if len(investigation.Artifacts) != 1 {
		t.Fatal("policy case selection", len(investigation.Artifacts))
	}
	a := investigation.Artifacts[0]
	if a.Kind != kind || a.DataClass != "raw" || a.Digest == "" || a.VerifiedNativeBytes == nil || *a.VerifiedNativeBytes <= 0 || *a.VerifiedNativeBytes > nativeLimit || a.Target.PodUID != podUID || a.Target.ClusterID != f.cluster {
		t.Fatal("verified raw case metadata", a)
	}
	// The collection approval is deliberately not disclosure authority. A new
	// exact-artifact human approval must precede any successful download prepare.
	denied, code, err := invoke(ctx, requester, "prepare_artifact_download", map[string]any{"artifact_id": a.ArtifactID, "idempotency_key": "policy-argument-download"})
	if err != nil || denied.Status != "error" || code != "RawApprovalRequired" {
		t.Fatal("collection-only raw prepare must require approval", denied.Status, code, err)
	}
	var raw grantView
	request := rawInput(progress.CaseID, a.Digest, *a.VerifiedNativeBytes)
	must(requester, "request_raw_access", request, &raw)
	if raw.ID == "" || raw.Phase != "Pending" {
		t.Fatal("standalone raw request", raw)
	}
	var replay grantView
	must(requester, "request_raw_access", request, &replay)
	if replay.ID != raw.ID {
		t.Fatal("raw request replay changed grant")
	}
	must(manager, "get_grant", map[string]any{"grant_id": raw.ID}, &raw)
	if raw.Kind != "rawQuery" || raw.RawAccess == nil || raw.RawAccess.CaseID != progress.CaseID || raw.RawAccess.MaxBytes != *a.VerifiedNativeBytes || len(raw.RawAccess.Artifacts) != 1 || raw.RawAccess.Artifacts[0].ArtifactID != a.ArtifactID || raw.RawAccess.Artifacts[0].Digest != a.Digest || raw.RawAccess.Artifacts[0].NativeBytes != *a.VerifiedNativeBytes || raw.RawAccess.Artifacts[0].CaptureID != captureID || raw.RawAccess.Artifacts[0].Target != a.Target || raw.RawAccess.NotAfter.IsZero() {
		t.Fatal("independent exact-artifact review", raw)
	}
	rawUntil := raw.RawAccess.NotAfter
	browser.approvedRecordingStepUp(t, ctx, reviewer, raw.ID)
	browserCall("decide_review", installedPolicyRecordingDecisionArguments(raw.ID), nil)
	must(requester, "get_grant", map[string]any{"grant_id": raw.ID}, &raw)
	if raw.Phase != "Approved" || raw.Decision == nil || raw.Decision.By.Subject != identity.ReviewerSubject || raw.NotAfter == nil || !raw.NotAfter.Equal(rawUntil) {
		t.Fatal("raw approval changed original authority", raw)
	}
	var download installedJourneyDownload
	prepare := map[string]any{"artifact_id": a.ArtifactID, "idempotency_key": "policy-argument-download"}
	wait("approved native policy download", 2*time.Minute, func(call context.Context) bool {
		name, args := "get_artifact_download", any(map[string]any{"download_id": download.DownloadID})
		if download.DownloadID == "" || download.ContinuePreparation {
			name, args = "prepare_artifact_download", prepare
		}
		return read(call, requester, name, args, &download) && download.State != "Preparing"
	})
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil || *download.SizeBytes != *a.VerifiedNativeBytes {
		t.Fatal("approved raw native download unavailable", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: 2 * time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	native, err := io.ReadAll(io.LimitReader(response.Body, nativeLimit+1))
	response.Body.Close()
	digest := sha256.Sum256(native)
	if err != nil || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 {
		t.Fatal("raw native size/hash", response.StatusCode, len(native), err)
	}
	extension := ".jsonl"
	if profileMode {
		extension = ".pb.gz"
	}
	_, disposition, dispositionErr := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	if dispositionErr != nil || disposition["filename"] != "artifact-"+a.ArtifactID+extension {
		t.Fatal("policy native filename", dispositionErr)
	}
	nativeFile := "../results/" + prefix + extension
	if err = os.WriteFile(nativeFile, native, 0600); err != nil {
		t.Fatal(err)
	}
	var originalGrant string
	if err = admin.QueryRow(ctx, `SELECT grant_id::text FROM policy_occurrence WHERE root_id=$1 AND capture_id=$2`, root, captureID).Scan(&originalGrant); err != nil || originalGrant != collection.ID {
		t.Fatal("policy capture changed original grant", originalGrant, err)
	}
	var byteCredit, eventCredit int64
	report := map[string]any{}
	if profileMode {
		p, err := profile.ParseData(native)
		if err != nil || p.CheckValid() != nil || p.DurationNanos < 9_000_000_000 || p.TimeNanos < triggeredAt.Add(-time.Second).UnixNano() {
			t.Fatal("policy CPU profile native parse", err)
		}
		found := false
		for _, fn := range p.Function {
			found = found || fn.Name == "main.burnCPU"
		}
		if !found || a.NativeFormat != "pprof" {
			t.Fatal("policy profile lacks actual workload samples/native format")
		}
		command := exec.CommandContext(ctx, "go", "tool", "pprof", "-top", "-symbolize=none", nativeFile)
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "main.burnCPU") {
			t.Fatal("policy native profile did not open with pprof", err)
		}
		if err = os.WriteFile("../results/"+prefix+"-pprof.txt", output, 0600); err != nil {
			t.Fatal(err)
		}
		var observations int
		if err = admin.QueryRow(ctx, `SELECT count(*) FROM policy_observation_session WHERE root_id=$1 AND capture_id=$2`, root, captureID).Scan(&observations); err != nil || observations != 0 {
			t.Fatal("profile invented observation session", observations, err)
		}
		report["nativePprofOpened"] = true
		report["durationNanos"] = p.DurationNanos
	} else {
		var observationGrant string
		if err = admin.QueryRow(ctx, `SELECT grant_id::text FROM policy_observation_session WHERE root_id=$1 AND capture_id=$2`, root, captureID).Scan(&observationGrant); err != nil || observationGrant != collection.ID {
			t.Fatal("argument observation changed original collection grant", observationGrant, err)
		}
		original := installedArgumentsSQLSource(t, ctx, admin, root)(captureID)
		footer, err := checkManualArgumentsNative(native, podUID, original)
		if err != nil {
			t.Fatal("policy argument original source/mechanism/counters", err)
		}
		byteCredit, eventCredit = original.ByteCredit, original.EventCredit
		report["source"], report["retainedEvents"] = original.Source, footer.Retained
	}
	must(requester, "get_grant", map[string]any{"grant_id": raw.ID}, &raw)
	if raw.RawAccess == nil || raw.RawAccess.BytesUsed != int64(len(native)) || raw.RawAccess.OperationsUsed != 1 {
		t.Fatal("standalone raw pool did not charge the exact single download", raw.RawAccess)
	}
	if profileMode {
		var spentExecutions, spentBytes int64
		if err = admin.QueryRow(ctx, `SELECT policy_executions_spent,policy_bytes_spent FROM access_grant WHERE root_id=$1 AND id=$2`, root, collection.ID).Scan(&spentExecutions, &spentBytes); err != nil || spentExecutions != 1 || spentBytes != nativeLimit {
			t.Fatal("profile grant did not debit exactly one full native allowance", spentExecutions, spentBytes, err)
		}
		report["grantExecutionsSpent"], report["grantNativeBytesSpent"] = spentExecutions, spentBytes
	}
	var status struct {
		Kind       string `json:"collection_kind"`
		Grant      string `json:"attached_grant_id"`
		Executions int64  `json:"executions_spent"`
		Output     int64  `json:"collected_bytes_spent"`
		Bytes      int64  `json:"observed_bytes_spent"`
		Events     int64  `json:"observed_events_spent"`
	}
	must(requester, "get_policy_status", map[string]any{"policy_name": name}, &status)
	if status.Kind != kind || status.Grant != collection.ID || status.Executions != 1 || status.Output != nativeLimit || status.Bytes != byteCredit || status.Events != eventCredit {
		t.Fatal("original shared policy reservations", status)
	}
	for key, value := range map[string]any{"policyUID": active.PolicyUID, "acceptanceID": active.AcceptanceID, "captureID": captureID, "caseID": progress.CaseID, "collectionGrantID": collection.ID, "rawGrantID": raw.ID, "artifactVersion": a.Digest, "nativeBytes": len(native), "nativeSHA256": hex.EncodeToString(digest[:]), "eventCredit": eventCredit, "byteCredit": byteCredit, "collectionOnlyDownloadDenied": true, "rawRequestReplaySameGrant": true, "independentReviewer": identity.ReviewerSubject, "elapsedSeconds": time.Since(started).Seconds(), "authority": "installed protected profile configuration, team policy approval, real restart, independent exact-artifact human raw approval; SQL reads verify results only"} {
		report[key] = value
	}
	body, err = json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("../results/"+prefix+"-report.json", append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("installed finite policy %s: independent collection/raw approvals, %d native bytes SHA256=%x; elapsed=%s", kind, len(native), digest, time.Since(started))
}
