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
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	processcodec "asservat.local/asservat/internal/adapters/processes"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/transport/presentation"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const installedProcessesQueryUnits = 2 * query.PacketSummaryQueryUnits
const installedProcessArgCanary = "synthetic-process-argv-private"
const installedProcessEnvCanary = "synthetic-process-env-private"

func installedProcessesFocus() bool { return installedJourneyFocus() == "manual-processes" }
func manualProcessesArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{"target_ref": map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload}, "requested_retention_seconds": 600, "profile_composition": map[string]any{"components": []any{map[string]any{"id": "inventory", "profileRef": map[string]string{"catalog": "builtin", "name": "inspect-processes", "version": "v1"}}}, "maxTotalBytes": artifact.ProcessNativeLimit, "maxDuration": "10s"}}
}

type savedProcessesBrowserSource struct{ CaptureID, ArtifactID, Version, NativePath string }
type installedProcessesRow struct {
	ProcessRef     string                              `json:"process_ref"`
	PodUID         string                              `json:"pod_uid"`
	DisplayPID     uint32                              `json:"display_pid"`
	ExecutableName string                              `json:"executable_name,omitempty"`
	ExecutablePath string                              `json:"executable_path,omitempty"`
	Runtime        string                              `json:"runtime"`
	IdentityBasis  struct{ Confidence, Reason string } `json:"identity_basis"`
	ParentRef      string                              `json:"parent_ref,omitempty"`
	RSSBytes       uint64                              `json:"rss_bytes"`
	ObservedAt     time.Time                           `json:"observed_at"`
}
type installedProcessesPage struct {
	Kind        string    `json:"kind"`
	CaptureID   string    `json:"capture_id"`
	ArtifactIDs []string  `json:"source_artifact_ids"`
	ExpiresAt   time.Time `json:"expires_at"`
	Section     string    `json:"section"`
	Summary     struct {
		StartedAt     time.Time `json:"started_at"`
		EndedAt       time.Time `json:"ended_at"`
		WireBytes     int64     `json:"observed_wire_bytes"`
		RetainedBytes int64     `json:"retained_bytes"`
		Coverage      struct {
			RequestedPods     int    `json:"requested_pods"`
			CoveredPods       int    `json:"covered_pods"`
			InventoryComplete bool   `json:"process_inventory_complete"`
			TrafficComplete   bool   `json:"traffic_complete"`
			DroppedPackets    uint64 `json:"dropped_packets"`
			StopReason        string `json:"stop_reason"`
		} `json:"coverage"`
		CaptureMode string `json:"capture_mode"`
	} `json:"summary"`
	Processes []installedProcessesRow `json:"processes"`
	Gaps      []string                `json:"gaps"`
	Observed  time.Time               `json:"query_observed_at"`
	Expires   time.Time               `json:"query_expires_at"`
}

// Only the operator-side fixture supplies Kubernetes/SQL facts and synthetic
// source canaries. Installed public services supply all effect/read authority.
func qualifyInstalledManualProcesses(t *testing.T, ctx context.Context, admin *pgxpool.Pool, hub kubernetes.Interface, root string, identity *installedIdentity, publicRoot []byte, address, origin, cluster, namespace, workload string, diagnose func()) {
	t.Helper()
	if !installedProcessesFocus() || identity == nil || installedPolicyTarget == nil || installedPolicyTarget.cluster != cluster || installedPolicyTarget.namespace != namespace || installedPolicyTarget.workload != workload {
		t.Fatal("installed process original target missing")
	}
	region := installedPolicyTarget.region
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
	connect := func(name string, tokens *installedJourneyTokenSource) *sdk.ClientSession {
		client := sdk.NewClient(&sdk.Implementation{Name: name, Version: "1"}, nil)
		session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, tokens.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal("installed processes MCP connect", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		return session
	}
	requester := connect("installed-finite-processes", identity.mcpTokenSource(origin))
	call := func(session *sdk.ClientSession, name string, args any) (installedJourneyEnvelope, string) {
		t.Helper()
		input, err := json.Marshal(args)
		if err != nil || wire.ValidateInput(name, input) != nil {
			t.Fatal("installed processes authored contract", name)
		}
		started := time.Now()
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			diagnose()
			t.Fatal("installed processes transport outcome unknown; no replay", name, err)
		}
		reply, code, err := installedJourneyReplyCode(wire, name, result)
		t.Logf("installed processes %s status=%s code=%s elapsed=%s", name, reply.Status, code, time.Since(started))
		if err != nil {
			t.Fatal(err)
		}
		return reply, code
	}
	invoke := func(name string, args any) (installedJourneyEnvelope, string) { return call(requester, name, args) }
	read := func(name string, args, out any) {
		t.Helper()
		reply, code := invoke(name, args)
		if code != "" || reply.Status != "ok" || out != nil && json.Unmarshal(reply.Data, out) != nil {
			diagnose()
			t.Fatal("installed processes public operation", name, reply.Status, code)
		}
	}
	wait := func(what string, limit time.Duration, done func() bool) {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, limit)
		defer cancel()
		for bounded.Err() == nil {
			if done() {
				return
			}
			if installedJourneyPause(bounded, time.Second) != nil {
				break
			}
		}
		diagnose()
		t.Fatal("installed processes timeout", what)
	}

	pods, err := region.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "app=regional-app"})
	if err != nil || len(pods.Items) != 1 {
		t.Fatal("original process Pod", err)
	}
	pod := pods.Items[0]
	if len(pod.Spec.Containers) != 2 || len(pod.Status.ContainerStatuses) != 2 {
		t.Fatal("whole-Pod two-container fixture missing")
	}
	if !strings.Contains(strings.Join(pod.Spec.Containers[0].Command, " "), installedProcessArgCanary) {
		t.Fatal("actual workload argument canary missing")
	}
	envCanary := false
	for _, e := range pod.Spec.Containers[0].Env {
		if e.Name == "SYNTHETIC_PROCESS_ENV_PRIVATE" && e.Value == installedProcessEnvCanary {
			envCanary = true
		}
	}
	if !envCanary {
		t.Fatal("actual workload environment canary missing")
	}

	submit := func(key string) (string, installedApprovedRecordingPreview) {
		var preview installedApprovedRecordingPreview
		read("preview_capture", manualProcessesArguments(cluster, namespace, workload), &preview)
		if preview.Approval || !preview.Enabled || len(preview.Blockers) != 0 || len(preview.Pods) != 1 || preview.Pods[0].UID != string(pod.UID) || len(preview.Lifecycle.Actions) != 1 {
			t.Fatal("ordinary process preview changed original whole-Pod scope or invented approval", preview)
		}
		original := map[string]any{"preview_id": preview.ID, "idempotency_key": key}
		var receipt struct {
			CaptureID string `json:"capture_id"`
		}
		send := func(input map[string]any) string {
			r, code := invoke("request_capture", input)
			if code == "" && json.Unmarshal(r.Data, &receipt) != nil {
				t.Fatal("process receipt")
			}
			return code
		}
		initial := send(original)
		for retry := 0; initial == "StorageRefreshing" && retry < 5; retry++ {
			if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
				t.Fatal(err)
			}
			initial = send(original)
		}
		resolve := func() (installedJourneyDisposition, error) {
			var d installedJourneyDisposition
			read("resolve_capture_request", map[string]string{"preview_id": preview.ID, "idempotency_key": key}, &d)
			if d.State == "accepted" {
				receipt.CaptureID = d.CaptureID
			}
			return d, nil
		}
		closed, err := installedJourneyRecoverCapture(ctx, initial, resolve, func() (string, string) {
			code := send(map[string]any{"preview_id": preview.ID, "idempotency_key": key, "continue_acquisition": true})
			return code, receipt.CaptureID
		}, func() error {
			d, err := resolve()
			if err != nil || d.State != "accepted" || d.CaptureID != receipt.CaptureID {
				return fmt.Errorf("original process request unresolved")
			}
			return nil
		}, installedJourneyPause, func(id string) (installedJourneyCaptureProgress, error) {
			var p installedJourneyCaptureProgress
			read("get_capture", map[string]string{"capture_id": id}, &p)
			return p, nil
		})
		if err != nil || closed || receipt.CaptureID == "" {
			t.Fatal("process capture not admitted", err, closed)
		}
		return receipt.CaptureID, preview
	}
	capture, originalPreview := submit("installed-original-processes")
	var progress installedJourneyCaptureProgress
	wait("verified process publication", time.Minute, func() bool {
		read("get_capture", map[string]string{"capture_id": capture}, &progress)
		ready, err := installedJourneyCaptureCaseReady(ctx, capture, progress)
		if err != nil {
			t.Fatal(err)
		}
		return ready
	})
	var investigation presentation.ContextCaseData
	read("get_case", map[string]string{"case_id": progress.CaseID}, &investigation)
	if len(investigation.Artifacts) != 1 {
		t.Fatal("process case artifact count")
	}
	a := investigation.Artifacts[0]
	if a.Kind != "processSnapshot" || a.NativeFormat != artifact.ProcessFormat || a.DataClass != "metadata" || a.Target.PodUID != string(pod.UID) || a.Target.ClusterID != cluster || a.Digest == "" || a.VerifiedNativeBytes == nil || *a.VerifiedNativeBytes <= 0 || *a.VerifiedNativeBytes > artifact.ProcessNativeLimit {
		t.Fatal("verified process original metadata", a)
	}
	var download installedJourneyDownload
	wait("ordinary exact process native download", time.Minute, func() bool {
		name, args := "get_artifact_download", any(map[string]string{"download_id": download.DownloadID})
		if download.DownloadID == "" || download.ContinuePreparation {
			name, args = "prepare_artifact_download", map[string]string{"artifact_id": a.ArtifactID, "idempotency_key": "installed-processes-native"}
		}
		r, code := invoke(name, args)
		return code == "" && r.Status == "ok" && json.Unmarshal(r.Data, &download) == nil && download.State != "Preparing"
	})
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil || *download.SizeBytes != *a.VerifiedNativeBytes {
		t.Fatal("process native not ready", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: 2 * time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	native, readErr := io.ReadAll(io.LimitReader(response.Body, artifact.ProcessNativeLimit+1))
	_ = response.Body.Close()
	digest := sha256.Sum256(native)
	_, disposition, dispositionErr := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	if readErr != nil || response.StatusCode != 200 || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 || dispositionErr != nil || disposition["filename"] != "artifact-"+a.ArtifactID+".json" {
		diagnose()
		t.Fatal("process native exact bytes/name", response.StatusCode, len(native), readErr)
	}
	nodeBefore, err := region.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, meta.GetOptions{})
	if err != nil {
		t.Fatal("original process Node provenance", err)
	}
	inventory, err := processcodec.DecodeProcesses(native)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.NodeUID != string(nodeBefore.UID) || inventory.NodeBootID != nodeBefore.Status.NodeInfo.BootID {
		t.Fatal("native process Node/boot differs from original API target")
	}
	currentPod, err := region.CoreV1().Pods(namespace).Get(ctx, pod.Name, meta.GetOptions{})
	if err != nil || currentPod.UID != pod.UID {
		t.Fatal("process original Pod unavailable after capture", err)
	}
	if err := checkInstalledProcessOrigins(inventory, *currentPod); err != nil {
		t.Fatal("original runtime changed across qualification", err)
	}
	if err := checkInstalledProcessOrigins(inventory, pod); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(native), installedProcessArgCanary) || strings.Contains(string(native), installedProcessEnvCanary) {
		t.Fatal("process metadata disclosed argument/environment canary")
	}
	nativePath := "../results/manual-processes.json"
	if err := os.WriteFile(nativePath, native, 0600); err != nil {
		t.Fatal(err)
	}
	source := savedProcessesBrowserSource{CaptureID: capture, ArtifactID: a.ArtifactID, Version: a.Digest, NativePath: nativePath}
	pipeline := &installedPacketTerminalPipeline{limit: 2}
	defer pipeline.finish(t)
	sink := func(wait func()) { pipeline.add(t, wait) }
	mcpVerify := installedProcessesQuerySQLCheck(t, ctx, admin, hub, root, sink)(a.ArtifactID)
	mcpPage := queryInstalledProcessesWithCall(t, ctx, source, func(name string, args any) installedComparisonReply {
		r, _ := invoke(name, args)
		return installedComparisonReply{r}
	}, mcpVerify)
	browserPage := qualifyInstalledProcessesBrowser(t, ctx, cert, address, origin, identity, source, installedProcessesQuerySQLCheck(t, ctx, admin, hub, root, sink))
	pipeline.finish(t)
	if mcpPage.Expires.After(a.ExpiresAt) || browserPage.Expires.After(a.ExpiresAt) {
		t.Fatal("saved process read renewed original evidence expiry")
	}
	if pipeline.admitted != 2 || pipeline.joined != 2 || len(pipeline.pending) != 0 {
		t.Fatal("original process query workers not joined")
	}
	if err := checkInstalledProcessPage(native, source, mcpPage); err != nil {
		t.Fatal("MCP native parity", err)
	}
	if err := checkInstalledProcessPage(native, source, browserPage); err != nil {
		t.Fatal("React native parity", err)
	}
	// Repeat obtains original persisted settings and a fresh preview; no repeated
	// capture is executed or claimed by this reference.
	qualifyManualRecorderRepeatPreview(t, capture, originalPreview, invoke, diagnose)
	stopCapture, _ := submit("installed-stop-processes")
	stopped := qualifyManualProcessesStop(t, ctx, stopCapture, read, invoke)
	report := map[string]any{"captureID": capture, "caseID": progress.CaseID, "artifactID": a.ArtifactID, "podUID": pod.UID, "nodeUID": inventory.NodeUID, "nodeBootID": inventory.NodeBootID, "nativeBytes": len(native), "nativeSHA256": hex.EncodeToString(digest[:]), "origins": len(inventory.Origins), "processes": len(inventory.Processes), "gaps": inventory.Gaps, "queries": 2, "queryUnits": installedProcessesQueryUnits, "queryWorkersJoined": pipeline.joined, "ordinaryCollection": true, "sameNativeMCPReact": true, "argumentEnvironmentCanariesAbsent": true, "repeatPreviewOnly": true, "repeatCaptureExecuted": false, "stopCaptureID": stopCapture, "inFlightStopQualified": stopped, "stopLimitation": "Natural completion before Stop is not an installed blocked-source cancellation proof.", "workerRetirement": "exact terminal; positive SQL retirement required when original Job is gone; surviving terminal remains charged"}
	body, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile("../results/manual-processes-report.json", append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("installed process discovery originalPod=%s origins=%d processes=%d native=%dB SHA256=%x; MCP+React same-native; 4 configured units; original query workers joined; inFlightStop=%t", pod.UID, len(inventory.Origins), len(inventory.Processes), len(native), digest, stopped)
}

// Scheduling stays in Go and preserves the first response's absolute expiry.
// get_target_discovery has no caller idempotency key: Begin is never replayed.
func queryInstalledProcessesWithCall(t *testing.T, ctx context.Context, s savedProcessesBrowserSource, call func(string, any) installedComparisonReply, verify func(string, string) func()) installedProcessesPage {
	t.Helper()
	out := call("get_target_discovery", map[string]any{"capture_id": s.CaptureID, "section": "processes", "limit": 20})
	operation, handle := out.RequestID, ""
	var firstObserved, firstExpiry time.Time
	parse := func(r installedComparisonReply) (string, int) {
		var p struct {
			Handle   string    `json:"query_handle"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
			Retry    int       `json:"retry_after_seconds"`
		}
		if json.Unmarshal(r.Data, &p) != nil || p.Observed.IsZero() || !p.Expires.After(p.Observed) {
			t.Fatal("process original query interval")
		}
		if firstExpiry.IsZero() {
			firstObserved, firstExpiry = p.Observed, p.Expires
		} else if !firstExpiry.Equal(p.Expires) {
			t.Fatal("process query renewed expiry")
		}
		return p.Handle, p.Retry
	}
	for attempts := 0; out.Status == "pending"; attempts++ {
		h, retry := parse(out)
		if h == "" || handle != "" && handle != h || retry < 1 || retry > 60 || attempts >= 4 {
			t.Fatal("process bounded pending lineage")
		}
		handle = h
		target, err := installedProjectionPollTime(firstObserved, firstExpiry, time.Now(), time.Duration(retry)*time.Second, attempts)
		if err != nil {
			t.Fatal(err)
		}
		if err = installedJourneyPause(ctx, time.Until(target)); err != nil {
			t.Fatal(err)
		}
		out = call("get_query_result", map[string]any{"query_handle": handle})
	}
	inner := out
	if len(out.Provenance) == 0 {
		var nested struct {
			Tool     string                   `json:"tool_name"`
			Handle   string                   `json:"query_handle"`
			Result   installedComparisonReply `json:"result"`
			Observed time.Time                `json:"query_observed_at"`
			Expires  time.Time                `json:"query_expires_at"`
		}
		if json.Unmarshal(out.Data, &nested) != nil || nested.Tool != "get_target_discovery" || nested.Handle != handle {
			t.Fatal("process nested source association")
		}
		inner = nested.Result
		var clocks struct {
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
		}
		if json.Unmarshal(inner.Data, &clocks) != nil || !clocks.Observed.Equal(nested.Observed) || !clocks.Expires.Equal(nested.Expires) {
			t.Fatal("process nested clock mismatch")
		}
	}
	var page installedProcessesPage
	if out.Status != "ok" || inner.Status != "ok" || out.DataClass != "extract" || inner.DataClass != "extract" || len(inner.Provenance) != 1 || inner.Provenance[0].ArtifactID != s.ArtifactID || inner.Provenance[0].Digest != s.Version || json.Unmarshal(inner.Data, &page) != nil || page.Kind != "discoveryPage" || page.CaptureID != s.CaptureID || len(page.ArtifactIDs) != 1 || page.ArtifactIDs[0] != s.ArtifactID || page.Section != "processes" || page.Processes == nil || page.Observed.IsZero() || !page.Expires.After(page.Observed) || !page.ExpiresAt.Equal(page.Expires) || !firstExpiry.IsZero() && !firstExpiry.Equal(page.Expires) {
		t.Fatal("process approved source/provenance/clock")
	}
	raw, _ := json.Marshal(inner)
	if strings.Contains(string(raw), installedProcessArgCanary) || strings.Contains(string(raw), installedProcessEnvCanary) {
		t.Fatal("process page exposed private canary")
	}
	if verify(handle, operation) == nil {
		t.Fatal("missing exact process SQL/worker/key proof")
	}
	return page
}

func checkInstalledProcessOrigins(p artifact.ProcessInventory, pod core.Pod) error {
	if !p.Valid() || p.PodUID != string(pod.UID) || p.Mode != artifact.ProcessAll || len(p.Origins) != len(pod.Status.ContainerStatuses) || len(p.Origins) != 2 || len(p.Processes) < 2 {
		return fmt.Errorf("original whole-Pod inventory missing")
	}
	expected := map[string]core.ContainerStatus{}
	for _, s := range pod.Status.ContainerStatuses {
		if s.State.Running == nil || s.ContainerID == "" {
			return fmt.Errorf("fixture original runtime not running")
		}
		expected[s.ContainerID] = s
	}
	for _, o := range p.Origins {
		s, ok := expected[o.RuntimeID]
		if !ok || o.Outcome != "observed" || o.RestartCount != uint32(s.RestartCount) {
			return fmt.Errorf("origin substituted exact runtime/restart")
		}
		main := false
		for _, r := range p.Processes {
			if r.Main && r.Identity.RuntimeID == o.RuntimeID && r.Identity.HostPID == o.MainPID {
				main = true
				if r.Identity.PodUID != string(pod.UID) || r.Identity.NodeBootID != p.NodeBootID || r.Identity.StartTimeTicks == 0 || r.Identity.CgroupID == 0 || !strings.Contains(r.Identity.CgroupPath, strings.TrimPrefix(o.RuntimeID, "containerd://")) {
					return fmt.Errorf("main kernel identity missing")
				}
			}
		}
		if !main {
			return fmt.Errorf("runtime main not recorded")
		}
	}
	return nil
}

func checkInstalledProcessPage(native []byte, s savedProcessesBrowserSource, p installedProcessesPage) error {
	inventory, err := processcodec.DecodeProcesses(native)
	if err != nil {
		return err
	}
	coverage := p.Summary.Coverage
	complete := inventory.Mode == artifact.ProcessAll
	covered := 0
	stop := "completed"
	for _, o := range inventory.Origins {
		if o.Outcome == "observed" {
			covered = 1
		} else {
			complete = false
			stop = "capabilityGap"
		}
	}
	if covered == 0 {
		complete = false
		stop = "capabilityGap"
	}
	for _, g := range inventory.Gaps {
		if g != "socketOwnersUnsupported" {
			complete = false
			if g == "processLimit" || g == "containerLimit" || g == "cgroupLimit" {
				stop = "outputLimit"
			} else if stop != "outputLimit" {
				stop = "capabilityGap"
			}
		}
	}
	if p.CaptureID != s.CaptureID || len(p.ArtifactIDs) != 1 || p.ArtifactIDs[0] != s.ArtifactID || p.Summary.CaptureMode != "none" || p.Summary.WireBytes != 0 || p.Summary.RetainedBytes != int64(len(native)) || !p.Summary.StartedAt.Equal(inventory.StartedAt) || !p.Summary.EndedAt.Equal(inventory.CompletedAt) || coverage.RequestedPods != 1 || coverage.CoveredPods != covered || coverage.InventoryComplete != complete || coverage.TrafficComplete || coverage.DroppedPackets != 0 || coverage.StopReason != stop || len(p.Gaps) != len(inventory.Gaps) || len(p.Processes) < 2 || len(p.Processes) > len(inventory.Processes) {
		return fmt.Errorf("page changed original coverage/window")
	}
	for i, g := range inventory.Gaps {
		if p.Gaps[i] != g {
			return fmt.Errorf("page changed capability gaps")
		}
	}
	version, err := hex.DecodeString(s.Version)
	if err != nil || len(version) != 32 {
		return fmt.Errorf("invalid protected version")
	}
	refs := map[string]artifact.ProcessRecord{}
	for _, r := range inventory.Processes {
		b, _ := json.Marshal(r.Identity)
		h := sha256.New()
		h.Write([]byte("process-ref/v1\x00" + s.CaptureID + s.ArtifactID))
		h.Write(version)
		h.Write(b)
		refs[hex.EncodeToString(h.Sum(nil))] = r
	}
	seen := map[string]bool{}
	if len(p.Processes) != min(20, len(inventory.Processes)) {
		return fmt.Errorf("first page silently omitted a row")
	}
	for i, r := range p.Processes {
		original, ok := refs[r.ProcessRef]
		if original.Identity != inventory.Processes[i].Identity {
			return fmt.Errorf("page changed original process order")
		}
		if !ok || seen[r.ProcessRef] || r.PodUID != inventory.PodUID || r.DisplayPID != original.NamespacePID || r.ExecutablePath != original.ExecutablePath || r.RSSBytes != original.RSSBytes || !r.ObservedAt.Equal(original.ObservedAt) || r.Runtime != "unknown" || r.IdentityBasis.Confidence != "observed" || r.IdentityBasis.Reason == "" {
			return fmt.Errorf("page row changed exact native identity/value")
		}
		seen[r.ProcessRef] = true
		if r.ParentRef != "" {
			parent, ok := refs[r.ParentRef]
			if !ok || !parent.Main || original.Main || parent.Identity.RuntimeID != original.Identity.RuntimeID || original.ParentPID != parent.Identity.HostPID {
				return fmt.Errorf("fabricated process parent")
			}
		}
	}
	return nil
}

// A fast finite snapshot may finish before cancellation can be requested. That
// outcome is retained as a limitation rather than presented as a Stop proof.
func qualifyManualProcessesStop(t *testing.T, ctx context.Context, id string, read func(string, any, any), invoke func(string, any) (installedJourneyEnvelope, string)) bool {
	t.Helper()
	call, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var p struct {
		CaptureID string `json:"capture_id"`
		Phase     string `json:"phase"`
		Revision  int64  `json:"revision"`
		CaseID    string `json:"case_id"`
	}
	for call.Err() == nil {
		read("get_capture", map[string]string{"capture_id": id}, &p)
		if p.CaptureID != id || p.Revision < 1 {
			t.Fatal("process Stop original progress")
		}
		if p.Phase == "Running" {
			break
		}
		if p.Phase == "Succeeded" {
			t.Log("process snapshot completed before Stop; blocked-source installed cancellation remains unqualified")
			return false
		}
		if p.Phase != "Pending" {
			t.Fatal("process Stop unexpected phase", p.Phase)
		}
		if installedJourneyPause(call, time.Second) != nil {
			break
		}
	}
	if p.Phase != "Running" {
		t.Fatal("process Stop observation timed out")
	}
	r, code := invoke("cancel_capture", map[string]any{"capture_id": id, "expected_revision": p.Revision, "idempotency_key": "stop-processes-" + id})
	// Completion can win the race after the actual Running observation.
	if code != "" {
		read("get_capture", map[string]string{"capture_id": id}, &p)
		if p.Phase == "Succeeded" {
			t.Log("process completed concurrently with Stop; no cancellation qualification")
			return false
		}
		t.Fatal("process Stop refused", code)
	}
	var reply struct {
		CaptureID string `json:"capture_id"`
		Requested bool   `json:"cancellation_requested"`
	}
	if r.Status != "ok" || json.Unmarshal(r.Data, &reply) != nil || reply.CaptureID != id || !reply.Requested {
		t.Fatal("process Stop did not acknowledge original request")
	}
	for call.Err() == nil {
		read("get_capture", map[string]string{"capture_id": id}, &p)
		if p.CaptureID != id {
			t.Fatal("process Stop changed capture")
		}
		if p.Phase == "Cancelled" {
			break
		}
		if p.Phase == "Succeeded" {
			t.Log("process publication won acknowledged cancellation race; no joined Stop qualification")
			return false
		}
		if p.Phase != "Running" && p.Phase != "Pending" {
			t.Fatal("process Stop failed", p.Phase)
		}
		if installedJourneyPause(call, time.Second) != nil {
			break
		}
	}
	if p.Phase != "Cancelled" {
		t.Fatal("process Stop missing joined terminal")
	}
	if p.CaseID != "" {
		var c struct {
			Artifacts []json.RawMessage `json:"artifacts"`
		}
		read("get_case", map[string]string{"case_id": p.CaseID}, &c)
		if len(c.Artifacts) != 0 {
			t.Fatal("joined cancelled process published evidence")
		}
	}
	return true
}
