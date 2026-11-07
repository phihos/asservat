package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	logcodec "asservat.local/asservat/internal/adapters/logs"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/transport/presentation"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

const installedLogsQueries = 2
const installedLogsQueryUnits = installedLogsQueries * query.LogQueryUnits
const installedLogsNativeLimit = 1 << 20
const installedLogsMarker = "synthetic-finite-saved-logs"

func installedLogsFocus() bool { return installedJourneyFocus() == "manual-logs" }
func manualLogsArguments(cluster, namespace, workload string, stop bool) map[string]any {
	after, timeout := "2s", "15s"
	if stop {
		after, timeout = "30s", "40s"
	}
	return map[string]any{"target_ref": map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload}, "requested_retention_seconds": 600, "profile_composition": map[string]any{"components": []any{map[string]any{"id": "logs", "profileRef": map[string]string{"catalog": "builtin", "name": "finite-logs", "version": "v1"}, "overrides": []any{map[string]any{"actionID": "logs", "field": "logBefore", "value": "1h"}, map[string]any{"actionID": "logs", "field": "logAfter", "value": after}, map[string]any{"actionID": "logs", "field": "actionTimeout", "value": timeout}, map[string]any{"actionID": "logs", "field": "actionMaxBytes", "value": installedLogsNativeLimit}}}}, "maxTotalBytes": installedLogsNativeLimit, "maxDuration": timeout}}
}

type installedLogsEntry struct {
	Origin struct {
		OriginID      uint16  `json:"origin_id"`
		ContainerKind string  `json:"container_kind"`
		ContainerName string  `json:"container_name"`
		Source        string  `json:"source"`
		Stream        string  `json:"stream"`
		RuntimeID     *string `json:"runtime_id"`
		RestartCount  *uint32 `json:"restart_count"`
	} `json:"origin"`
	Fragment     uint64  `json:"fragment"`
	Line         uint64  `json:"line"`
	Offset       uint64  `json:"offset"`
	LineOffset   uint64  `json:"line_offset"`
	Continuation bool    `json:"continuation"`
	EndLine      bool    `json:"end_line"`
	SourceTime   *string `json:"source_time"`
	Text         *string `json:"text"`
	BytesBase64  *string `json:"bytes_base64"`
}
type installedLogsPage struct {
	Kind        string               `json:"kind"`
	PodUID      string               `json:"pod_uid"`
	WindowStart time.Time            `json:"window_start"`
	WindowEnd   time.Time            `json:"window_end"`
	Entries     []installedLogsEntry `json:"entries"`
	Coverage    struct {
		Origins     uint16 `json:"origins"`
		Complete    uint16 `json:"complete_origins"`
		Partial     uint16 `json:"partial_origins"`
		Unavailable uint16 `json:"unavailable_origins"`
		Unknown     uint16 `json:"unknown_timestamp_origins"`
		Gapped      uint16 `json:"gapped_origins"`
		SourceBytes uint64 `json:"source_bytes"`
		Fragments   uint64 `json:"total_fragments"`
	} `json:"coverage"`
	Observed time.Time `json:"query_observed_at"`
	Expires  time.Time `json:"query_expires_at"`
}

func installedLogsRequest(s savedLogsBrowserSource, key string) map[string]any {
	return map[string]any{"case_id": s.CaseID, "artifact_id": s.ArtifactID, "grant_id": s.GrantID, "idempotency_key": key, "limit": 100}
}

// Go owns scheduling and paid polls; Chromium uses the same bounded protocol.
// A same-key Begin is always replayed for MCP, including an immediate page.
func queryInstalledLogsWithCall(t *testing.T, ctx context.Context, s savedLogsBrowserSource, request map[string]any, call func(string, any) installedComparisonReply, verify func(string, string) func(), replay bool) installedLogsPage {
	t.Helper()
	out := call("get_logs", request)
	operation, handle := out.RequestID, ""
	checked := false
	defer func() {
		if !checked && operation != "" {
			verify(handle, operation)
		}
	}()
	var firstExpiry time.Time
	parseTimes := func(r installedComparisonReply) (string, time.Time, time.Time, int) {
		var p struct {
			Handle   string    `json:"query_handle"`
			Observed time.Time `json:"query_observed_at"`
			Expires  time.Time `json:"query_expires_at"`
			Retry    int       `json:"retry_after_seconds"`
		}
		if json.Unmarshal(r.Data, &p) != nil || p.Observed.IsZero() || !p.Expires.After(p.Observed) || p.Expires.After(s.Expires) {
			t.Fatal("logs response original interval")
		}
		if firstExpiry.IsZero() {
			firstExpiry = p.Expires
		} else if !p.Expires.Equal(firstExpiry) {
			t.Fatal("logs query renewed original expiry")
		}
		return p.Handle, p.Observed, p.Expires, p.Retry
	}
	if out.Status != "pending" && out.Status != "ok" {
		t.Fatal("initial saved logs unavailable", out.Status)
	}
	originalHandle, initialObserved, _, _ := parseTimes(out)
	if replay {
		again := call("get_logs", request)
		h, _, _, _ := parseTimes(again)
		if again.Status != "pending" || h == "" || originalHandle != "" && h != originalHandle {
			t.Fatal("same-key logs replay replaced lineage/disclosed page")
		}
		handle = h
	}
	for attempts := 0; out.Status == "pending"; attempts++ {
		h, _, _, retry := parseTimes(out)
		if h == "" || handle != "" && h != handle || retry < 1 || retry > 60 || attempts >= 4 {
			t.Fatal("logs bounded original pending lineage")
		}
		handle = h
		target, err := installedProjectionPollTime(initialObserved, firstExpiry, time.Now(), time.Duration(retry)*time.Second, attempts)
		if err != nil {
			t.Fatal(err)
		}
		if err = installedJourneyPause(ctx, time.Until(target)); err != nil {
			t.Fatal(err)
		}
		out = call("get_query_result", map[string]any{"query_handle": handle})
	}
	var inner installedComparisonReply
	outerObserved, outerExpires := time.Time{}, time.Time{}
	if len(out.Provenance) == 0 {
		var nested struct {
			Tool     string                   `json:"tool_name"`
			QueryID  string                   `json:"query_handle"`
			Result   installedComparisonReply `json:"result"`
			Observed time.Time                `json:"query_observed_at"`
			Expires  time.Time                `json:"query_expires_at"`
		}
		if json.Unmarshal(out.Data, &nested) != nil || nested.Tool != "get_logs" || nested.QueryID != handle {
			t.Fatal("nested logs association")
		}
		inner = nested.Result
		outerObserved, outerExpires = nested.Observed, nested.Expires
	} else {
		inner = out
	}
	var page installedLogsPage
	if out.Status != "ok" || inner.Status != "ok" || out.DataClass != "raw" || inner.DataClass != "raw" || len(inner.Provenance) != 1 || inner.Provenance[0].ArtifactID != s.ArtifactID || inner.Provenance[0].Digest != s.Version || json.Unmarshal(inner.Data, &page) != nil || page.Kind != "logs" || page.PodUID != s.PodUID || page.Entries == nil || page.WindowEnd.Before(page.WindowStart) || !page.Expires.Equal(firstExpiry) || !page.Expires.After(page.Observed) {
		t.Fatal("logs raw page lost exact source/times")
	}
	if !outerObserved.IsZero() && (!page.Observed.Equal(outerObserved) || !page.Expires.Equal(outerExpires)) {
		t.Fatal("inner/outer logs clocks differ in same response")
	}
	if verify(handle, operation) == nil {
		t.Fatal("logs missing SQL/key/worker proof")
	}
	checked = true
	return page
}

// Native parity is independently walked over the authenticated downloaded JSONL.
// Returned pages must preserve exact saved bytes, origin identities and offsets.
func checkInstalledLogsParity(native []byte, pod string, pages ...installedLogsPage) (artifact.LogFooter, error) {
	var header artifact.LogHeader
	var origin artifact.LogOrigin
	var origins []artifact.LogOrigin
	var fragments []artifact.LogFragment
	var coverage []artifact.LogCoverage
	footer, err := logcodec.Walk(context.Background(), bytes.NewReader(native), installedLogsNativeLimit, logcodec.Visitor{Header: func(h artifact.LogHeader) error { header = h; return nil }, Origin: func(o artifact.LogOrigin) error { origin = o; origins = append(origins, origin); return nil }, Fragment: func(f artifact.LogFragment) error { fragments = append(fragments, f); return nil }, Coverage: func(c artifact.LogCoverage) error { coverage = append(coverage, c); return nil }})
	if err != nil || header.PodUID != pod {
		return footer, fmt.Errorf("original logs native: %w", err)
	}
	for _, p := range pages {
		if p.PodUID != pod || !p.WindowStart.Equal(header.WindowStart) || !p.WindowEnd.Equal(header.WindowEnd) || p.Coverage.Origins != header.Origins || p.Coverage.SourceBytes != footer.SourceBytes || p.Coverage.Fragments != footer.Fragments {
			return footer, fmt.Errorf("logs page changed original native coverage")
		}
		var complete, partial, unavailable, unknown, gapped uint16
		for _, c := range coverage {
			switch c.FetchOutcome {
			case "complete":
				complete++
			case "partial":
				partial++
			case "unavailable":
				unavailable++
			}
			if len(c.Gaps) > 0 {
				gapped++
			}
			for _, g := range c.Gaps {
				if g == "timestampUnknown" {
					unknown++
				}
			}
		}
		if p.Coverage.Complete != complete || p.Coverage.Partial != partial || p.Coverage.Unavailable != unavailable || p.Coverage.Unknown != unknown || p.Coverage.Gapped != gapped {
			return footer, fmt.Errorf("logs page changed known/unknown native coverage")
		}
		for _, e := range p.Entries {
			if e.Fragment >= uint64(len(fragments)) || (e.Text == nil) == (e.BytesBase64 == nil) {
				return footer, fmt.Errorf("logs page invalid fragment/encoding")
			}
			f := fragments[e.Fragment]
			o := origins[f.OriginID]
			raw, _ := f.Bytes()
			var b []byte
			if e.Text != nil {
				b = []byte(*e.Text)
				if !utf8.Valid(b) {
					return footer, fmt.Errorf("invalid bytes rewritten as text")
				}
			} else {
				b, err = base64.StdEncoding.Strict().DecodeString(*e.BytesBase64)
				if err != nil {
					return footer, err
				}
			}
			offset := int64(e.Offset) - int64(f.Offset)
			if offset < 0 || offset+int64(len(b)) > int64(len(raw)) || !bytes.Equal(b, raw[offset:offset+int64(len(b))]) || e.Line != f.Line || e.LineOffset != f.LineOffset+uint64(offset) || e.Continuation != (e.LineOffset > 0) || e.EndLine != (f.EndLine && offset+int64(len(b)) == int64(len(raw))) || !reflect.DeepEqual(e.SourceTime, f.SourceTime) || e.Origin.OriginID != o.OriginID || e.Origin.ContainerKind != o.ContainerKind || e.Origin.ContainerName != o.ContainerName || e.Origin.Source != o.Source || e.Origin.Stream != "combined" || !reflect.DeepEqual(e.Origin.RuntimeID, o.RuntimeID) || !reflect.DeepEqual(e.Origin.RestartCount, o.RestartCount) {
				return footer, fmt.Errorf("logs page bytes/provenance differ from native")
			}
		}
	}
	return footer, nil
}

// This focused journey uses the provisioned API-only connector. Administrator
// Kubernetes/SQL reads set up synthetic bytes and verify outcomes; they never
// provide capture, query, approval or key authority to the installed product.
func installedLogsListenerReady(ctx context.Context, region kubernetes.Interface, namespace, podName string) bool {
	_, err := region.CoreV1().RESTClient().Get().Namespace(namespace).Resource("pods").Name(podName+":8080").SubResource("proxy").Suffix("traffic").Param("records", "1").DoRaw(ctx)
	return err == nil
}

func qualifyInstalledManualLogs(t *testing.T, ctx context.Context, admin *pgxpool.Pool, hub kubernetes.Interface, root string, identity *installedIdentity, publicRoot []byte, address, origin, regionalConfig, cluster, namespace, workload string, diagnose func()) {
	t.Helper()
	if !installedLogsFocus() || identity == nil || identity.ReviewerSubject == "" || installedPolicyTarget == nil || installedPolicyTarget.cluster != cluster || installedPolicyTarget.namespace != namespace || installedPolicyTarget.workload != workload {
		t.Fatal("installed logs target/reviewer missing")
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
	initialized := false
	if installedRerunMode() != "" {
		// A development-only rerun's earlier run may have initialized
		// processing already; the product refuses a second initialization.
		if err := admin.QueryRow(ctx, `SELECT initialized_at IS NOT NULL FROM processing_root WHERE root_id=$1`, root).Scan(&initialized); err != nil {
			t.Fatal("kept processing state", err)
		}
	}
	if !initialized {
		identity.initializeProcessing(t, ctx, cert, address, origin, diagnose)
	}
	connect := func(name string, tokens *installedJourneyTokenSource) *sdk.ClientSession {
		client := sdk.NewClient(&sdk.Implementation{Name: name, Version: "1"}, nil)
		session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, tokens.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal("installed logs MCP connect", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		return session
	}
	requester := connect("installed-finite-logs", identity.mcpTokenSource(origin))
	rawSession := connect("installed-saved-logs-raw", identity.packetQueryTokenSource(origin))
	call := func(session *sdk.ClientSession, name string, args any) (installedJourneyEnvelope, string) {
		t.Helper()
		input, err := json.Marshal(args)
		if err != nil || wire.ValidateInput(name, input) != nil {
			t.Fatal("installed logs authored contract", name)
		}
		started := time.Now()
		result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			diagnose()
			t.Fatal("installed logs transport outcome unknown; no replay", name, err)
		}
		reply, code, err := installedJourneyReplyCode(wire, name, result)
		t.Logf("installed logs %s status=%s code=%s elapsed=%s", name, reply.Status, code, time.Since(started))
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
			t.Fatal("installed logs public operation", name, reply.Status, code)
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
		t.Fatal("installed logs timeout", what)
	}
	// Set up previous/current, init and ephemeral bytes BEFORE original preview.
	pods, err := region.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "app=regional-app"})
	if err != nil || len(pods.Items) != 1 {
		t.Fatal("logs original Pod", err)
	}
	pod := pods.Items[0]
	podName, podUID := pod.Name, string(pod.UID)
	proxy := func(method, path, line string) {
		t.Helper()
		request := region.CoreV1().RESTClient().Verb(method).Namespace(namespace).Resource("pods").Name(podName + ":8080").SubResource("proxy").Suffix(path)
		if line != "" {
			request = request.Param("line", line)
		}
		_, err := request.DoRaw(ctx)
		if path == "exit" {
			t.Logf("single synthetic exit request transportError=%t; original Pod restart is checked independently", err != nil)
		}
		if err != nil && path != "exit" {
			t.Fatal("synthetic logs workload", path, err)
		}
	}
	proxy(http.MethodGet, "log", installedLogsMarker+"-previous")
	oldRestart, oldID := int32(0), ""
	for _, s := range pod.Status.ContainerStatuses {
		if s.Name == "app" {
			oldRestart, oldID = s.RestartCount, s.ContainerID
		}
	}
	proxy(http.MethodPost, "exit", "") // One fixture exit; actual same-Pod restart proves it.
	wait("same-Pod current/previous instances", time.Minute, func() bool {
		p, e := region.CoreV1().Pods(namespace).Get(ctx, podName, meta.GetOptions{})
		if e != nil {
			return false
		}
		if string(p.UID) != podUID {
			t.Fatal("logs setup substituted Pod")
		}
		for _, s := range p.Status.ContainerStatuses {
			if s.Name == "app" && s.RestartCount > oldRestart && s.ContainerID != "" && s.ContainerID != oldID && s.State.Running != nil {
				pod = *p
				return true
			}
		}
		return false
	})
	wait("restarted synthetic HTTP listener", 30*time.Second, func() bool {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return installedLogsListenerReady(c, region, namespace, podName)
	})
	proxy(http.MethodGet, "log", installedLogsMarker+"-current\n\n\xff\x00\n"+strings.Repeat("long-line-", 400))
	ep := pod.DeepCopy()
	ep.Spec.EphemeralContainers = append(ep.Spec.EphemeralContainers, core.EphemeralContainer{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "log-ephemeral" + installedRunSuffix(), Image: pod.Spec.Containers[0].Image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/provider-proxy", "signals-once"}, SecurityContext: &core.SecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}})
	if _, err := region.CoreV1().Pods(namespace).UpdateEphemeralContainers(ctx, podName, ep, meta.UpdateOptions{}); err != nil {
		t.Fatal("synthetic ephemeral logs source", err)
	}
	wait("original init/ephemeral sources completed", time.Minute, func() bool {
		p, e := region.CoreV1().Pods(namespace).Get(ctx, podName, meta.GetOptions{})
		if e != nil {
			return false
		}
		if string(p.UID) != podUID {
			t.Fatal("logs setup substituted Pod")
		}
		for _, s := range p.Status.EphemeralContainerStatuses {
			if s.Name == "log-ephemeral"+installedRunSuffix() && s.State.Terminated != nil && s.State.Terminated.ExitCode == 0 {
				pod = *p
				return true
			}
		}
		return false
	})

	reviewerKC := *identity.kc
	reviewerKC.username = "reviewer"
	reviewer := &installedIdentity{kc: &reviewerKC, Issuer: identity.Issuer, RootPEM: identity.RootPEM, ReviewerSubject: identity.ReviewerSubject}
	reviewBrowser := reviewer.consoleSession(t, ctx, cert, address, origin)
	approve := func(id string) {
		t.Helper()
		reviewBrowser.approvedRecordingStepUp(t, ctx, reviewer, id)
		reply, status, err := reviewBrowser.operation(ctx, "decide_review", installedPolicyRecordingDecisionArguments(id), "native-decision-"+id)
		if err != nil || status != 200 || reply.Status != "ok" {
			t.Fatal("logs independent fresh decision", status, err)
		}
	}
	submit := func(args map[string]any, key string) (string, installedApprovedRecordingPreview, string) {
		t.Helper()
		var preview installedApprovedRecordingPreview
		read("preview_capture", args, &preview)
		if !preview.readyForApproval(time.Now()) || preview.Pods[0].UID != podUID || len(preview.Lifecycle.Actions) != 1 {
			t.Fatal("protected logs lost actual required review/original Pod", preview.Blockers)
		}
		operations, ok := preview.resultAccessOperations(preview.Lifecycle.Actions[0].ActionID, []string{"download_artifact", "get_logs"})
		if !ok {
			t.Fatal("actual protected preview did not offer logs result operations")
		}
		original := map[string]any{"preview_id": preview.ID, "idempotency_key": key, "result_access": map[string]any{"actionIds": []string{preview.Lifecycle.Actions[0].ActionID}, "operations": operations, "clientIDs": []string{"console", "mcp"}, "maxArtifacts": 1, "maxBytes": 16 << 20, "maxOperations": 16, "notAfter": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}
		resolution := map[string]string{"preview_id": preview.ID, "idempotency_key": key}
		var receipt struct {
			CaptureID string `json:"capture_id"`
		}
		send := func(input map[string]any) string {
			reply, code := invoke("request_capture", input)
			if code == "" && json.Unmarshal(reply.Data, &receipt) != nil {
				t.Fatal("logs capture receipt")
			}
			return code
		}
		pending, code := invoke("request_capture", original)
		var navigation struct {
			URI string `json:"navigation_uri"`
		}
		if code != "ApprovalRequired" || json.Unmarshal(pending.Data, &navigation) != nil {
			t.Fatal("protected logs did not require one independent combined approval", code)
		}
		u, err := url.Parse(navigation.URI)
		if err != nil {
			t.Fatal(err)
		}
		grantID := strings.TrimPrefix(u.Path, "/approvals/")
		if len(grantID) != 36 || grantID == u.Path {
			t.Fatal("logs combined grant identity")
		}
		approve(grantID)
		initial := send(original)
		for retry := 0; initial == "StorageRefreshing" && retry < 5; retry++ {
			if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
				t.Fatal(err)
			}
			initial = send(original)
		}
		resolve := func() (installedJourneyDisposition, error) {
			var d installedJourneyDisposition
			read("resolve_capture_request", resolution, &d)
			if d.State == "accepted" {
				receipt.CaptureID = d.CaptureID
			}
			return d, nil
		}
		continuation := map[string]any{"preview_id": preview.ID, "idempotency_key": key, "continue_acquisition": true}
		closed, err := installedJourneyRecoverCapture(ctx, initial, resolve, func() (string, string) { code := send(continuation); return code, receipt.CaptureID }, func() error {
			d, err := resolve()
			if err != nil || d.State != "accepted" || d.CaptureID != receipt.CaptureID {
				return fmt.Errorf("logs original request unresolved")
			}
			return nil
		}, installedJourneyPause, func(id string) (installedJourneyCaptureProgress, error) {
			var p installedJourneyCaptureProgress
			read("get_capture", map[string]string{"capture_id": id}, &p)
			return p, nil
		})
		if err != nil || closed || receipt.CaptureID == "" {
			t.Fatal("finite logs not admitted", err, closed)
		}
		return receipt.CaptureID, preview, grantID
	}
	capture, originalPreview, grantID := submit(manualLogsArguments(cluster, namespace, workload, false), "installed-original-logs"+installedRunSuffix())
	var progress installedJourneyCaptureProgress
	wait("verified encrypted logs publication", time.Minute, func() bool {
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
		t.Fatal("logs case artifact count")
	}
	a := investigation.Artifacts[0]
	if a.Kind != "logs" || a.NativeFormat != artifact.LogFormat || a.DataClass != "raw" || a.Target.PodUID != podUID || a.Target.ClusterID != cluster || a.Digest == "" || a.VerifiedNativeBytes == nil || *a.VerifiedNativeBytes <= 0 || *a.VerifiedNativeBytes > installedLogsNativeLimit {
		t.Fatal("logs verified case metadata", a)
	}
	// The protected reference qualifies one real combined review shared by
	// MCP and console. It does not claim ordinary observe collection native proof.
	var grant struct {
		ID           string `json:"grant_id"`
		Kind         string `json:"kind"`
		Phase        string `json:"phase"`
		ResultAccess *struct {
			Operations   []string  `json:"operations"`
			Clients      []string  `json:"client_ids"`
			MaxArtifacts int       `json:"max_artifacts"`
			MaxBytes     int64     `json:"max_bytes"`
			MaxOps       int64     `json:"max_operations"`
			NotAfter     time.Time `json:"not_after"`
		} `json:"result_access"`
		Decision *struct {
			By struct {
				Subject string `json:"subject"`
			} `json:"decided_by"`
			Authentication *struct {
				ACR string    `json:"acr"`
				At  time.Time `json:"authenticated_at"`
			} `json:"authentication_context"`
		} `json:"decision"`
	}
	read("get_grant", map[string]string{"grant_id": grantID}, &grant)
	if grant.ID != grantID || grant.Kind != "adHocCapture" || grant.Phase != "Approved" || grant.ResultAccess == nil || !reflect.DeepEqual(grant.ResultAccess.Operations, []string{"download_artifact", "get_logs"}) || !reflect.DeepEqual(grant.ResultAccess.Clients, []string{"console", "mcp"}) || grant.ResultAccess.MaxArtifacts != 1 || grant.ResultAccess.MaxBytes != 16<<20 || grant.ResultAccess.MaxOps != 16 || grant.Decision == nil || grant.Decision.By.Subject != identity.ReviewerSubject || grant.Decision.Authentication == nil || grant.Decision.Authentication.ACR != "1" || grant.Decision.Authentication.At.IsZero() {
		t.Fatal("logs combined review lost exact operations/clients or independent actual step-up")
	}

	source := savedLogsBrowserSource{CaseID: progress.CaseID, ArtifactID: a.ArtifactID, Version: a.Digest, PodUID: podUID, GrantID: grantID, Expires: a.ExpiresAt}
	pipeline := &installedPacketTerminalPipeline{limit: 2}
	defer pipeline.finish(t)
	sink := func(wait func()) { pipeline.add(t, wait) }
	mcpVerify := installedLogsQuerySQLCheck(t, ctx, admin, hub, root, sink, true)(a.ArtifactID)
	rawCall := func(name string, args any) installedComparisonReply {
		r, _ := call(rawSession, name, args)
		return installedComparisonReply{r}
	}
	denied, _ := call(rawSession, "prepare_artifact_download", map[string]string{"artifact_id": a.ArtifactID, "idempotency_key": "logs-readraw-no-native" + installedRunSuffix()})
	if denied.Status != "error" {
		t.Fatal("read+raw session obtained native preparation")
	}
	mcpVerify("", "")
	mcpPage := queryInstalledLogsWithCall(t, ctx, source, installedLogsRequest(source, "installed-logs-mcp-"+a.ArtifactID), rawCall, mcpVerify, true)
	capturingBrowser := identity.consoleSession(t, ctx, cert, address, origin)
	browserVerify := installedLogsQuerySQLCheck(t, ctx, admin, hub, root, sink, false)(a.ArtifactID)
	browserRequest := installedLogsRequest(source, "ui-generates-original-key")
	browserCall, browserFinish := savedLogsBrowser(t, ctx, capturingBrowser, address, source, browserRequest, func(installedComparisonReply) {})
	browserPage := queryInstalledLogsWithCall(t, ctx, source, browserRequest, browserCall, func(handle, operation string) func() {
		browserFinish()
		return browserVerify(handle, operation)
	}, false)
	browserFinish()
	pipeline.finish(t)
	if pipeline.admitted != 2 || pipeline.joined != 2 || len(pipeline.pending) != 0 {
		t.Fatal("logs original query workers not joined")
	}
	mcpCompare, browserCompare := mcpPage, browserPage
	mcpCompare.Observed, mcpCompare.Expires = time.Time{}, time.Time{}
	browserCompare.Observed, browserCompare.Expires = time.Time{}, time.Time{}
	if !reflect.DeepEqual(mcpCompare, browserCompare) {
		t.Fatal("MCP and React differ for same saved source/selection")
	}

	var download installedJourneyDownload
	wait("approved exact native logs download", time.Minute, func() bool {
		name, args := "get_artifact_download", any(map[string]string{"download_id": download.DownloadID})
		if download.DownloadID == "" || download.ContinuePreparation {
			name, args = "prepare_artifact_download", map[string]string{"artifact_id": a.ArtifactID, "idempotency_key": "installed-logs-native" + installedRunSuffix()}
		}
		r, code := invoke(name, args)
		return code == "" && r.Status == "ok" && json.Unmarshal(r.Data, &download) == nil && download.State != "Preparing"
	})
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil || *download.SizeBytes != *a.VerifiedNativeBytes {
		t.Fatal("logs native download not Ready", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: 2 * time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	native, readErr := io.ReadAll(io.LimitReader(response.Body, installedLogsNativeLimit+1))
	_ = response.Body.Close()
	digest := sha256.Sum256(native)
	_, disposition, dispositionErr := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	if readErr != nil || response.StatusCode != 200 || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 || dispositionErr != nil || disposition["filename"] != "artifact-"+a.ArtifactID+".jsonl" {
		diagnose()
		t.Fatal("logs native exact bytes/name", response.StatusCode, len(native), readErr)
	}
	// Every original query worker is terminal. The SQL checker requires
	// positive retirement if its exact Job is gone; a surviving terminal Job
	// remains charged. One later native demand need not retire both workers.
	footer, err := checkInstalledLogsParity(native, podUID, mcpPage, browserPage)
	if err != nil {
		t.Fatal(err)
	}
	expectedInstances := map[string]string{}
	for _, group := range []struct {
		kind     string
		statuses []core.ContainerStatus
	}{{"regular", pod.Status.ContainerStatuses}, {"init", pod.Status.InitContainerStatuses}, {"ephemeral", pod.Status.EphemeralContainerStatuses}} {
		for _, status := range group.statuses {
			if status.ContainerID != "" {
				expectedInstances[group.kind+"/"+status.Name+"/current"] = status.ContainerID
			}
			if previous := status.LastTerminationState.Terminated; previous != nil && previous.ContainerID != "" {
				expectedInstances[group.kind+"/"+status.Name+"/previous"] = previous.ContainerID
			}
		}
	}
	if expectedInstances["regular/app/previous"] != oldID {
		t.Fatal("setup lost the independently observed original previous instance")
	}
	if err := checkInstalledLogsOrigins(native, expectedInstances); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../results/manual-logs.jsonl", native, 0600); err != nil {
		t.Fatal(err)
	}
	// Repeat is a fresh preview/settings proof here, never an unexecuted repeat
	// capture claim. Its original composition/expiry must remain unchanged.
	qualifyManualRecorderRepeatPreview(t, capture, originalPreview, invoke, diagnose)
	stopCapture, _, _ := submit(manualLogsArguments(cluster, namespace, workload, true), "installed-stop-logs"+installedRunSuffix())
	qualifyManualLogsStop(t, ctx, stopCapture, read, invoke)
	report := map[string]any{"captureID": capture, "caseID": progress.CaseID, "podUID": podUID, "artifactID": a.ArtifactID, "grantID": grantID, "nativeBytes": len(native), "nativeSHA256": hex.EncodeToString(digest[:]), "origins": footer.Origins, "sourceBytes": footer.SourceBytes, "fragments": footer.Fragments, "queryUnits": installedLogsQueryUnits, "queries": 2, "ordinaryCollection": false, "protectedRequireAll": true, "ordinaryObserveNativeQualified": false, "independentReviewer": identity.ReviewerSubject, "querySameKeyReplay": true, "sameNativeMCPReact": true, "queryWorkersJoined": pipeline.joined, "workerRetirement": "exact terminal; positive SQL retirement required if original Job gone; surviving terminal worker remains charged", "readRawNativeDenied": true, "repeatPreviewOnly": true, "repeatCaptureExecuted": false, "stopCaptureID": stopCapture, "stop": "Running to Cancelled without artifact", "authority": "actual provisioned capture/publication/raw approval/MCP/React/native/SQL path; operator only sets up synthetic source bytes and verifies results"}
	body, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile("../results/manual-logs-report.json", append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("installed finite logs: originalPod%s current+previous/init/ephemeral, native%dB SHA256=%x, MCP+React40 configured units, combined capture and result approval, original workers joined, fresh Repeat preview only, node-free Running Stop Cancelled", podUID, len(native), digest)
	_ = regionalConfig // The actual provisioned target/client above owns source setup.
}

func checkInstalledLogsOrigins(native []byte, expectedInstances map[string]string) error {
	var origin artifact.LogOrigin
	origins := map[string]artifact.LogOrigin{}
	data := map[string][]byte{}
	_, err := logcodec.Walk(context.Background(), bytes.NewReader(native), installedLogsNativeLimit, logcodec.Visitor{Origin: func(o artifact.LogOrigin) error {
		origin = o
		origins[o.ContainerKind+"/"+o.ContainerName+"/"+o.Source] = o
		return nil
	}, Fragment: func(f artifact.LogFragment) error {
		b, err := f.Bytes()
		if err == nil {
			key := origin.ContainerKind + "/" + origin.ContainerName + "/" + origin.Source
			data[key] = append(data[key], b...)
		}
		return err
	}})
	if err != nil {
		return err
	}
	for key, id := range expectedInstances {
		o, exists := origins[key]
		if !exists || o.RuntimeID == nil || *o.RuntimeID != id {
			return fmt.Errorf("native origin differs from independently observed instance: %s", key)
		}
	}
	current, previous := "regular/app/current", "regular/app/previous"
	if !bytes.Contains(data[current], []byte(installedLogsMarker+"-current")) || !bytes.Contains(data[previous], []byte(installedLogsMarker+"-previous")) || origins[current].RuntimeID == nil || origins[previous].RuntimeID == nil || *origins[current].RuntimeID == *origins[previous].RuntimeID {
		return fmt.Errorf("native lacks original current/previous instance bytes")
	}
	for _, key := range []string{"init/log-init/current", "ephemeral/log-ephemeral/current"} {
		b := data[key]
		if !bytes.Contains(b, []byte("synthetic-finite-logs-once")) || !bytes.Contains(b, []byte("synthetic-finite-logs-stderr")) || !bytes.Contains(b, []byte{0xff, 0}) || !bytes.Contains(b, bytes.Repeat([]byte{'L'}, 4096)) || origins[key].Stream != "combined" {
			return fmt.Errorf("native missing exact combined init/ephemeral invalid/long bytes: %s", key)
		}
	}
	return nil
}
func qualifyManualLogsStop(t *testing.T, ctx context.Context, id string, read func(string, any, any), invoke func(string, any) (installedJourneyEnvelope, string)) {
	t.Helper()
	var p struct {
		CaptureID string `json:"capture_id"`
		Phase     string `json:"phase"`
		Revision  int64  `json:"revision"`
		CaseID    string `json:"case_id"`
	}
	call, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for call.Err() == nil {
		read("get_capture", map[string]string{"capture_id": id}, &p)
		if p.CaptureID != id || p.Revision < 1 {
			t.Fatal("logs Stop progress binding")
		}
		if p.Phase == "Running" {
			break
		}
		if p.Phase != "Pending" {
			t.Fatal("logs Stop never reached Running", p.Phase)
		}
		if installedJourneyPause(call, time.Second) != nil {
			break
		}
	}
	if p.Phase != "Running" {
		t.Fatal("logs Stop did not observe actual Running")
	}
	reply, code := invoke("cancel_capture", map[string]any{"capture_id": id, "expected_revision": p.Revision, "idempotency_key": "stop-logs-" + id})
	var stopped struct {
		CaptureID string `json:"capture_id"`
		Requested bool   `json:"cancellation_requested"`
	}
	if code != "" || reply.Status != "ok" || json.Unmarshal(reply.Data, &stopped) != nil || stopped.CaptureID != id || !stopped.Requested {
		t.Fatal("node-free logs Stop refused", code)
	}
	for _, warning := range reply.Warnings {
		if strings.HasPrefix(warning, "Cancellation delivery is unconfirmed;") {
			t.Fatal("logs Stop delivery was not confirmed")
		}
	}
	for call.Err() == nil {
		read("get_capture", map[string]string{"capture_id": id}, &p)
		if p.CaptureID != id {
			t.Fatal("logs Stop changed capture")
		}
		if p.Phase == "Cancelled" {
			break
		}
		if p.Phase != "Running" && p.Phase != "Pending" {
			t.Fatal("logs Stop missing joined terminal", p.Phase)
		}
		if installedJourneyPause(call, time.Second) != nil {
			break
		}
	}
	if p.Phase != "Cancelled" {
		t.Fatal("logs Stop never joined original owner")
	}
	if p.CaseID != "" {
		var c struct {
			Artifacts []json.RawMessage `json:"artifacts"`
		}
		read("get_case", map[string]string{"case_id": p.CaseID}, &c)
		if len(c.Artifacts) != 0 {
			t.Fatal("stopped logs published artifact")
		}
	}
	t.Logf("installed logs %s: actual Running Stop acknowledged, joined terminal Cancelled, no artifact; no node collector", id)
}
