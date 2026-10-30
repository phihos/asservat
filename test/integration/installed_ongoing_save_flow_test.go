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
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Authored inputs only: the builtin ongoing networkHeaders recorder (30s ring,
// 30s history) with a reviewed Save opt-in. Three header-visible destination
// ports separate outside-window, retained pre-T0 and post-T0 traffic.
const (
	installedOngoingSaveName   = "regional-ongoing-packets"
	installedOngoingSaveFilter = "tcp portrange 9101-9103"
	ongoingSaveOutsidePort     = 9101
	ongoingSaveRetainedPort    = 9102
	ongoingSaveAfterPort       = 9103
	ongoingSaveBefore          = 15 * time.Second
	ongoingSaveLifetime        = 300
)

func installedOngoingSaveSpec(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target":    map[string]any{"cluster": cluster, "namespace": namespace, "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": workload}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors": []any{map[string]any{"id": "crashed", "kind": "exit", "options": map[string]any{"reasons": []any{"Error", "OOMKilled"}}}},
		"when":      map[string]any{"detector": "crashed"},
		"profileComposition": map[string]any{"components": []any{map[string]any{"id": "network", "profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"}, "overrides": []any{
			map[string]any{"actionID": "sample", "field": "packetFilter", "value": installedOngoingSaveFilter},
		}}}, "maxTotalBytes": 16 << 20, "maxDuration": "20s"},
		"budgets":   map[string]any{"cooldown": "5s", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention": "10m", "suspended": false, "observation": map[string]any{"mode": "allAuthorized"},
		"evaluation":     map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"},
		"recordingSaves": map[string]any{"enabled": true},
	}
}

type ongoingSaveSource struct {
	ID, Fence                  string
	StartedAt, HardUntil, Leaf time.Time
	InitialCredit, Credit      int64
	EndedAt                    *time.Time
}

// qualifyInstalledOngoingSave is the one-active-source installed ordinary
// packet + Save focus. It seeds no grant, acceptance, source or capture row:
// every effect goes through the installed MCP/console/native paths.
func qualifyInstalledOngoingSave(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, identity *installedIdentity, publicRoot []byte, address, origin string, diagnose func()) {
	t.Helper()
	if st, err := os.Stat("/etc/asservat-disposable-host"); err != nil || !st.Mode().IsRegular() {
		t.Fatal("ongoing save requires a fresh disposable runner")
	}
	f := installedPolicyTarget
	if f == nil || identity == nil {
		t.Fatal("ongoing save lacks installed target")
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
	c := sdk.NewClient(&sdk.Implementation{Name: "ongoing-save-requester", Version: "1"}, nil)
	requester, err := c.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, identity.mcpTokenSource(origin).Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("ongoing save MCP", err)
	}
	defer requester.Close()
	invoke := func(call context.Context, name string, args any) (installedJourneyEnvelope, string, error) {
		raw, err := json.Marshal(args)
		if err != nil {
			return installedJourneyEnvelope{}, "", err
		}
		if err = wire.ValidateInput(name, raw); err != nil {
			return installedJourneyEnvelope{}, "", fmt.Errorf("native authored %s: %w", name, err)
		}
		out, err := requester.CallTool(call, &sdk.CallToolParams{Name: name, Arguments: args})
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
		t.Fatal("installed ongoing save timed out", what)
	}
	read := func(call context.Context, name string, args, out any) bool {
		reply, code, err := invoke(call, name, args)
		if err != nil || reply.Status != "ok" || code != "" {
			return false
		}
		if out != nil && json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("ongoing save response", name)
		}
		return true
	}
	must := func(name string, args, out any) {
		t.Helper()
		reply, code, err := invoke(ctx, name, args)
		if err != nil || reply.Status != "ok" || code != "" {
			diagnose()
			t.Fatal("ongoing save public operation", name, code, err)
		}
		if out != nil && json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("ongoing save public data", name)
		}
	}

	binding := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": "ongoing-packet-automation"}, "spec": map[string]any{"effect": "Allow", "subjects": f.binding["subjects"], "roles": []any{"workload-maintainer", "evidence-owner"}, "scope": f.binding["scope"], "reason": "installed ongoing packet Save qualification", "automation": map[string]any{"allowedActions": []any{"packetCapture"}, "maxLifetimeSeconds": ongoingSaveLifetime, "maxExecutions": 8, "maxBytes": 64 << 20, "maxObservedBytes": 128 << 20}}}
	body, _ := json.Marshal(binding)
	if err = f.hub.Post().AbsPath(f.base + "accessbindings").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("operator packet automation envelope", err)
	}
	policy := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": installedOngoingSaveName}, "spec": installedOngoingSaveSpec(f.cluster, f.namespace, f.workload)}
	body, _ = json.Marshal(policy)
	if err = f.hub.Post().AbsPath(f.base + "debugpolicies").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("operator ongoing policy", err)
	}
	var active struct {
		PolicyUID    string `json:"policy_uid"`
		AcceptanceID string `json:"acceptance_id"`
		State        string `json:"state"`
	}
	// Without required recording approval, source admission uses no policy
	// grant: the accepted authority (envelope lifetime) bounds each source.
	activate := func(key string) {
		t.Helper()
		wait("independently audited ongoing policy acceptance", 2*time.Minute, func(call context.Context) bool {
			return read(call, "activate_policy", map[string]any{"policy_name": installedOngoingSaveName, "idempotency_key": key}, &active) && active.State == "active"
		})
	}
	activate("native-ongoing-activate")
	firstAcceptance := active.AcceptanceID
	if active.PolicyUID == "" || active.AcceptanceID == "" {
		t.Fatal("ongoing activation lost source identity", active)
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
		t.Fatal("actual running ongoing target missing")
	}
	// One proxied connection attempt reaches the Pod's interface as SYN/RST
	// headers on the chosen port; the port is closed, so no payload exists.
	marker := func(port int) time.Time {
		sent := time.Now()
		for range 3 {
			call, stop := context.WithTimeout(ctx, 2*time.Second)
			_, _ = f.region.CoreV1().RESTClient().Get().Namespace(f.namespace).Resource("pods").Name(fmt.Sprintf("%s:%d", podName, port)).SubResource("proxy").DoRaw(call)
			stop()
		}
		return sent
	}
	sources := func(call context.Context) ([]ongoingSaveSource, error) {
		rows, err := admin.Query(call, `SELECT id::text,fence::text,started_at,hard_until,initial_leaf_until,initial_credit,credit,ended_at FROM policy_recording_source WHERE root_id=$1 AND policy_uid=$2 ORDER BY started_at`, root, active.PolicyUID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []ongoingSaveSource
		for rows.Next() {
			var s ongoingSaveSource
			if err = rows.Scan(&s.ID, &s.Fence, &s.StartedAt, &s.HardUntil, &s.Leaf, &s.InitialCredit, &s.Credit, &s.EndedAt); err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, rows.Err()
	}
	current := func(call context.Context) (ongoingSaveSource, int, bool) {
		all, err := sources(call)
		if err != nil {
			return ongoingSaveSource{}, 0, false
		}
		var live []ongoingSaveSource
		for _, s := range all {
			if s.EndedAt == nil {
				live = append(live, s)
			}
		}
		if len(live) > 1 {
			t.Fatal("more than one active ongoing source", len(live))
		}
		if len(live) == 0 {
			return ongoingSaveSource{}, len(all), false
		}
		return live[0], len(all), true
	}
	type recording struct {
		Handle   string   `json:"recording_handle"`
		PodUID   string   `json:"pod_uid"`
		Policy   string   `json:"policy_uid"`
		State    string   `json:"state"`
		History  string   `json:"history"`
		Eligible bool     `json:"save_eligible"`
		Blockers []string `json:"blockers"`
	}
	target := map[string]any{"target_ref": map[string]any{"cluster_id": f.cluster, "namespace": f.namespace, "kind": "Deployment", "name": f.workload}}
	// lastSelection keeps the most recent public answer for failure analysis.
	var lastSelection string
	selection := func(call context.Context) (recording, bool) {
		var page struct {
			Recordings []recording `json:"recordings"`
		}
		reply, code, err := invoke(call, "list_recordings", target)
		if err != nil || reply.Status != "ok" || code != "" {
			lastSelection = fmt.Sprintf("status=%s code=%s err=%v", reply.Status, code, err)
			return recording{}, false
		}
		if json.Unmarshal(reply.Data, &page) != nil {
			t.Fatal("list_recordings data")
		}
		lastSelection = fmt.Sprintf("%d recordings", len(page.Recordings))
		for _, r := range page.Recordings {
			lastSelection += fmt.Sprintf("; policy=%t pod=%t state=%s history=%s eligible=%t handle=%t blockers=%v", r.Policy == active.PolicyUID, r.PodUID == podUID, r.State, r.History, r.Eligible, r.Handle != "", r.Blockers)
			if r.Policy == active.PolicyUID && r.PodUID == podUID && r.Eligible && r.Handle != "" {
				return r, true
			}
		}
		return recording{}, false
	}
	// At most three selections (each counts toward the caller's open
	// selections) within about three seconds, inside the 15 s window.
	selectNow := func(what string) recording {
		t.Helper()
		for range 3 {
			if r, ok := selection(ctx); ok {
				return r
			}
			if installedJourneyPause(ctx, time.Second) != nil {
				break
			}
		}
		diagnose()
		t.Fatal(what, "selection unavailable:", lastSelection)
		return recording{}
	}
	type preview struct {
		ID string `json:"preview_id"`
	}
	save := func(args map[string]any, key string) (string, time.Time) {
		t.Helper()
		var p preview
		must("preview_recording_save", args, &p)
		var progress installedJourneyCaptureProgress
		must("request_capture", map[string]any{"preview_id": p.ID, "idempotency_key": key}, &progress)
		var t0 time.Time
		if progress.CaptureID == "" || admin.QueryRow(ctx, `SELECT accepted_at FROM recording_save_reservation WHERE root_id=$1 AND capture_id=$2`, root, progress.CaptureID).Scan(&t0) != nil {
			t.Fatal("Save lost its SQL-accepted T0", progress)
		}
		// Passive replay of the same key returns the original capture.
		var replay installedJourneyCaptureProgress
		must("request_capture", map[string]any{"preview_id": p.ID, "idempotency_key": key}, &replay)
		if replay.CaptureID != progress.CaptureID {
			t.Fatal("passive Save replay changed capture identity")
		}
		return progress.CaptureID, t0
	}
	published := func(captureID string) string {
		t.Helper()
		var progress installedJourneyCaptureProgress
		wait("Save publication", 2*time.Minute, func(call context.Context) bool {
			if !read(call, "get_capture", map[string]any{"capture_id": captureID}, &progress) {
				return false
			}
			ready, err := installedJourneyCaptureCaseReady(call, captureID, progress)
			if err != nil {
				diagnose()
				t.Fatal(err)
			}
			return ready
		})
		return progress.CaseID
	}

	// Incarnation 1: arm, renew past the first leaf, Save, repeat, natural expiry.
	var src ongoingSaveSource
	armStarted := time.Now()
	wait("ongoing source arm", 2*time.Minute, func(call context.Context) bool {
		s, _, ok := current(call)
		src = s
		return ok
	})
	armLatency := time.Since(armStarted)
	if src.HardUntil.Sub(src.StartedAt) > ongoingSaveLifetime*time.Second {
		t.Fatal("source hard bound outlives its accepted authority", src.StartedAt, src.HardUntil)
	}
	// Wait on SQL facts: every list_recordings opens a selection that counts
	// toward the caller's ten open previews/selections.
	// A start that fails before any Save is ended and re-armed under a new
	// identity by the product; follow the live source and count re-arms.
	// Lineage must still be unchanged across the Save itself.
	rearms := 0
	wait("a live source past its first leaf", 2*time.Minute, func(call context.Context) bool {
		s, _, ok := current(call)
		if !ok {
			return false
		}
		if s.ID != src.ID {
			src = s
			rearms++
		}
		return time.Now().After(src.Leaf.Add(time.Second))
	})
	outsideSent := marker(ongoingSaveOutsidePort)
	if err = installedJourneyPause(ctx, ongoingSaveBefore+7*time.Second); err != nil {
		t.Fatal(err)
	}
	retainedSent := marker(ongoingSaveRetainedPort)
	selected := selectNow("fresh Save")
	captureID, t0 := save(map[string]any{"recording_handles": []string{selected.Handle}, "before": "15s"}, "native-ongoing-save")
	afterSent := marker(ongoingSaveAfterPort)
	// Refuse ambiguous boundary evidence instead of adding tolerance.
	if !outsideSent.Before(t0.Add(-ongoingSaveBefore-2*time.Second)) || !retainedSent.After(t0.Add(-ongoingSaveBefore+time.Second)) || !retainedSent.Before(t0) {
		t.Fatal("marker timing too close to the Save window boundary", outsideSent, retainedSent, t0)
	}
	same, count, ok2 := current(ctx)
	if !ok2 || same.ID != src.ID || same.Fence != src.Fence || count != 1+rearms {
		t.Fatal("Save changed, stopped or re-armed the original source", same, count)
	}
	caseID := published(captureID)
	var investigation struct {
		Artifacts []struct {
			ID string `json:"artifact_id"`
		} `json:"artifacts"`
	}
	must("get_case", map[string]any{"case_id": caseID}, &investigation)
	if len(investigation.Artifacts) != 1 {
		t.Fatal("ongoing Save PCAPNG case", len(investigation.Artifacts))
	}
	var download installedJourneyDownload
	prepare := map[string]any{"artifact_id": investigation.Artifacts[0].ID, "idempotency_key": "native-ongoing-pcap-download"}
	wait("ongoing Save native download", 2*time.Minute, func(call context.Context) bool {
		name, args := "get_artifact_download", any(map[string]any{"download_id": download.DownloadID})
		if download.DownloadID == "" || download.ContinuePreparation {
			name, args = "prepare_artifact_download", prepare
		}
		return read(call, name, args, &download) && download.State != "Preparing"
	})
	if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil {
		t.Fatal("ongoing Save native download unavailable", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: 2 * time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	native, err := io.ReadAll(io.LimitReader(response.Body, artifact.RecordingNativeLimit+1))
	response.Body.Close()
	digest := sha256.Sum256(native)
	if err != nil || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 {
		t.Fatal("ongoing Save native bytes", response.StatusCode, len(native), err)
	}
	file := filepath.Join("..", "results", "ongoing-save.pcapng")
	if err = os.WriteFile(file, native, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(ctx, "tshark", ongoingSaveFieldArgs(file)...).Output()
	if err != nil {
		t.Fatal("offline native Wireshark read", err)
	}
	markers, err := ongoingSavePackets(out, t0, ongoingSaveBefore)
	if err != nil {
		t.Logf("native ongoing evidence retained: ongoing-save.pcapng bytes=%d SHA256=%x", len(native), digest)
		t.Fatal("ongoing Save window/header proof", err)
	}

	// Fresh selection repeat; the original handle is not reused.
	repeatSelection := selectNow("fresh repeat")
	repeatID, _ := save(map[string]any{"recording_handles": []string{repeatSelection.Handle}, "before": "15s", "repeated_from_capture_id": captureID}, "native-ongoing-repeat")
	published(repeatID)
	if same, count, ok2 = current(ctx); !ok2 || same.ID != src.ID || count != 1+rearms {
		t.Fatal("repeat changed or re-armed the original source", same, count)
	}

	byID := func(call context.Context, id string) (ongoingSaveSource, bool) {
		all, err := sources(call)
		if err != nil {
			return ongoingSaveSource{}, false
		}
		for _, s := range all {
			if s.ID == id {
				return s, true
			}
		}
		return ongoingSaveSource{}, false
	}
	// Natural expiry at the original authority-bounded hard deadline, no stop call.
	var expired ongoingSaveSource
	wait("natural source expiry", time.Until(src.HardUntil)+time.Minute, func(call context.Context) bool {
		var ok bool
		expired, ok = byID(call, src.ID)
		return ok && expired.EndedAt != nil
	})
	if expired.ID != src.ID || expired.EndedAt.Before(src.HardUntil) || expired.Credit < src.Credit {
		t.Fatal("natural expiry ended early, changed source or refunded credit", expired)
	}
	if _, ok := selection(ctx); ok {
		t.Fatal("expired source still offered for Save")
	}

	// Incarnation 2: a new grant arms one new source; explicit stop ends it.
	activate("native-ongoing-reactivate")
	if active.AcceptanceID == firstAcceptance {
		t.Fatal("reactivation after authority expiry reused the original acceptance")
	}
	var replacement ongoingSaveSource
	wait("second ongoing source arm", 3*time.Minute, func(call context.Context) bool {
		s, _, ok := current(call)
		replacement = s
		return ok && s.ID != src.ID
	})
	if replacement.ID == src.ID || replacement.HardUntil.Sub(replacement.StartedAt) > ongoingSaveLifetime*time.Second {
		t.Fatal("second incarnation reused the old source or outlived its authority", replacement)
	}
	must("deactivate_policy", map[string]any{"policy_name": installedOngoingSaveName, "idempotency_key": "native-ongoing-stop"}, nil)
	stopped := time.Now()
	var ended ongoingSaveSource
	wait("explicit source stop", time.Minute, func(call context.Context) bool {
		var ok bool
		ended, ok = byID(call, replacement.ID)
		return ok && ended.EndedAt != nil
	})
	if ended.ID != replacement.ID || !ended.EndedAt.Before(replacement.HardUntil) {
		t.Fatal("explicit stop did not end the second source before its hard deadline", ended)
	}

	report := map[string]any{
		"policyUID": active.PolicyUID, "podUID": podUID,
		"firstAcceptanceID": firstAcceptance, "secondAcceptanceID": active.AcceptanceID, "envelopeLifetimeSeconds": ongoingSaveLifetime,
		"sourceID": src.ID, "sourceFence": src.Fence, "sourceStartedAt": src.StartedAt, "sourceHardUntil": src.HardUntil, "sourceInitialLeafUntil": src.Leaf,
		"sourceInitialCredit": src.InitialCredit, "sourceCreditAtArm": src.Credit, "sourceCreditAtExpiry": expired.Credit, "sourceEndedAt": expired.EndedAt,
		"armLatencySeconds": armLatency.Seconds(), "rearmsBeforeSave": rearms, "saveCaptureID": captureID, "saveAcceptedAt": t0, "repeatCaptureID": repeatID,
		"outsideMarkerSent": outsideSent, "retainedMarkerSent": retainedSent, "afterMarkerSent": afterSent,
		"retainedMarkerPackets": markers, "nativeBytes": len(native), "nativeSHA256": hex.EncodeToString(digest[:]),
		"secondSourceID": replacement.ID, "explicitStopRequested": stopped, "secondSourceEndedAt": ended.EndedAt,
		"scope": "one active ordinary ongoing networkHeaders source on one installed Pod; history labels are as reported (Unknown/Partial are not upgraded); no quiet-Full, clock-step, loss, multi-node or syscall claim",
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("../results/ongoing-save-report.json", append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("UNPUBLISHED installed ongoing Save proof: source %s armed in %.1fs, Save %s T0=%s retained %d marker packets, PCAPNG %dB SHA256=%x, natural expiry %s, explicit stop of %s", src.ID, armLatency.Seconds(), captureID, t0.Format(time.RFC3339Nano), markers, len(native), digest, expired.EndedAt.Format(time.RFC3339Nano), replacement.ID)
}

func ongoingSaveFieldArgs(file string) []string {
	return []string{"-r", file, "-T", "fields", "-E", "occurrence=f", "-e", "frame.time_epoch", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.payload"}
}

// ongoingSavePackets requires retained pre-T0 marker headers inside the
// requested window and rejects outside-window, post-T0 and payload bytes.
func ongoingSavePackets(out []byte, t0 time.Time, before time.Duration) (int, error) {
	retained := 0
	for row, line := range strings.Split(strings.TrimRight(string(out), "\r\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return 0, fmt.Errorf("row %d: columns", row+1)
		}
		if fields[3] != "" {
			return 0, fmt.Errorf("row %d: payload in header-only capture", row+1)
		}
		seconds, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, fmt.Errorf("row %d: time", row+1)
		}
		whole, frac := math.Modf(seconds)
		at := time.Unix(int64(whole), int64(frac*1e9))
		if at.After(t0) || at.Before(t0.Add(-before)) {
			return 0, fmt.Errorf("row %d: packet at %s outside [T0-%s, T0=%s]", row+1, at.Format(time.RFC3339Nano), before, t0.Format(time.RFC3339Nano))
		}
		ports := fields[1] + "," + fields[2]
		switch {
		case strings.Contains(ports, strconv.Itoa(ongoingSaveOutsidePort)), strings.Contains(ports, strconv.Itoa(ongoingSaveAfterPort)):
			return 0, fmt.Errorf("row %d: excluded marker port present", row+1)
		case strings.Contains(ports, strconv.Itoa(ongoingSaveRetainedPort)):
			retained++
		}
	}
	if retained == 0 {
		return 0, fmt.Errorf("no retained pre-T0 marker packets")
	}
	return retained, nil
}
