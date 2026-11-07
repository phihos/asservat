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
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
	// ongoingSaveDiskBytes is the ongoing-save-disk focus's collector ring
	// volume (ADR-278): room for the one 4 x 4 MiB sealed ring with headroom.
	ongoingSaveDiskBytes = 64 << 20
)

func installedOngoingSaveSpec(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target":             map[string]any{"cluster": cluster, "namespace": namespace, "workloadRef": map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": workload}, "maxPods": 1, "selection": "triggeringPod", "adoption": "pinUID"},
		"detectors":          []any{map[string]any{"id": "crashed", "kind": "exit", "options": map[string]any{"reasons": []any{"Error", "OOMKilled"}}}},
		"when":               map[string]any{"detector": "crashed"},
		"profileComposition": installedOngoingComposition(),
		"budgets":            map[string]any{"cooldown": "5s", "burst": 2, "maxOccurrencesPerHour": 12, "maxConcurrentActions": 1},
		"retention":          "10m", "suspended": false, "observation": map[string]any{"mode": "allAuthorized"},
		"evaluation":     map[string]any{"scope": "pod", "fireOnActivation": false, "rearmFor": "10s"},
		"recordingSaves": map[string]any{"enabled": true},
	}
}

// installedOngoingComposition is the builtin ongoing networkHeaders recorder,
// or for the ongoing-syscall focus the builtin syscall metadata recorder
// (ADR-273) with its defaults.
func installedOngoingComposition() map[string]any {
	calls := map[string]any{"id": "calls", "profileRef": map[string]string{"catalog": "builtin", "name": "syscall-activity", "version": "v1"}}
	network := map[string]any{"id": "network", "profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"}, "overrides": []any{
		map[string]any{"actionID": "sample", "field": "packetFilter", "value": installedOngoingSaveFilter},
	}}
	switch installedJourneyFocus() {
	case "ongoing-syscall":
		return map[string]any{"components": []any{calls}, "maxTotalBytes": 16 << 20, "maxDuration": "30s"}
	case "ongoing-mixed":
		// ADR-275: one policy, one packet and one syscall source per Pod.
		return map[string]any{"components": []any{network, calls}, "maxTotalBytes": 32 << 20, "maxDuration": "30s"}
	}
	if installedJourneyFocus() == "ongoing-save-disk" {
		// The builtin ring on the administrator's encrypted-disk medium (ADR-278).
		network["overrides"] = append(network["overrides"].([]any), map[string]any{"actionID": "sample", "field": "packetRing", "value": map[string]any{"maxAge": "30s", "maxBytes": 16 << 20, "segmentBytes": 4 << 20, "maxSegments": 4, "medium": "encryptedDisk"}})
	}
	return map[string]any{"components": []any{network}, "maxTotalBytes": 16 << 20, "maxDuration": "20s"}
}

// qualifyOngoingRingDisk checks, for the ongoing-save-disk focus, that the
// installed collector runs with the administrator's ring volume and reports
// the encrypted-disk medium available. The node refuses an encryptedDisk
// source with MediumUnavailable otherwise, so the armed source and its Save
// already ran on that medium; this pins the installed shape and log.
func qualifyOngoingRingDisk(t *testing.T, ctx context.Context, region kubernetes.Interface) {
	t.Helper()
	pods, err := region.CoreV1().Pods("asservat-collector").List(ctx, meta.ListOptions{LabelSelector: "app.kubernetes.io/name=asservat-node"})
	if err != nil || len(pods.Items) == 0 {
		t.Fatal("ring disk collector Pods", err)
	}
	for _, p := range pods.Items {
		volume := false
		for _, v := range p.Spec.Volumes {
			if v.Name == "ring-disk" && v.EmptyDir != nil && v.EmptyDir.SizeLimit != nil && v.EmptyDir.SizeLimit.Value() == ongoingSaveDiskBytes {
				volume = true
			}
		}
		if !volume {
			t.Fatal("collector lacks the bounded encrypted-disk ring volume", p.Name)
		}
		// The medium line is printed at startup: read from the log's start.
		var limit int64 = 1 << 20
		raw, err := region.CoreV1().Pods(p.Namespace).GetLogs(p.Name, &core.PodLogOptions{Container: "node", LimitBytes: &limit}).DoRaw(ctx)
		if err != nil {
			t.Fatal("collector ring medium log", p.Name, err)
		}
		logs := string(raw)
		if !strings.Contains(logs, "node collector ring medium: encrypted disk available=true") || strings.Contains(logs, "encrypted disk available=false") {
			t.Fatal("collector did not report the encrypted-disk ring medium available", p.Name)
		}
	}
	t.Logf("encrypted-disk ring medium available on %d collector Pod(s), volume %d bytes", len(pods.Items), ongoingSaveDiskBytes)
}

// installedActionID is the compiler's generated expanded action ID
// (REQ-CPR-003: "a" + 24 hex of sha256(component NUL local action)).
func installedActionID(component, local string) string {
	h := sha256.Sum256([]byte(component + "\x00" + local))
	return "a" + hex.EncodeToString(h[:])[:24]
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
	// Source admission charges the control account and needs a fresh storage
	// binding; log their state on any failure (native run 41247682605 refused
	// the second source at admit-insert).
	base := diagnose
	diagnose = func() {
		base()
		ongoingSaveControlDiagnostics(t, ctx, admin, root)
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

	ongoingAction := "packetCapture"
	allowed := []any{"packetCapture"}
	switch installedJourneyFocus() {
	case "ongoing-syscall":
		ongoingAction, allowed = "syscallTrace", []any{"syscallTrace"}
	case "ongoing-mixed":
		ongoingAction, allowed = "packetCapture and syscallTrace", []any{"packetCapture", "syscallTrace"}
	}
	binding := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": "ongoing-packet-automation"}, "spec": map[string]any{"effect": "Allow", "subjects": f.binding["subjects"], "roles": []any{"workload-maintainer", "evidence-owner"}, "scope": f.binding["scope"], "reason": "installed ongoing packet Save qualification", "automation": map[string]any{"allowedActions": allowed, "maxLifetimeSeconds": ongoingSaveLifetime, "maxExecutions": 8, "maxBytes": 64 << 20, "maxObservedBytes": 128 << 20}}}
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
		// The mixed focus tracks its packet source here; its syscall source is
		// checked separately.
		action := ""
		if installedJourneyFocus() == "ongoing-mixed" {
			action = installedActionID("network", "sample")
		}
		rows, err := admin.Query(call, `SELECT id::text,fence::text,started_at,hard_until,initial_leaf_until,initial_credit,credit,ended_at FROM policy_recording_source WHERE root_id=$1 AND policy_uid=$2 AND ($3='' OR action_id=$3) ORDER BY started_at`, root, active.PolicyUID, action)
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
		// A retryable refusal (ParametersUnavailable, NotAvailable) is retried
		// as a client would: a transient history read failed one repeat
		// preview in native run 41244512181.
		for attempt := 0; ; attempt++ {
			reply, code, err := invoke(ctx, "preview_recording_save", args)
			if err == nil && reply.Status == "ok" && code == "" {
				if json.Unmarshal(reply.Data, &p) != nil {
					t.Fatal("ongoing save public data", "preview_recording_save")
				}
				break
			}
			if attempt == 2 || err != nil || code != "ParametersUnavailable" && code != "NotAvailable" || installedJourneyPause(ctx, time.Second) != nil {
				diagnose()
				t.Fatal("ongoing save public operation", "preview_recording_save", code, err)
			}
		}
		// Existing journey contract: resolve/continue the original preview and
		// key on OutcomeUnknown or AcquisitionNotStarted, never a new request.
		call := func(name string, arguments any, data any) (string, string) {
			reply, code, err := invoke(ctx, name, arguments)
			if err != nil {
				return "error", "OutcomeUnknown"
			}
			if reply.Status == "ok" && code == "" && data != nil && json.Unmarshal(reply.Data, data) != nil {
				t.Fatal("ongoing Save data", name)
			}
			return reply.Status, code
		}
		var progress installedJourneyCaptureProgress
		var err error
		progress.CaptureID, err = installedJourneySubmit(ctx, call, map[string]any{"preview_id": p.ID, "idempotency_key": key})
		if err != nil {
			diagnose()
			t.Fatal("ongoing Save request", err)
		}
		var t0 time.Time
		if progress.CaptureID == "" || admin.QueryRow(ctx, `SELECT accepted_at FROM recording_save_reservation WHERE root_id=$1 AND capture_id=$2`, root, progress.CaptureID).Scan(&t0) != nil {
			t.Fatal("Save lost its SQL-accepted T0", progress)
		}
		// Passive replay of the same key returns the original capture.
		replay, err := installedJourneySubmit(ctx, call, map[string]any{"preview_id": p.ID, "idempotency_key": key})
		if err != nil || replay != progress.CaptureID {
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
	if installedJourneyFocus() == "ongoing-mixed" {
		// Both recorders of the one policy arm on the same Pod (ADR-275).
		wait("ongoing syscall source arm beside the packet source", 2*time.Minute, func(call context.Context) bool {
			var live int
			return admin.QueryRow(call, `SELECT count(*) FROM policy_recording_source WHERE root_id=$1 AND policy_uid=$2 AND action_id=$3 AND ended_at IS NULL`, root, active.PolicyUID, installedActionID("calls", "syscalls")).Scan(&live) == nil && live == 1
		})
	}
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
	// fetchNative downloads a case's single PCAPNG artifact natively, checks
	// its size and SHA-256 against the download record and stores it under
	// test/results.
	fetchNative := func(caseID, key, name string) ([]byte, string) {
		t.Helper()
		var investigation struct {
			Artifacts []struct {
				ID string `json:"artifact_id"`
			} `json:"artifacts"`
		}
		must("get_case", map[string]any{"case_id": caseID}, &investigation)
		if len(investigation.Artifacts) != 1 {
			t.Fatal("ongoing PCAPNG case", name, len(investigation.Artifacts))
		}
		var download installedJourneyDownload
		prepare := map[string]any{"artifact_id": investigation.Artifacts[0].ID, "idempotency_key": key}
		wait("ongoing native download "+name, 2*time.Minute, func(call context.Context) bool {
			op, args := "get_artifact_download", any(map[string]any{"download_id": download.DownloadID})
			if download.DownloadID == "" || download.ContinuePreparation {
				op, args = "prepare_artifact_download", prepare
			}
			return read(call, op, args, &download) && download.State != "Preparing"
		})
		if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil {
			t.Fatal("ongoing native download unavailable", name, download.State)
		}
		response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: 2 * time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
		native, err := io.ReadAll(io.LimitReader(response.Body, artifact.RecordingNativeLimit+1))
		response.Body.Close()
		digest := sha256.Sum256(native)
		if err != nil || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 {
			t.Fatal("ongoing native bytes", name, response.StatusCode, len(native), err)
		}
		file := filepath.Join("..", "results", name)
		if err = os.WriteFile(file, native, 0600); err != nil {
			t.Fatal(err)
		}
		return native, file
	}
	// The ongoing-incident focus spends the workload's shared trigger budget
	// (two per five minutes) on the incident alone: in ongoing-save, Save and
	// repeat already spend it, so a third occurrence is correctly suppressed
	// as cooldown (runs 41278608533/41278610152).
	if installedJourneyFocus() == "ongoing-incident" || installedJourneyFocus() == "ongoing-syscall" || installedJourneyFocus() == "ongoing-mixed" {
		// Automatic incident: a real restart of the armed Pod's container admits
		// one policy occurrence, whose snapshot the policy executor saves from the
		// running source (no manual request, no finite recipe). The retained-port
		// marker just before the restart must be in the saved window.
		incidentSent := marker(ongoingSaveRetainedPort)
		if installedJourneyFocus() == "ongoing-syscall" || installedJourneyFocus() == "ongoing-mixed" {
			// An idle Go workload parks without syscalls; serving a few
			// requests gives the window real pre-restart calls.
			for range 5 {
				call, stop := context.WithTimeout(ctx, 2*time.Second)
				_, _ = f.region.CoreV1().RESTClient().Get().AbsPath("/api/v1/namespaces/"+f.namespace+"/pods/"+podName+":8080/proxy/log").Param("line", "asservat syscall window").DoRaw(call)
				stop()
			}
		}
		if installedPublisherSettled != nil {
			installedPublisherSettled(ctx)
		}
		pod, err := f.region.CoreV1().Pods(f.namespace).Get(ctx, podName, meta.GetOptions{})
		if err != nil || string(pod.UID) != podUID {
			t.Fatal("ongoing incident Pod before restart", err)
		}
		killedAt := time.Now()
		kill, stopKill := context.WithTimeout(ctx, 15*time.Second)
		killed := installedKillContainer(t, kill, *pod)
		stopKill()
		if !killed {
			t.Fatal("ongoing incident workload did not stop")
		}
		before := int32(0)
		if len(pod.Status.ContainerStatuses) == 1 {
			before = pod.Status.ContainerStatuses[0].RestartCount
		}
		wait("the incident container restart", time.Minute, func(call context.Context) bool {
			p, err := f.region.CoreV1().Pods(f.namespace).Get(call, podName, meta.GetOptions{})
			if err != nil || len(p.Status.ContainerStatuses) != 1 || p.Status.ContainerStatuses[0].RestartCount <= before {
				return false
			}
			if term := p.Status.ContainerStatuses[0].LastTerminationState.Terminated; term != nil {
				t.Logf("incident container restart %d: reason %q exit %d", p.Status.ContainerStatuses[0].RestartCount, term.Reason, term.ExitCode)
			}
			return true
		})
		var incidentID string
		wait("automatic incident snapshot occurrence", 2*time.Minute, func(call context.Context) bool {
			return admin.QueryRow(call, `SELECT coalesce(capture_id::text,'') FROM policy_occurrence WHERE root_id=$1 AND policy_uid=$2 AND pod_uid=$3 AND capture_id IS NOT NULL ORDER BY created_at DESC LIMIT 1`, root, active.PolicyUID, podUID).Scan(&incidentID) == nil && incidentID != ""
		})
		var incidentNative []byte
		incidentMarkers := 0
		if installedJourneyFocus() == "ongoing-syscall" {
			incidentNative, _ = fetchNative(published(incidentID), "native-ongoing-syscall-download", "ongoing-syscall.jsonl")
			incidentMarkers = ongoingSyscallEvents(t, incidentNative, podUID, killedAt)
		} else {
			var incidentFile string
			incidentNative, incidentFile = fetchNative(published(incidentID), "native-ongoing-incident-download", "ongoing-incident.pcapng")
			incidentOut, err := exec.CommandContext(ctx, "tshark", ongoingSaveFieldArgs(incidentFile)...).Output()
			if err != nil {
				t.Fatal("offline incident Wireshark read", err)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(incidentOut)), "\n") {
				fields := strings.Split(line, "\t")
				if len(fields) >= 3 && (fields[1] == strconv.Itoa(ongoingSaveRetainedPort) || fields[2] == strconv.Itoa(ongoingSaveRetainedPort)) {
					incidentMarkers++
				}
			}
		}
		if incidentMarkers == 0 {
			t.Fatal("automatic incident snapshot lacks pre-restart evidence", incidentSent, len(incidentNative))
		}
		// ADR-275: the same occurrence also saved the syscall recorder's window
		// as its own child capture, with its own native download.
		childID, childEvents := "", 0
		if installedJourneyFocus() == "ongoing-mixed" {
			wait("automatic incident syscall child capture", 2*time.Minute, func(call context.Context) bool {
				return admin.QueryRow(call, `SELECT c.capture_id::text FROM policy_occurrence_capture c JOIN policy_occurrence o ON o.id=c.occurrence_id AND o.root_id=c.root_id WHERE o.root_id=$1 AND o.capture_id=$2 AND c.action_id=$3`, root, incidentID, installedActionID("calls", "syscalls")).Scan(&childID) == nil
			})
			childNative, _ := fetchNative(published(childID), "native-ongoing-mixed-syscall-download", "ongoing-mixed.jsonl")
			if childEvents = ongoingSyscallEvents(t, childNative, podUID, killedAt); childEvents == 0 {
				t.Fatal("incident syscall child lacks pre-restart calls", childID, len(childNative))
			}
			t.Logf("automatic incident syscall child %s retained %d pre-restart events", childID, childEvents)
		}
		// A container restart may legitimately re-attach the source; record it.
		afterIncident, incidentCount, _ := current(ctx)
		t.Logf("automatic incident %s retained %d marker packets; source after restart %s (sources %d)", incidentID, incidentMarkers, afterIncident.ID, incidentCount)
		report := map[string]any{
			"policyUID": active.PolicyUID, "podUID": podUID, "sourceID": src.ID, "armLatencySeconds": armLatency.Seconds(), "rearmsBeforeIncident": rearms,
			"incidentCaptureID": incidentID, "incidentChildCaptureID": childID, "incidentChildSyscallEvents": childEvents, "incidentMarkerSent": incidentSent, "incidentMarkerPackets": incidentMarkers, "incidentNativeBytes": len(incidentNative), "sourceAfterIncident": afterIncident.ID,
			"scope": "one automatic exit-detector incident snapshot from one active ordinary ongoing " + ongoingAction + " source on one installed Pod; no Save in the same trigger budget window",
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("../results/"+installedJourneyFocus()+"-report.json", append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		_ = outsideSent
		return
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
	native, file := fetchNative(caseID, "native-ongoing-pcap-download", "ongoing-save.pcapng")
	digest := sha256.Sum256(native)
	out, err := exec.CommandContext(ctx, "tshark", ongoingSaveFieldArgs(file)...).Output()
	if err != nil {
		t.Fatal("offline native Wireshark read", err)
	}
	markers, err := ongoingSavePackets(out, t0, ongoingSaveBefore)
	if err != nil {
		t.Logf("native ongoing evidence retained: ongoing-save.pcapng bytes=%d SHA256=%x", len(native), digest)
		t.Fatal("ongoing Save window/header proof", err)
	}
	if installedJourneyFocus() == "ongoing-save-disk" {
		qualifyOngoingRingDisk(t, ctx, f.region)
	}

	// Fresh selection repeat; the original handle is not reused. Retained
	// traffic inside its window: an empty window with incomplete history is
	// reported as absence (CaptureFailed), not as evidence (run 41238165999).
	marker(ongoingSaveRetainedPort)
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
	natural := src
	var expired ongoingSaveSource
	wait("natural source expiry", time.Until(natural.HardUntil)+time.Minute, func(call context.Context) bool {
		var ok bool
		expired, ok = byID(call, natural.ID)
		return ok && expired.EndedAt != nil
	})
	if expired.ID != natural.ID || expired.EndedAt.Before(natural.HardUntil) || expired.Credit < natural.Credit {
		t.Fatal("natural expiry ended early, changed source or refunded credit", expired)
	}
	if _, ok := selection(ctx); ok {
		t.Fatal("expired source still offered for Save")
	}

	// Incarnation 2: specs/policy-automation.md never accepts an unchanged
	// revision again, and the expired acceptance cannot be renewed. The
	// operator adds a second policy under the same envelope; its fresh
	// acceptance arms one new source, and an explicit stop ends it.
	second := installedOngoingSaveName + "-second"
	policy = map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": second}, "spec": installedOngoingSaveSpec(f.cluster, f.namespace, f.workload)}
	body, _ = json.Marshal(policy)
	if err = f.hub.Post().AbsPath(f.base + "debugpolicies").Body(body).Do(ctx).Error(); err != nil {
		t.Fatal("operator second ongoing policy", err)
	}
	wait("fresh acceptance of the second policy", 2*time.Minute, func(call context.Context) bool {
		return read(call, "activate_policy", map[string]any{"policy_name": second, "idempotency_key": "native-ongoing-second"}, &active) && active.State == "active"
	})
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
	must("deactivate_policy", map[string]any{"policy_name": second, "idempotency_key": "native-ongoing-stop"}, nil)
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
	report["ringMedium"] = "memory"
	if installedJourneyFocus() == "ongoing-save-disk" {
		report["ringMedium"] = "encryptedDisk"
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("../results/"+installedJourneyFocus()+"-report.json", append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("UNPUBLISHED installed ongoing Save proof: source %s armed in %.1fs, Save %s T0=%s retained %d marker packets, PCAPNG %dB SHA256=%x, natural expiry %s, explicit stop of %s", src.ID, armLatency.Seconds(), captureID, t0.Format(time.RFC3339Nano), markers, len(native), digest, expired.EndedAt.Format(time.RFC3339Nano), replacement.ID)
}

// installedOngoingFocus selects the installed ongoing packet source flow:
// Save qualification or the automatic incident snapshot.
func installedOngoingFocus() bool {
	f := installedJourneyFocus()
	return f == "ongoing-save" || f == "ongoing-save-disk" || f == "ongoing-incident" || f == "ongoing-syscall" || f == "ongoing-mixed" || f == "live-observation"
}

// ongoingSyscallEvents checks a downloaded syscall window (ADR-273): JSON
// Lines of metadata-only events of the armed Pod, and returns their count.
func ongoingSyscallEvents(t *testing.T, native []byte, podUID string, before time.Time) int {
	t.Helper()
	n, early := 0, 0
	for _, line := range strings.Split(strings.TrimSuffix(string(native), "\n"), "\n") {
		var e struct {
			Identity struct {
				PodUID string `json:"pod_uid"`
			} `json:"identity"`
			Syscall, ABI, Timestamp, Outcome string
		}
		dec := json.NewDecoder(strings.NewReader(line))
		if err := dec.Decode(&e); err != nil || e.Identity.PodUID != podUID || e.Syscall == "" || e.ABI != "x86_64" || e.Timestamp == "" || e.Outcome == "" {
			t.Fatalf("syscall event %q: %v", line, err)
		}
		for _, banned := range []string{"args", "arguments", "buffer", "comm", "path"} {
			if strings.Contains(line, `"`+banned+`"`) {
				t.Fatalf("syscall event carries %s: %s", banned, line)
			}
		}
		if at, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil && at.Before(before) {
			early++
		}
		n++
	}
	if early == 0 {
		t.Fatalf("syscall window has %d events but none from the requests before the restart", n)
	}
	return n
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

func ongoingSaveControlDiagnostics(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string) {
	t.Helper()
	call, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	for _, q := range []string{
		`SELECT concat('pool configured=',configured,' paused=',paused,' valid=',clock_timestamp()<valid_until,' full=',full_limit,' replay=',replay_limit) FROM context_control_pool WHERE root_id=$1`,
		`SELECT concat('account configured=',configured,' paused=',paused,' valid=',clock_timestamp()<valid_until,' full=',charged_full,'/',full_limit,' replay=',charged_replay,'/',replay_limit) FROM context_control_account WHERE root_id=$1`,
		`SELECT concat('binding fresh=',clock_timestamp()<fresh_until) FROM context_storage_binding WHERE root_id=$1`,
		`SELECT concat('occurrences=',count(*),' captured=',count(capture_id),' outcomes=',string_agg(DISTINCT coalesce(outcome,'-'),',')) FROM policy_occurrence WHERE root_id=$1`,
		`SELECT concat('watermark policy=',policy_uid,' pod=',pod_uid,' restarts=',restarts,' seen=',last_seen) FROM policy_pod_watermark WHERE root_id=$1`,
		`SELECT concat('suppressed policy=',policy_uid,' ',reason,'=',count,' last=',last_at) FROM policy_suppression WHERE root_id=$1`,
		`SELECT concat('acceptance policy=',policy_uid,' executions=',executions_spent,'/',coalesce(record#>>'{Authority,Limits,MaxExecutions}','?')) FROM policy_acceptance WHERE root_id=$1`,
		`SELECT concat('sources unreleased=',count(*) FILTER (WHERE slot_released_at IS NULL),' ended=',count(*) FILTER (WHERE ended_at IS NOT NULL),' total=',count(*)) FROM policy_recording_source WHERE root_id=$1`,
		// ADR-275: each incident capture (occurrence or child), its state,
		// execution phase and catalog publication.
		`SELECT concat('capture ',c.id,' child=',EXISTS(SELECT 1 FROM policy_occurrence_capture o WHERE o.capture_id=c.id),' state=',c.state,' deadline=',c.deadline,' execution=',coalesce(e.phase,'-'),' completed=',coalesce(e.completed_at::text,'-'),' published=',EXISTS(SELECT 1 FROM context_catalog k WHERE k.capture_id=c.id)) FROM context_capture c LEFT JOIN context_execution e ON e.capture_id=c.id WHERE c.root_id=$1 AND c.created_at>clock_timestamp()-interval '15 minutes'`,
	} {
		rows, err := admin.Query(call, q, root)
		if err != nil {
			t.Log("diagnostics: control query", err)
			continue
		}
		for rows.Next() {
			var line string
			if rows.Scan(&line) == nil {
				t.Log("diagnostics:", line)
			}
		}
		rows.Close()
	}
}
