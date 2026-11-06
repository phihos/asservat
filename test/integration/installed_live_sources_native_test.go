package integration

// Installed producer helpers: every acceptance, grant, start and stop goes
// through the existing product API. SQL below is independent readback only.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type installedLiveFixture struct {
	Target                                                                         map[string]string
	RootID, ClusterID, Namespace, Workload, PodUID                                 string
	PolicyUID, SourceID, ActionID, Kind, Projection, CaptureID, ObservationGrantID string
	HardUntil                                                                      time.Time
	// APIStartedAt is the real acknowledged start-journal time, not a claimed
	// node clock. The live catalog independently obtains actual node start/end.
	APIStartedAt                  time.Time
	ExecutorPodUID, ExecutorEpoch string
}

const installedLiveProducerMarker = "synthetic-installed-live-private-canary"

func installedLiveComposition(projection string, finite bool) map[string]any {
	component, local, name, catalog := "network", "sample", "network-connections", "builtin"
	if projection == "syscallMetadata" {
		component, local, name = "calls", "syscalls", "syscall-activity"
	}
	if projection == "httpHeaders" {
		name, catalog = manualHTTPProfileName, "namespace"
	}
	before, after, timeout := "2s", "1s", "40s"
	if projection == "httpHeaders" {
		timeout = "300s"
	}
	if finite {
		before, after, timeout = "0s", "30s", "40s"
		if projection == "httpHeaders" {
			after, timeout = "12s", "20s"
		}
	}
	beforeField, afterField := "packetBefore", "packetAfter"
	if projection == "syscallMetadata" {
		beforeField, afterField = "syscallBefore", "syscallAfter"
	}
	edits := []any{map[string]any{"actionID": local, "field": beforeField, "value": before}, map[string]any{"actionID": local, "field": afterField, "value": after}, map[string]any{"actionID": local, "field": "actionTimeout", "value": timeout}}
	if projection != "syscallMetadata" {
		edits = append(edits, map[string]any{"actionID": local, "field": "packetFilter", "value": "tcp port 8080"})
	}
	if finite {
		edits = append(edits, map[string]any{"actionID": local, "field": "actionExecutionMode", "value": "onTrigger"})
	}
	return map[string]any{"components": []any{map[string]any{"id": component, "profileRef": map[string]string{"catalog": catalog, "name": name, "version": "v1"}, "overrides": edits}}, "maxTotalBytes": 16 << 20, "maxDuration": timeout}
}
func installedLivePolicySpec(cluster, namespace, workload, projection string) map[string]any {
	spec := installedOngoingSaveSpec(cluster, namespace, workload)
	spec["profileComposition"] = installedLiveComposition(projection, false)
	return spec
}
func installedLiveManualInput(cluster, namespace, workload, projection string) map[string]any {
	return map[string]any{"target_ref": map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload}, "requested_retention_seconds": 600, "profile_composition": installedLiveComposition(projection, true)}
}
func installedLivePolicyGrantInput(name, id, projection string) map[string]any {
	out := map[string]any{"policy_name": name, "policy_uid": id, "idempotency_key": "live-policy-review-" + id, "lifetime_seconds": 300, "limits": map[string]any{"max_executions": 2, "max_collected_bytes": 16 << 20, "max_observed_bytes": 128 << 20}}
	if projection == "httpHeaders" {
		out["observation_limits"] = map[string]any{"max_session_seconds": 300, "max_observed_bytes": 128 << 20, "max_bytes_per_second": 16 << 20, "max_concurrent_sessions": 1}
	}
	return out
}

type installedLiveGrant struct {
	ID       string     `json:"grant_id"`
	Kind     string     `json:"kind"`
	Phase    string     `json:"phase"`
	NotAfter *time.Time `json:"not_after"`
	Decision *struct {
		By struct {
			Subject string `json:"subject"`
		} `json:"decided_by"`
	} `json:"decision"`
}
type installedLiveProducer struct {
	t               *testing.T
	ctx             context.Context
	admin           *pgxpool.Pool
	root            string
	f               *installedPolicyFixture
	invoke          installedRecordingInvoke
	reviewer        *installedIdentity
	browser         *installedBrowser
	observe         func(context.Context, installedLiveFixture) error
	podName, podUID string
	transport       http.RoundTripper
	owner           *installedIdentity
	origin          string
}

func (p *installedLiveProducer) read(ctx context.Context, name string, input, out any) error {
	reply, code, err := p.invoke(ctx, name, input)
	if err != nil {
		return err
	}
	if code != "" || reply.Status != "ok" {
		return fmt.Errorf("%s: %s", name, code)
	}
	if out != nil && json.Unmarshal(reply.Data, out) != nil {
		return fmt.Errorf("%s output does not decode", name)
	}
	return nil
}
func (p *installedLiveProducer) must(ctx context.Context, name string, input, out any) {
	p.t.Helper()
	if err := p.read(ctx, name, input, out); err != nil {
		p.t.Fatal("installed LIVE producer", err)
	}
}
func (p *installedLiveProducer) wait(ctx context.Context, label string, limit time.Duration, ready func(context.Context) bool) {
	p.t.Helper()
	call, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	for call.Err() == nil {
		if ready(call) {
			return
		}
		if installedJourneyPause(call, time.Second) != nil {
			break
		}
	}
	p.t.Fatal("installed LIVE producer wait", label, call.Err())
}
func (p *installedLiveProducer) review(ctx context.Context, id string) installedLiveGrant {
	p.t.Helper()
	var before installedLiveGrant
	p.must(ctx, "get_grant", map[string]any{"grant_id": id}, &before)
	if before.ID != id || before.Phase != "Pending" || before.NotAfter == nil {
		p.t.Fatal("LIVE review is not original Pending grant", before)
	}
	p.browser.approvedRecordingStepUp(p.t, ctx, p.reviewer, id)
	input := installedPolicyRecordingDecisionArguments(id)
	input["reason"] = "Independently review original installed LIVE collection; viewing does not acquire evidence."
	reply, status, err := p.browser.operation(ctx, "decide_review", input, input["idempotency_key"].(string))
	if err != nil || status != http.StatusOK || reply.Status != "ok" {
		p.t.Fatal("LIVE independent reviewer decision", status, err)
	}
	var approved installedLiveGrant
	p.must(ctx, "get_grant", map[string]any{"grant_id": id}, &approved)
	if approved.ID != id || approved.Phase != "Approved" || approved.Decision == nil || approved.Decision.By.Subject != p.reviewer.ReviewerSubject || approved.NotAfter == nil || !approved.NotAfter.Equal(*before.NotAfter) {
		p.t.Fatal("LIVE reviewer changed original grant/clock", approved)
	}
	return approved
}
func (p *installedLiveProducer) submit(ctx context.Context, previewID, key string) string {
	p.t.Helper()
	request := map[string]any{"preview_id": previewID, "idempotency_key": key}
	reply, code, err := p.invoke(ctx, "request_capture", request)
	if err != nil {
		code = "OutcomeUnknown"
	}
	if code == "ApprovalRequired" {
		var pending struct {
			URI string `json:"navigation_uri"`
		}
		if json.Unmarshal(reply.Data, &pending) != nil {
			p.t.Fatal("LIVE Pending navigation")
		}
		u, e := url.Parse(pending.URI)
		if e != nil || !strings.HasPrefix(u.Path, "/approvals/") {
			p.t.Fatal("LIVE Pending review URI")
		}
		p.review(ctx, strings.TrimPrefix(u.Path, "/approvals/"))
	} else if code == "" && reply.Status == "ok" {
		var accepted struct {
			ID string `json:"capture_id"`
		}
		if json.Unmarshal(reply.Data, &accepted) != nil || accepted.ID == "" {
			p.t.Fatal("LIVE accepted capture missing original ID")
		}
		return accepted.ID
	} else if code != "OutcomeUnknown" && code != "AcquisitionNotStarted" {
		p.t.Fatal("LIVE initial capture refused", code, err)
	}
	// Existing submit helper resolves unknown original key; it never selects a
	// replacement capture or renews a closed/uncertain acquisition.
	call := func(name string, input, data any) (string, string) {
		r, c, e := p.invoke(ctx, name, input)
		if e != nil {
			return "error", "OutcomeUnknown"
		}
		if data != nil && r.Status == "ok" && json.Unmarshal(r.Data, data) != nil {
			p.t.Fatal("LIVE capture reply decode", name)
		}
		return r.Status, c
	}
	id, e := installedJourneySubmit(ctx, call, request)
	if e != nil {
		p.t.Fatal("LIVE original capture resolution", e)
	}
	return id
}
func (p *installedLiveProducer) source(ctx context.Context, name, projection string) {
	p.t.Helper()
	spec := installedLivePolicySpec(p.f.cluster, p.f.namespace, p.f.workload, projection)
	object := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "DebugPolicy", "metadata": map[string]any{"name": name}, "spec": spec}
	raw, _ := json.Marshal(object)
	if e := p.f.hub.Post().AbsPath(p.f.base + "debugpolicies").Body(raw).Do(ctx).Error(); e != nil {
		p.t.Fatal("LIVE real policy create", e)
	}
	var active struct {
		PolicyUID  string `json:"policy_uid"`
		Acceptance string `json:"acceptance_id"`
		State      string `json:"state"`
	}
	activation := map[string]any{"policy_name": name, "idempotency_key": "live-activate-" + name}
	p.wait(ctx, "audited LIVE policy acceptance", 2*time.Minute, func(c context.Context) bool {
		return p.read(c, "activate_policy", activation, &active) == nil && active.State == "active"
	})
	if active.PolicyUID == "" || active.Acceptance == "" {
		p.t.Fatal("LIVE policy acceptance identity")
	}
	var pending installedLiveGrant
	p.must(ctx, "request_policy_grant", installedLivePolicyGrantInput(name, active.PolicyUID, projection), &pending)
	approved := p.review(ctx, pending.ID)
	p.must(ctx, "activate_policy", map[string]any{"policy_name": name, "grant_id": approved.ID, "idempotency_key": "live-attach-" + approved.ID}, nil)
	fixture := installedLiveFixture{Target: map[string]string{"cluster_id": p.f.cluster, "namespace": p.f.namespace, "kind": "Deployment", "name": p.f.workload}, RootID: p.root, ClusterID: p.f.cluster, Namespace: p.f.namespace, Workload: p.f.workload, PodUID: p.podUID, PolicyUID: active.PolicyUID, Kind: "policy", Projection: projection}
	var fence string
	var started, leaf time.Time
	var initialCredit int64
	p.wait(ctx, "original LIVE source admission", time.Minute, func(c context.Context) bool {
		var binding []byte
		e := p.admin.QueryRow(c, `SELECT id::text,fence::text,action_id,started_at,hard_until,initial_leaf_until,initial_credit,binding_json FROM policy_recording_source WHERE root_id=$1 AND policy_uid=$2 AND acceptance_id=$3 AND pod_uid=$4 AND ended_at IS NULL ORDER BY started_at LIMIT 1`, p.root, active.PolicyUID, active.Acceptance, p.podUID).Scan(&fixture.SourceID, &fence, &fixture.ActionID, &started, &fixture.HardUntil, &leaf, &initialCredit, &binding)
		if e != nil {
			return false
		}
		var b struct{ ObservationGrantID, NodeUID, BootID, CollectorPodUID, CollectorEpoch string }
		if json.Unmarshal(binding, &b) != nil {
			p.t.Fatal("LIVE original source binding")
		}
		fixture.ObservationGrantID = b.ObservationGrantID
		if projection == "httpHeaders" && b.ObservationGrantID != approved.ID {
			p.t.Fatal("HTTP source did not retain original reviewed observation grant")
		}
		return fixture.SourceID != "" && time.Now().Before(fixture.HardUntil)
	})
	if fixture.HardUntil.Sub(started) > 300*time.Second || approved.NotAfter == nil || fixture.HardUntil.After(*approved.NotAfter) {
		p.t.Fatal("source exceeded original approval/session", fixture)
	}
	if e := p.observe(ctx, fixture); e != nil {
		p.t.Fatal("installed LIVE original ongoing observation", e)
	}
	if projection == "httpHeaders" {
		p.saveHTTP(ctx, fixture)
	}
	p.must(ctx, "deactivate_policy", map[string]any{"policy_name": name, "idempotency_key": "live-stop-" + active.PolicyUID}, nil)
	p.wait(ctx, "original source explicit end", time.Minute, func(c context.Context) bool {
		var ended *time.Time
		var gotFence string
		var hard time.Time
		var credit int64
		e := p.admin.QueryRow(c, `SELECT ended_at,fence::text,hard_until,initial_credit FROM policy_recording_source WHERE root_id=$1 AND id=$2`, p.root, fixture.SourceID).Scan(&ended, &gotFence, &hard, &credit)
		if e != nil {
			return false
		}
		if gotFence != fence || !hard.Equal(fixture.HardUntil) || credit != initialCredit {
			p.t.Fatal("stop replaced/refunded original LIVE source")
		}
		return ended != nil
	})
	p.t.Logf("installed LIVE policy source %s projection=%s originalGrant=%s sourceHard=%s initialLeaf=%s ended through actual deactivate; collection/source grants and acceptance are product-produced", fixture.SourceID, projection, fixture.ObservationGrantID, fixture.HardUntil.Format(time.RFC3339Nano), leaf.Format(time.RFC3339Nano))
}
func (p *installedLiveProducer) manual(ctx context.Context, projection string) {
	p.t.Helper()
	var preview installedApprovedRecordingPreview
	p.wait(ctx, "finite LIVE preview", time.Minute, func(c context.Context) bool {
		return p.read(c, "preview_capture", installedLiveManualInput(p.f.cluster, p.f.namespace, p.f.workload, projection), &preview) == nil && preview.ID != "" && len(preview.Pods) == 1
	})
	if preview.Pods[0].UID != p.podUID || len(preview.Lifecycle.Actions) != 1 || !time.Now().Before(preview.Expires) {
		p.t.Fatal("LIVE manual preview changed original Pod/action")
	}
	id := p.submit(ctx, preview.ID, "live-manual-"+preview.ID)
	var progress struct {
		CaptureID string `json:"capture_id"`
		Phase     string `json:"phase"`
		Revision  int64  `json:"revision"`
		CaseID    string `json:"case_id"`
	}
	fixture := installedLiveFixture{Target: map[string]string{"cluster_id": p.f.cluster, "namespace": p.f.namespace, "kind": "Deployment", "name": p.f.workload}, RootID: p.root, ClusterID: p.f.cluster, Namespace: p.f.namespace, Workload: p.f.workload, PodUID: p.podUID, SourceID: id, CaptureID: id, ActionID: preview.Lifecycle.Actions[0].ActionID, Kind: "manualSession", Projection: projection}
	p.wait(ctx, "actual finite started receipt BEFORE publication", 30*time.Second, func(c context.Context) bool {
		if p.read(c, "get_capture", map[string]any{"capture_id": id}, &progress) != nil {
			return false
		}
		if progress.Phase != "Running" {
			if progress.Phase != "Pending" {
				p.t.Fatal("finite LIVE source published/ended before attach", progress.Phase)
			}
			return false
		}
		var ebody, process []byte
		err := p.admin.QueryRow(c, `SELECT e.started_at,c.expectation_json,e.process_json FROM context_capture c JOIN context_execution e ON e.root_id=c.root_id AND e.capture_id=c.id AND e.attempt_id=c.attempt_id WHERE c.root_id=$1 AND c.id=$2 AND c.state='intent_audited' AND e.phase='started'`, p.root, id).Scan(&fixture.APIStartedAt, &ebody, &process)
		if err != nil {
			return false
		}
		var e artifact.ContextExpectation
		if json.Unmarshal(ebody, &e) != nil || e.Recording == nil || e.CaptureUID != id || e.PodUID != p.podUID || e.ActionID != fixture.ActionID {
			p.t.Fatal("finite LIVE actual accepted expectation mismatch")
		}
		var receiver struct{ PodUID, ProcessEpoch string }
		if json.Unmarshal(process, &receiver) != nil || receiver.PodUID == "" || receiver.ProcessEpoch == "" {
			p.t.Fatal("finite LIVE original executor missing")
		}
		fixture.ExecutorPodUID, fixture.ExecutorEpoch = receiver.PodUID, receiver.ProcessEpoch
		return !fixture.APIStartedAt.IsZero()
	})
	// Deliberately no guessed HardUntil from SQL's start acknowledgement. The
	// actual node holder is queried by C3, and list_live_sources gives its lease.
	if e := p.observe(ctx, fixture); e != nil {
		p.t.Fatal("installed LIVE original finite observation", e)
	}
	p.must(ctx, "get_capture", map[string]any{"capture_id": id}, &progress)
	if progress.Phase != "Running" || progress.Revision < 1 {
		p.t.Fatal("finite LIVE callback missed original in-flight Stop", progress.Phase)
	}
	var cancelled struct {
		CaptureID string `json:"capture_id"`
		Requested bool   `json:"cancellation_requested"`
	}
	p.must(ctx, "cancel_capture", map[string]any{"capture_id": id, "expected_revision": progress.Revision, "idempotency_key": "live-cancel-" + id}, &cancelled)
	if cancelled.CaptureID != id || !cancelled.Requested {
		p.t.Fatal("LIVE original capture Stop not acknowledged")
	}
	p.wait(ctx, "finite LIVE cancellation terminal/join", time.Minute, func(c context.Context) bool {
		if p.read(c, "get_capture", map[string]any{"capture_id": id}, &progress) != nil {
			return false
		}
		if progress.Phase == "Cancelled" {
			if progress.CaseID != "" {
				p.t.Fatal("cancelled LIVE capture published evidence")
			}
			var joined bool
			if p.admin.QueryRow(c, `SELECT snapshot_cancel_joined_at IS NOT NULL FROM context_capture WHERE root_id=$1 AND id=$2`, p.root, id).Scan(&joined) != nil {
				return false
			}
			return joined
		}
		if progress.Phase != "Pending" && progress.Phase != "Running" {
			p.t.Fatal("LIVE original cancellation outcome", progress.Phase)
		}
		return false
	})
	p.t.Logf("installed LIVE manual capture %s projection=%s actualStartedReceipt=%s originalExecutor=%s/%s; viewer attached before publication, actual cancel joined without replacement", id, projection, fixture.APIStartedAt.Format(time.RFC3339Nano), fixture.ExecutorPodUID, fixture.ExecutorEpoch)
}
func (p *installedLiveProducer) saveHTTP(ctx context.Context, source installedLiveFixture) {
	p.t.Helper()
	var listings struct {
		Recordings []struct {
			Handle   string `json:"recording_handle"`
			PodUID   string `json:"pod_uid"`
			Policy   string `json:"policy_uid"`
			Eligible bool   `json:"save_eligible"`
		} `json:"recordings"`
	}
	var handle string
	p.wait(ctx, "same HTTP source Save selection", 20*time.Second, func(c context.Context) bool {
		if p.read(c, "list_recordings", map[string]any{"target_ref": source.Target}, &listings) != nil {
			return false
		}
		for _, r := range listings.Recordings {
			if r.Policy == source.PolicyUID && r.PodUID == source.PodUID && r.Eligible {
				handle = r.Handle
				return handle != ""
			}
		}
		return false
	})
	var preview struct {
		ID string `json:"preview_id"`
	}
	p.must(ctx, "preview_recording_save", map[string]any{"recording_handles": []string{handle}, "before": "2s"}, &preview)
	if preview.ID == "" {
		p.t.Fatal("HTTP Save preview absent")
	}
	id := p.submit(ctx, preview.ID, "live-save-http-"+preview.ID)
	var progress installedJourneyCaptureProgress
	p.wait(ctx, "actual HTTP Save/native publication", time.Minute, func(c context.Context) bool {
		if p.read(c, "get_capture", map[string]any{"capture_id": id}, &progress) != nil {
			return false
		}
		ready, e := installedJourneyCaptureCaseReady(c, id, progress)
		if e != nil {
			p.t.Fatal(e)
		}
		return ready
	})
	var investigation struct {
		Artifacts []struct {
			ID         string `json:"artifact_id"`
			CaptureID  string `json:"capture_id"`
			NativeType string `json:"native_type"`
		} `json:"artifacts"`
	}
	p.must(ctx, "get_case", map[string]any{"case_id": progress.CaseID}, &investigation)
	if len(investigation.Artifacts) != 1 {
		p.t.Fatal("HTTP Save did not produce one native derivative")
	}
	// Same authenticated native endpoint as the other installed recordings,
	// owned by the original capturing human, with no new source grant.
	invoke := func(name string, input any) (installedJourneyEnvelope, string) {
		r, c, e := p.invoke(ctx, name, input)
		if e != nil {
			return r, "OutcomeUnknown"
		}
		return r, c
	}
	read := func(name string, input, out any) { p.must(ctx, name, input, out) }
	body, _ := installedNativeDownload(p.t, ctx, p.transport, p.owner, p.origin, investigation.Artifacts[0].ID, "live-http-download-"+id, invoke, read, func() {}, ".json")
	if n, e := httpheaders.CheckProjection(bytes.NewReader(body), manualHTTPLimits(), artifact.HTTPHeadersNativeLimit); e != nil || n == 0 {
		p.t.Fatal("HTTP native derivative canonical evidence", n, e)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if bytes.Contains(body, []byte(manualHTTPMarker)) || bytes.Contains(body, []byte(installedLiveProducerMarker)) {
		p.t.Fatal("HTTP native derivative contains excluded canary")
	}
	p.t.Logf("installed LIVE HTTP source Save capture=%s native=%dB SHA256=%s; live rows were not persisted/reused as evidence", id, len(body), digest)
}
func qualifyInstalledLiveSources(t *testing.T, ctx context.Context, admin *pgxpool.Pool, identity *installedIdentity, publicRoot []byte, address, origin, regionalConfig, root string, transport http.RoundTripper, invoke installedRecordingInvoke, observe func(context.Context, installedLiveFixture) error) {
	t.Helper()
	if st, e := os.Stat("/etc/asservat-disposable-host"); e != nil || !st.Mode().IsRegular() {
		t.Fatal("LIVE installed producer requires disposable host")
	}
	f := installedPolicyTarget
	if f == nil || identity == nil || identity.ReviewerSubject == "" || admin == nil || invoke == nil || observe == nil {
		t.Fatal("LIVE installed producer composition missing")
	}
	cert, e := x509.ParseCertificate(publicRoot)
	if e != nil {
		t.Fatal(e)
	}
	kc := *identity.kc
	kc.username = "reviewer"
	reviewer := &installedIdentity{kc: &kc, Issuer: identity.Issuer, RootPEM: identity.RootPEM, ReviewerSubject: identity.ReviewerSubject}
	p := &installedLiveProducer{t: t, ctx: ctx, admin: admin, root: root, f: f, invoke: invoke, reviewer: reviewer, browser: reviewer.consoleSession(t, ctx, cert, address, origin), observe: observe, transport: transport, owner: identity, origin: origin}
	pods, e := f.region.CoreV1().Pods(f.namespace).List(ctx, meta.ListOptions{LabelSelector: "app=" + f.workload})
	if e != nil {
		t.Fatal(e)
	}
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp == nil && pod.Status.Phase == "Running" {
			if p.podUID != "" {
				t.Fatal("LIVE expects exact one whole-Pod target")
			}
			p.podUID, p.podName = string(pod.UID), pod.Name
		}
	}
	if p.podUID == "" {
		t.Fatal("LIVE original workload Pod unavailable")
	}
	publishManualHTTPProfile(t, ctx, regionalConfig, f.namespace)
	binding := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"name": "installed-live-automation"}, "spec": map[string]any{"effect": "Allow", "subjects": f.binding["subjects"], "roles": []any{"workload-maintainer", "evidence-owner"}, "scope": f.binding["scope"], "reason": "bounded installed LIVE source qualification", "automation": map[string]any{"allowedActions": []any{"packetCapture", "syscallTrace"}, "maxLifetimeSeconds": 300, "maxExecutions": 8, "maxBytes": 64 << 20, "maxObservedBytes": 256 << 20}}}
	raw, _ := json.Marshal(binding)
	if e = f.hub.Post().AbsPath(f.base + "accessbindings").Body(raw).Do(ctx).Error(); e != nil {
		t.Fatal("LIVE actual automation envelope", e)
	}
	traffic, cancel := context.WithCancel(ctx)
	var joined sync.WaitGroup
	joined.Add(1)
	go func() {
		defer joined.Done()
		for traffic.Err() == nil {
			call, end := context.WithTimeout(traffic, 2*time.Second)
			request := f.region.CoreV1().RESTClient().Get().Namespace(f.namespace).Resource("pods").Name(p.podName + ":8080").SubResource("proxy").Suffix("log")
			_, _ = manualHTTPTraffic(request).DoRaw(call)
			end()
			if installedJourneyPause(traffic, 100*time.Millisecond) != nil {
				return
			}
		}
	}()
	defer func() { cancel(); joined.Wait() }()
	for i, projection := range []string{"packetMetadata", "syscallMetadata", "httpHeaders"} {
		current, e := f.region.CoreV1().Pods(f.namespace).Get(ctx, p.podName, meta.GetOptions{})
		if e != nil || string(current.UID) != p.podUID {
			t.Fatal("LIVE cannot replace its original Pod", e)
		}
		p.source(ctx, fmt.Sprintf("installed-live-%d", i), projection)
	}
	for _, projection := range []string{"packetMetadata", "syscallMetadata", "httpHeaders"} {
		p.manual(ctx, projection)
	}
}
