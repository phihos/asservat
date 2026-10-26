package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type installedJourneyBearer struct {
	inner http.RoundTripper
	token func(context.Context) (string, error)
}

func (b installedJourneyBearer) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := b.token(r.Context())
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+token)
	return b.inner.RoundTrip(r)
}

// installedJourney returns the first installed S-02 slice: as the owned
// Keycloak user, over MCP through the public API's NodePort Service
// (ADR-202), preview, request and resolve a pod-status capture of the
// regional workload, download it, then see access end when the operator
// revokes it and again when the capture expires. deny adds (true) or removes
// (false) the operator's Deny binding for the user's group. Every authority
// input is the installed product's own:
// the operator's AccessBinding, the permission stream, the regional capacity
// binding refreshed on demand (ADR-200) and the federation; nothing is seeded.
// diagnose prints the hub processes' logs before a failure ends the test.
// installedJourneyRetention is the requested evidence access lifetime in
// seconds: long enough to collect, publish and download, short enough to
// wait for expiry. CI reached the expiry wait 155 s after acceptance (local
// native109: 168 s); 240 s keeps about 50 % margin and lets the cluster's full
// journey fit one 20-minute run.
const installedJourneyRetention = 240

// installedJourneyRetentionSeconds is the journey's retention. The focused
// journey run (ASSERVAT_JOURNEY_FOCUS=journey) moves the console checks and
// the approved projection to the browser focus and reached the expiry wait
// 25 s after acceptance locally, so 80 s keeps a margin of about a minute
// and the run stays well under 15 minutes.
func installedJourneyRetentionSeconds() int64 {
	if installedJourneyFocus() == "journey" {
		return 80
	}
	return installedJourneyRetention
}

type installedJourneyDownload struct {
	DownloadID          string    `json:"download_id"`
	ArtifactID          string    `json:"artifact_id"`
	State               string    `json:"state"`
	SizeBytes           *int64    `json:"size_bytes"`
	SHA256              string    `json:"sha256"`
	ContentPath         string    `json:"content_path"`
	ContinuePreparation bool      `json:"continue_preparation"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// installedJourney returns the installed S-02 journey for one regional
// workload. A nil deny selects the short journey for a further workload
// cluster: preview, request, collection/publication, get_case and the native
// download with its SHA-256 check, after the full journey has initialized
// processing. Its idempotency keys carry the cluster so they never collide
// with the full journey's keys.
func installedJourney(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string, identity *installedIdentity, publicRoot []byte, address, origin string, diagnose func(), deletionCheck func(artifactID string) func(), projectionCheck installedProjectionCheck) func(cluster, namespace, workload string, deny func(bool), gone func(podUID string)) {
	// Each further run in the same installation gets its own idempotency keys;
	// the count spans every cluster's journey in this test process.
	return func(cluster, namespace, workload string, deny func(bool), gone func(podUID string)) {
		installedJourneyRuns++
		runs := installedJourneyRuns
		t.Helper()
		if identity == nil {
			t.Fatal("installed journey requires the harness identity provider")
		}
		short, keys := deny == nil, "installed-journey"
		if short {
			keys += "-" + cluster
		}
		if runs > 1 {
			keys += fmt.Sprintf("-run%d", runs)
		}
		// The focused restart run (ASSERVAT_JOURNEY_FOCUS=restart) starts with a
		// short journey, which must initialize processing itself.
		initialize := !short || (installedJourneyFocus() == "restart" || installedJourneyFocus() == "clusters" || installedJourneyFocus() == "upgrade" || installedJourneyFocus() == "chain" || installedJourneyFocus() == "share") && runs == 1
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
			t.Fatal("installed wire contracts", err)
		}
		// ADR-210: processing is initialized once, before any preview.
		if initialize {
			identity.initializeProcessing(t, ctx, cert, address, origin, diagnose)
		}
		tokens := identity.mcpTokenSource(origin)
		client := sdk.NewClient(&sdk.Implementation{Name: "installed-journey", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
		session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(origin, "/") + "/mcp", HTTPClient: &http.Client{Transport: installedJourneyBearer{transport, tokens.Token}, Timeout: 60 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
		if err != nil {
			t.Fatal("installed MCP session", err)
		}
		defer session.Close()
		// Discovery/status calls may retry, and capture requests retain their
		// original preview and idempotency key. An uncertain download prepare
		// never retries automatically: only its acknowledged continuation flag
		// below permits another call under the exact original key.
		readReply := func(callCtx context.Context, name string, arguments any) (installedJourneyEnvelope, error) {
			result, err := session.CallTool(callCtx, &sdk.CallToolParams{Name: name, Arguments: arguments})
			if err != nil {
				return installedJourneyEnvelope{}, err
			}
			reply, err := installedJourneyReply(wire, name, result)
			if err != nil {
				diagnose()
				t.Fatal("installed response contract", name, err)
			}
			return reply, err
		}
		call := func(callCtx context.Context, name string, arguments any, data any) {
			t.Helper()
			tries := 4
			if name == "prepare_artifact_download" {
				tries = 1
			}
			var failure error
			for attempt := 1; attempt <= tries; attempt++ {
				started := time.Now()
				reply, err := readReply(callCtx, name, arguments)
				if err == nil && reply.Status == "ok" {
					if err = installedJourneyDecode(reply.Data, data); err != nil {
						t.Fatal("installed response data", name, err)
					}
					return
				}
				failure = err
				if failure == nil {
					// The validated public error deliberately exposes no private
					// dependency stage. Retain its existing retryability distinction
					// and request correlation without logging inputs or credentials.
					var unavailable struct {
						Retryable bool `json:"retryable"`
					}
					if json.Unmarshal(reply.Data, &unavailable) != nil {
						t.Fatal("installed unavailable response")
					}
					failure = fmt.Errorf("acknowledged operation unavailable (retryable=%t)", unavailable.Retryable)
				}
				t.Logf("installed %s attempt %d after %s request %s: %v", name, attempt, time.Since(started).Round(time.Millisecond), reply.RequestID, failure)
				if attempt < tries && installedJourneyPause(callCtx, 2*time.Second) != nil {
					break
				}
			}
			diagnose()
			t.Fatalf("installed %s: %v", name, failure)
		}
		target := map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload}
		previewArguments := map[string]any{"target_ref": target,
			"preset_ref": map[string]string{"name": "pod-status", "version": "v1"}, "requested_retention_seconds": installedJourneyRetentionSeconds()}
		if dir := os.Getenv("ASSERVAT_JOURNEY_HOLD"); dir != "" && !short {
			installedJourneyHold(t, ctx, dir, wire, session, previewArguments, diagnose)
		}
		// The console checks run in the unfocused run and in the browser focus;
		// the journey focus covers the MCP, Stop, Deny, TargetGone, expiry and
		// deletion checks (both within the 20-minute rule).
		browserChecks := !short && installedJourneyFocus() != "journey"
		if browserChecks {
			qualifyInstalledBrowserSubmission(t, ctx, identity, cert, address, origin, previewArguments, diagnose)
		}
		var preview struct {
			PreviewID      string `json:"preview_id"`
			CaptureEnabled bool   `json:"capture_enabled"`
			TargetRef      struct {
				ClusterID string `json:"cluster_id"`
			} `json:"target_ref"`
			SelectedPods []struct {
				UID       string `json:"uid"`
				ClusterID string `json:"cluster_id"`
			} `json:"selected_pods"`
		}
		var accepted installedJourneyAcceptedReceipt
		// Resolve failures under the original preview/key before continuing.
		// Only an acknowledged close permits this fixture's next fresh review;
		// continuation requires an acknowledged accepted capture.
		requestCapture := func(arguments map[string]any) string {
			t.Helper()
			result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "request_capture", Arguments: arguments})
			if err != nil {
				t.Logf("installed request_capture transport: %v", err)
				return "OutcomeUnknown"
			}
			reply, code, err := installedJourneyReplyCode(wire, "request_capture", result)
			if err != nil {
				diagnose()
				t.Fatal("installed response contract request_capture", err)
			}
			if code == "" {
				var current struct {
					CaptureID string `json:"capture_id"`
				}
				if err = installedJourneyDecode(reply.Data, &current); err != nil {
					t.Fatal("installed response data request_capture", err)
				}
				if err = accepted.remember(current.CaptureID, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("installed request_capture %s request %s", map[bool]string{true: "ok", false: code}[code == ""], reply.RequestID)
			return code
		}
		var request map[string]any
		for attempt := 1; ; attempt++ {
			accepted = installedJourneyAcceptedReceipt{}
			call(ctx, "preview_capture", previewArguments, &preview)
			if !preview.CaptureEnabled || len(preview.SelectedPods) != 1 || preview.PreviewID == "" || preview.SelectedPods[0].UID == "" {
				t.Fatal("installed preview did not pin the regional Pod", preview)
			}
			// No cross-cluster mixup: the preview names the requested cluster
			// for both the target and its one selected Pod.
			if preview.TargetRef.ClusterID != cluster || preview.SelectedPods[0].ClusterID != cluster {
				t.Fatal("installed preview names another cluster", preview.TargetRef.ClusterID, preview.SelectedPods[0].ClusterID, cluster)
			}
			request = map[string]any{"preview_id": preview.PreviewID, "idempotency_key": fmt.Sprintf("%s-capture-%d", keys, attempt)}
			closed, err := installedJourneyRecoverCapture(ctx, requestCapture(request), func() (installedJourneyDisposition, error) {
				reply, err := readReply(ctx, "resolve_capture_request", request)
				if err != nil {
					return installedJourneyDisposition{}, err
				}
				if reply.Status != "ok" {
					return installedJourneyDisposition{}, errors.New("original capture request remains unresolved")
				}
				var disposition installedJourneyDisposition
				err = installedJourneyDecode(reply.Data, &disposition)
				if err == nil && disposition.State == "accepted" {
					err = accepted.remember(disposition.CaptureID, time.Now())
				}
				return disposition, err
			}, func() (string, string) {
				code := requestCapture(map[string]any{"preview_id": request["preview_id"], "idempotency_key": request["idempotency_key"], "continue_acquisition": true})
				return code, accepted.CaptureID
			}, func() error {
				var resolved installedJourneyDisposition
				call(ctx, "resolve_capture_request", request, &resolved)
				if accepted.CaptureID == "" || resolved.State != "accepted" || resolved.CaptureID != accepted.CaptureID {
					return errors.New("installed request was not accepted once")
				}
				return nil
			}, installedJourneyPause, func(id string) (installedJourneyCaptureProgress, error) {
				var current installedJourneyCaptureProgress
				reply, err := readReply(ctx, "get_capture", map[string]string{"capture_id": id})
				if err != nil {
					return current, err
				}
				if reply.Status != "ok" {
					return current, errors.New("original accepted capture progress is unavailable")
				}
				err = installedJourneyDecode(reply.Data, &current)
				return current, err
			})
			if err != nil {
				diagnose()
				t.Fatal("installed capture request was not accepted", err)
			}
			if !closed {
				break
			}
			if attempt == 4 {
				diagnose()
				t.Fatal("installed capture requests closed without admission after four reviews")
			}
			if installedJourneyPause(ctx, 2*time.Second) != nil {
				t.Fatal("installed capture request", ctx.Err())
			}
		}
		if accepted.CaptureID == "" || accepted.AcceptedAt.IsZero() {
			t.Fatal("installed capture lost its acknowledged original receipt")
		}
		t.Logf("installed journey: MCP preview, request and resolution of a regional pod-status capture in cluster %s as the Keycloak user", cluster)
		if !short {
			installedJourneyIdempotency(t, ctx, admin, root, accepted.CaptureID, request, requestCapture)
		}
		// The regional executor collects; the publisher verifies and publishes
		// (ADR-203). A successful capture may omit its independently authorized
		// case link. Keep both passive waits inside one original phase deadline.
		publicationUntil := time.Now().Add(5 * time.Minute)
		var progress installedJourneyCaptureProgress
		wait := func(what string, until time.Time, done func(context.Context) bool) {
			t.Helper()
			bounded, stop := context.WithDeadline(ctx, until)
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
			t.Fatal("installed journey: timed out waiting for", what)
		}
		// Unpublished cases are intentionally unavailable. Read polls may
		// remain pending for their whole phase budget; four short call retries
		// must not turn an otherwise healthy delayed publication into failure.
		observe := func(poll context.Context, name string, arguments any, data any) bool {
			reply, err := readReply(poll, name, arguments)
			if err != nil || reply.Status != "ok" {
				return false
			}
			if installedJourneyDecode(reply.Data, data) != nil {
				t.Fatal("installed status data", name)
			}
			return true
		}
		wait("a successful capture with a current case link", publicationUntil, func(poll context.Context) bool {
			if !observe(poll, "get_capture", map[string]string{"capture_id": accepted.CaptureID}, &progress) {
				return false
			}
			ready, err := installedJourneyCaptureCaseReady(poll, accepted.CaptureID, progress)
			if err != nil {
				diagnose()
				t.Fatal("installed capture was not collected", err)
			}
			return ready
		})
		if progress.Phase != "Succeeded" || progress.CaseID == "" {
			diagnose()
			t.Fatal("installed capture was not collected", progress.Phase, progress.CaseID)
		}
		var investigation struct {
			Artifacts []struct {
				ArtifactID string    `json:"artifact_id"`
				ExpiresAt  time.Time `json:"expires_at"`
			} `json:"artifacts"`
		}
		wait("the published artifact", publicationUntil, func(poll context.Context) bool {
			return observe(poll, "get_case", map[string]string{"case_id": progress.CaseID}, &investigation) && len(investigation.Artifacts) > 0
		})
		if len(investigation.Artifacts) != 1 {
			t.Fatal("installed case lists more than the one pod-status artifact", investigation.Artifacts)
		}
		expires := investigation.Artifacts[0].ExpiresAt
		if expires.IsZero() || !time.Now().Before(expires) || expires.After(accepted.AcceptedAt.Add(time.Duration(installedJourneyRetentionSeconds())*time.Second)) {
			t.Fatal("installed capture returned an invalid original retention deadline", expires)
		}
		// Operator readback: the published attempt is stored under this cluster.
		var stored []string
		if err := admin.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT a.cluster_id::text),'{}') FROM context_catalog c JOIN custody_attempt a ON a.artifact_id=c.artifact_id WHERE c.root_id=$1 AND c.artifact_id=$2`, root, investigation.Artifacts[0].ArtifactID).Scan(&stored); err != nil || len(stored) != 1 || stored[0] != cluster {
			t.Fatal("installed artifact is not stored under the requested cluster", stored, err)
		}
		var checkDeleted func()
		if !short {
			if deletionCheck == nil {
				t.Fatal("installed journey requires independent deletion verification")
			}
			if checkDeleted = deletionCheck(investigation.Artifacts[0].ArtifactID); checkDeleted == nil {
				t.Fatal("installed deletion verification missing")
			}
		}
		t.Logf("installed journey: the regional capture in cluster %s was collected, verified and published", cluster)
		var approved query.ContextExcerpt
		var checkQueryRetired func()
		// The approved read-only projection (and its retirement check) belongs
		// to the console checks: the browser focus and the unfocused run.
		if browserChecks {
			approved, checkQueryRetired = installedApprovedProjection(t, ctx, identity, transport, origin, progress.CaseID, investigation.Artifacts[0].ArtifactID, preview.SelectedPods[0].UID, expires, projectionCheck)
		}
		// A hub-local download worker (ADR-204) prepares the native file; the
		// same MCP client fetches it with its download-route token.
		var download installedJourneyDownload
		prepare := map[string]string{"artifact_id": investigation.Artifacts[0].ArtifactID, "idempotency_key": keys + "-download"}
		call(ctx, "prepare_artifact_download", prepare, &download)
		originalDownload, downloadUntil := download.DownloadID, download.ExpiresAt
		if originalDownload == "" || downloadUntil.IsZero() || downloadUntil.After(expires) {
			t.Fatal("installed download deadline", downloadUntil)
		}
		wait("a prepared download", installedJourneyEarlier(downloadUntil, time.Now().Add(5*time.Minute)), func(poll context.Context) bool {
			if download.State == "Preparing" {
				// GET cannot start or continue a worker. Only an acknowledged
				// prepare with this flag permits another same-key prepare.
				name, args := "get_artifact_download", map[string]string{"download_id": originalDownload}
				if download.ContinuePreparation {
					name, args = "prepare_artifact_download", prepare
				}
				call(poll, name, args, &download)
			}
			if download.DownloadID != originalDownload || !download.ExpiresAt.Equal(downloadUntil) {
				t.Fatal("installed download changed its original identity/deadline")
			}
			return download.State != "Preparing"
		})
		if download.State != "Ready" || download.ContentPath == "" || download.SizeBytes == nil || *download.SizeBytes < 1 || *download.SizeBytes > artifact.MaxContextBytes || download.SHA256 == "" {
			diagnose()
			t.Fatal("installed download was not prepared", download.State, download.ContentPath)
		}
		contentURL, contentClient := strings.TrimSuffix(origin, "/")+download.ContentPath, &http.Client{Transport: transport, Timeout: 2 * time.Minute}
		var head, tail []byte
		if !short {
			head, tail = installedJourneyResume(t, ctx, contentClient, contentURL, identity.downloadToken(), *download.SizeBytes)
		}
		response := installedJourneyContent(t, ctx, contentClient, contentURL, identity.downloadToken(), nil)
		native, err := io.ReadAll(io.LimitReader(response.Body, artifact.MaxContextBytes+1))
		response.Body.Close()
		digest := sha256.Sum256(native)
		size := int64(len(native))
		var projected struct {
			Format       string `json:"format"`
			NamespaceUID string `json:"namespaceUID"`
			PodUID       string `json:"podUID"`
		}
		if err != nil || response.StatusCode != http.StatusOK || size != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 ||
			json.Unmarshal(native, &projected) != nil || projected.Format != artifact.ContextFormat || projected.PodUID != preview.SelectedPods[0].UID {
			diagnose()
			t.Fatal("installed native download differs from its metadata or selected Pod", response.StatusCode, size, err)
		}
		if browserChecks {
			if err := installedProjectionMatchesNative(approved, native); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("installed journey: the Keycloak user downloaded the native pod-status file (%d bytes) of cluster %s through the hub-local worker", size, cluster)
		if short {
			if installedJourneyFocus() == "share" {
				// ADR-232: share the published artifact with the unrelated principal.
				installedJourneyShare(t, ctx, wire, identity, transport, origin, progress.CaseID, investigation.Artifacts[0].ArtifactID, native, diagnose)
			}
			t.Logf("installed journey: short journey in cluster %s complete; its native file names Pod %s in namespace %s", cluster, projected.PodUID, projected.NamespaceUID)
			return
		}
		if !bytes.Equal(append(head, tail...), native) {
			t.Fatal("installed resumed ranges differ from the full native download")
		}
		installedJourneyResumeSpent(t, ctx, admin, contentClient, root, originalDownload, contentURL, identity.downloadToken(), size)
		installedJourneyCatalogMinimized(t, ctx, admin, root, investigation.Artifacts[0].ArtifactID, native)
		if browserChecks {
			qualifyInstalledBrowserJourney(t, ctx, identity, cert, address, origin, readReply, previewArguments,
				progress.CaseID, investigation.Artifacts[0].ArtifactID, approved, native, projectionCheck, diagnose)
		}
		if installedJourneyFocus() == "browser" {
			t.Log("installed journey: browser focus complete; Stop, Deny, TargetGone, expiry and deletion run in the journey focus")
			return
		}
		installedJourneyUnrelated(t, ctx, wire, identity.unrelated(), transport, origin, target, preview.PreviewID, progress.CaseID, investigation.Artifacts[0].ArtifactID)
		// Revocation: with the Deny binding the case is no longer available;
		// without it, it is again. Expiry: once the artifact's access ends,
		// the case no longer offers it and a new preparation is refused.
		available := func(callCtx context.Context) (bool, time.Time) {
			t.Helper()
			reply, err := readReply(callCtx, "get_case", map[string]string{"case_id": progress.CaseID})
			if err != nil {
				t.Fatal("installed get_case", err)
			}
			if reply.Status == "error" {
				return false, time.Time{}
			}
			var data struct {
				Artifacts []struct {
					ArtifactID string    `json:"artifact_id"`
					ExpiresAt  time.Time `json:"expires_at"`
				} `json:"artifacts"`
			}
			if installedJourneyDecode(reply.Data, &data) != nil || len(data.Artifacts) != 1 || data.Artifacts[0].ArtifactID != investigation.Artifacts[0].ArtifactID || !data.Artifacts[0].ExpiresAt.Equal(expires) {
				t.Fatal("installed case changed its original artifact/deadline")
			}
			return true, data.Artifacts[0].ExpiresAt
		}
		until := func(what string, limit time.Duration, want bool) {
			t.Helper()
			wait(what, time.Now().Add(limit), func(poll context.Context) bool { got, _ := available(poll); return got == want })
		}
		refused := func(key string) {
			t.Helper()
			reply, err := readReply(ctx, "prepare_artifact_download", map[string]string{"artifact_id": investigation.Artifacts[0].ArtifactID, "idempotency_key": key})
			if err != nil || reply.Status != "error" {
				t.Fatal("installed journey: new preparation was not refused", key, err)
			}
		}
		healthy := func() {
			t.Helper()
			var diagnostics struct {
				Diagnostics []struct {
					Available bool `json:"available"`
				} `json:"diagnostics"`
			}
			call(ctx, "list_diagnostics", map[string]any{"target_ref": target}, &diagnostics)
			if len(diagnostics.Diagnostics) != 1 || !diagnostics.Diagnostics[0].Available {
				t.Fatal("installed authorized diagnostic is unavailable")
			}
		}
		healthy()
		// The installed four-record backing admits the MCP, browser and Stop
		// sessions without refunding completed ones: 24 KiB output and 48 MiB
		// read fit its 32 KiB/48 MiB allocation. Stop needs a nonterminal
		// session; stopping the completed first download proves AlreadyTerminal.
		stopReply, err := readReply(ctx, "prepare_artifact_download", map[string]string{
			"artifact_id": investigation.Artifacts[0].ArtifactID, "idempotency_key": "installed-journey-stop-download",
		})
		var stopDownload installedJourneyDownload
		if err != nil || stopReply.Status != "ok" || installedJourneyDecode(stopReply.Data, &stopDownload) != nil ||
			stopDownload.DownloadID == "" || stopDownload.DownloadID == originalDownload || stopDownload.ArtifactID != investigation.Artifacts[0].ArtifactID ||
			(stopDownload.State != "Preparing" && stopDownload.State != "Ready") || !time.Now().Before(stopDownload.ExpiresAt) || stopDownload.ExpiresAt.After(expires) {
			diagnose()
			t.Fatal("installed Stop requires one acknowledged distinct nonterminal download", stopReply.RequestID, err)
		}
		if checkQueryRetired != nil {
			checkQueryRetired()
		}
		// Preparing need not advertise a content link. Retain the public route
		// for this acknowledged ID; no second readiness/worker wait is needed.
		stopContentPath := "/api/v1/downloads/" + stopDownload.DownloadID + "/content"
		if stopDownload.ContentPath != "" && stopDownload.ContentPath != stopContentPath {
			t.Fatal("installed Stop preparation changed its content route")
		}
		// The operator closure waits for a fresh accepted SQL Deny projection.
		// Public errors deliberately conflate refusal and service failure; the
		// independent projection and restored positive read establish controls,
		// not a private explanation of the individual wire error.
		deny(true)
		until("the revocation", 2*time.Minute, false)
		refused("installed-journey-revoked")
		stopCtx, stopEnd := context.WithDeadline(ctx, stopDownload.ExpiresAt)
		stopReceipts, err := installedJourneyStopTwice(stopCtx, readReply, stopDownload.DownloadID, "installed-journey-stop")
		stopEnd()
		for attempt, receipt := range stopReceipts {
			if receipt.RequestID != "" {
				t.Logf("installed Stop call %d: download %s request %s state %s audit %s", attempt+1, receipt.DownloadID, receipt.RequestID, receipt.State, receipt.AuditState)
			}
		}
		if err != nil {
			diagnose()
			t.Fatal("installed Stop after accepted Deny", err)
		}
		deny(false)
		until("the restored access", 2*time.Minute, true)
		healthy()
		var stopped installedJourneyDownload
		call(ctx, "get_artifact_download", map[string]string{"download_id": stopDownload.DownloadID}, &stopped)
		if stopped.DownloadID != stopDownload.DownloadID || stopped.ArtifactID != stopDownload.ArtifactID || stopped.State != "Cancelled" ||
			!stopped.ExpiresAt.Equal(stopDownload.ExpiresAt) || stopped.ContentPath != "" || stopped.SizeBytes != nil || stopped.SHA256 != "" || stopped.ContinuePreparation {
			t.Fatal("installed Stop changed identity/deadline or regained native delivery")
		}
		stoppedGet, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(origin, "/")+stopContentPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		stoppedGet.Header.Set("Authorization", "Bearer "+identity.downloadToken())
		stoppedResponse, err := (&http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(stoppedGet)
		if err != nil {
			diagnose()
			t.Fatal("installed stopped content response", err)
		}
		if err = installedJourneyStoppedContent(stoppedResponse); err != nil {
			diagnose()
			t.Fatal("installed stopped content disclosed data", err)
		}
		t.Log("installed journey: Stop after accepted Deny remained Cancelled on exact-key replay and restored access; original content route returned only a bounded problem response (no active-stream interruption tested)")
		t.Log("installed journey: accepted Deny accompanied refusal; removing it restored the original artifact")
		if gone != nil {
			// S-02 exit item 2: a reviewed Pod deleted before submission is a
			// useful, non-retryable TargetGone, not an uncertain outcome.
			var gonePreview struct {
				PreviewID    string `json:"preview_id"`
				SelectedPods []struct {
					UID string `json:"uid"`
				} `json:"selected_pods"`
			}
			call(ctx, "preview_capture", previewArguments, &gonePreview)
			if gonePreview.PreviewID == "" || len(gonePreview.SelectedPods) != 1 || gonePreview.SelectedPods[0].UID == "" {
				t.Fatal("installed preview before Pod deletion", gonePreview)
			}
			gone(gonePreview.SelectedPods[0].UID)
			// OutcomeUnknown asks for a retry with the same preview and key.
			goneRequest := map[string]any{"preview_id": gonePreview.PreviewID, "idempotency_key": keys + "-gone"}
			code := requestCapture(goneRequest)
			for attempt := 1; code == "OutcomeUnknown" && attempt < 4 && installedJourneyPause(ctx, 2*time.Second) == nil; attempt++ {
				code = requestCapture(goneRequest)
			}
			if code != "TargetGone" {
				diagnose()
				t.Fatal("installed request for a deleted pinned Pod", code)
			}
			t.Log("installed journey: request for a deleted pinned Pod returned TargetGone and started no capture")
		}
		// Measures how much of installedJourneyRetention the journey leaves
		// idle, so the retention can be set no longer than it needs.
		t.Logf("installed journey: %s after acceptance, waiting %s for the original expiry", time.Since(accepted.AcceptedAt).Round(time.Second), time.Until(expires).Round(time.Second))
		if err := installedJourneyPause(ctx, time.Until(expires)); err != nil {
			t.Fatal("installed expiry wait", err)
		}
		healthy()
		until("the expiry", 2*time.Minute, false)
		refused("installed-journey-expired")
		healthy()
		checkDeleted()
		t.Log("installed journey: after original expiry, case and new preparation refused while current workload diagnostics succeeded; independent deletion verified")
	}
}

type installedJourneyStopReceipt struct {
	DownloadID string `json:"download_id"`
	State      string `json:"state"`
	AuditState string `json:"audit_state"`
	RequestID  string `json:"-"`
}

// These are two explicit calls, not an uncertain-mutation retry loop. The
// second verifies the original acknowledged Stop's identity and audit state.
func installedJourneyStopTwice(ctx context.Context, read func(context.Context, string, any) (installedJourneyEnvelope, error), downloadID, key string) ([2]installedJourneyStopReceipt, error) {
	var receipts [2]installedJourneyStopReceipt
	for i := range receipts {
		if err := ctx.Err(); err != nil {
			return receipts, err
		}
		reply, err := read(ctx, "cancel_artifact_download", map[string]string{"download_id": downloadID, "idempotency_key": key})
		if err != nil {
			return receipts, err
		}
		if ctx.Err() != nil {
			return receipts, ctx.Err()
		}
		if reply.Status != "ok" || reply.RequestID == "" || installedJourneyDecode(reply.Data, &receipts[i]) != nil ||
			receipts[i].DownloadID != downloadID || receipts[i].State != "Cancelled" ||
			(receipts[i].AuditState != "pending" && receipts[i].AuditState != "recorded" && receipts[i].AuditState != "overdue") {
			return receipts, errors.New("Stop did not acknowledge the exact live download")
		}
		receipts[i].RequestID = reply.RequestID
		if i > 0 && (receipts[i].RequestID != receipts[0].RequestID || receipts[0].AuditState == "recorded" && receipts[i].AuditState != "recorded") {
			return receipts, errors.New("Stop replay changed the original request or lost recorded audit")
		}
	}
	return receipts, nil
}

func installedJourneyStoppedContent(response *http.Response) error {
	if response == nil || response.Body == nil {
		return errors.New("missing stopped content response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	closed := response.Body.Close()
	var problem map[string]any
	if err != nil || closed != nil || len(body) > 1024 || response.StatusCode != http.StatusServiceUnavailable ||
		response.Header.Get("Content-Type") != "application/problem+json" || response.Header.Get("Content-Disposition") != "" ||
		response.Header.Get("ETag") != "" || response.Header.Get("Content-Range") != "" ||
		json.Unmarshal(body, &problem) != nil || len(problem) != 3 || problem["type"] != "about:blank" ||
		problem["title"] != http.StatusText(response.StatusCode) || problem["status"] != float64(response.StatusCode) {
		return errors.New("stopped route did not return the bounded public unavailable response")
	}
	return nil
}

type installedJourneyEnvelope struct {
	RequestID string          `json:"request_id"`
	Status    string          `json:"status"`
	Data      json.RawMessage `json:"data"`
}

type installedJourneyDisposition struct {
	State     string `json:"state"`
	CaptureID string `json:"capture_id"`
}

type installedJourneyCaptureProgress struct {
	CaptureID string `json:"capture_id"`
	Phase     string `json:"phase"`
	CaseID    string `json:"case_id"`
}

// A terminal failure ends the passive wait. Successful collection must also
// supply a currently authorized navigation link before the case is selected;
// the subsequent get_case still performs its own fresh authorization.
func installedJourneyCaptureCaseReady(ctx context.Context, captureID string, progress installedJourneyCaptureProgress) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if captureID == "" || progress.CaptureID != captureID {
		return false, errors.New("installed progress changed the original capture identity")
	}
	switch progress.Phase {
	case "Succeeded":
		if progress.CaseID == "" {
			return false, nil
		}
		return true, nil
	case "Partial", "Failed", "Cancelled", "Indeterminate":
		return false, fmt.Errorf("installed capture was not collected: %s", progress.Phase)
	default:
		return false, nil
	}
}

// The retained receipt selects the original operation; each public read and
// continuation still supplies fresh authorization. Its first acknowledgement
// time remains the conservative upper bound used by the retention assertion.
type installedJourneyAcceptedReceipt struct {
	CaptureID  string
	AcceptedAt time.Time
}

func (r *installedJourneyAcceptedReceipt) remember(id string, now time.Time) error {
	if id == "" || now.IsZero() || (r.CaptureID != "" && r.CaptureID != id) {
		return errors.New("installed accepted capture identity changed")
	}
	r.CaptureID = id
	if r.AcceptedAt.IsZero() {
		r.AcceptedAt = now
	}
	return nil
}

// Recovery never infers non-admission from a failed request. The resolver must
// acknowledge closure before the fixture can review again. An accepted request
// stays bound to its original identity, including across continuation failures.
// Once acceptance is known, a fresh current progress read determines whether
// another explicit continuation is appropriate. Progress past Pending hands
// off to the unchanged terminal/publication checks; it is not success here.
// Only immediate success needs a separate admission confirmation.
func installedJourneyRecoverCapture(ctx context.Context, code string, resolve func() (installedJourneyDisposition, error), continueCapture func() (code, captureID string), confirmAccepted func() error, pause func(context.Context, time.Duration) error, observe func(string) (installedJourneyCaptureProgress, error)) (closed bool, err error) {
	acceptedID := ""
	for continued := 0; code != ""; {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		switch code {
		case "OutcomeUnknown", "ReviewChanged", "NotAvailable":
		default:
			return false, fmt.Errorf("original capture request failed: %s", code)
		}
		if acceptedID == "" {
			disposition, err := resolve()
			if err != nil {
				return false, err
			}
			if err := ctx.Err(); err != nil {
				return false, err
			}
			switch disposition.State {
			case "closed":
				if disposition.CaptureID != "" {
					return false, errors.New("closed capture request contains an accepted identity")
				}
				return true, nil
			case "accepted":
				if disposition.CaptureID == "" {
					return false, errors.New("original accepted capture identity is missing")
				}
				acceptedID = disposition.CaptureID
			default:
				return false, errors.New("original capture request remains unresolved")
			}
		}
		if code != "OutcomeUnknown" {
			return false, fmt.Errorf("original accepted capture remains unavailable: %s", code)
		}
		current, err := observe(acceptedID)
		if err != nil {
			return false, err
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if current.CaptureID != acceptedID {
			return false, errors.New("current progress changed the original accepted capture identity")
		}
		switch current.Phase {
		case "Running", "Finalizing", "Succeeded":
			return false, nil
		case "Pending":
			if continued == 4 {
				return false, errors.New("original accepted capture remains pending after four continuations")
			}
		default:
			return false, fmt.Errorf("original accepted capture cannot continue in phase %s", current.Phase)
		}
		if err := pause(ctx, 2*time.Second); err != nil {
			return false, err
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		var captureID string
		code, captureID = continueCapture()
		if code == "" && captureID != acceptedID {
			return false, errors.New("successful continuation changed the original accepted capture identity")
		}
		continued++
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if acceptedID != "" {
		return false, nil
	}
	if err := confirmAccepted(); err != nil {
		return false, err
	}
	return false, ctx.Err()
}

// installedJourneyReplyCode validates a reply like installedJourneyReply but
// returns any schema-valid public failure code instead of refusing it.
func installedJourneyReplyCode(wire *contracts.InvestigationContracts, name string, result *sdk.CallToolResult) (installedJourneyEnvelope, string, error) {
	var out installedJourneyEnvelope
	if result == nil {
		return out, "", errors.New("missing installed reply")
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
		return installedJourneyEnvelope{}, "", errors.New("invalid installed response schema/status")
	}
	if out.Status == "error" {
		var failure struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(out.Data, &failure) != nil || failure.Code == "" {
			return installedJourneyEnvelope{}, "", errors.New("installed failure without code")
		}
		return out, failure.Code, nil
	} else if out.Status != "ok" {
		return installedJourneyEnvelope{}, "", errors.New("unexpected installed operation status")
	}
	return out, "", nil
}

func installedJourneyReply(wire *contracts.InvestigationContracts, name string, result *sdk.CallToolResult) (installedJourneyEnvelope, error) {
	var out installedJourneyEnvelope
	if result == nil {
		return out, errors.New("missing installed reply")
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil || wire.ValidateOutput(name, raw) != nil || json.Unmarshal(raw, &out) != nil || result.IsError != (out.Status == "error") {
		return installedJourneyEnvelope{}, errors.New("invalid installed response schema/status")
	}
	if out.Status == "error" {
		var failure struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(out.Data, &failure) != nil || failure.Code != "NotAvailable" {
			// The schema-validated public code is a closed enum, never input.
			return installedJourneyEnvelope{}, fmt.Errorf("unexpected installed operation failure %q", failure.Code)
		}
	} else if out.Status != "ok" {
		return installedJourneyEnvelope{}, errors.New("unexpected installed operation status")
	}
	return out, nil
}

// Decode into a fresh value: omitted fields must never retain a previous Ready
// response's native metadata or continuation permission.
func installedJourneyDecode(raw []byte, target any) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return errors.New("invalid installed response destination")
	}
	next := reflect.New(v.Elem().Type())
	if err := json.Unmarshal(raw, next.Interface()); err != nil {
		return err
	}
	v.Elem().Set(next.Elem())
	return nil
}

func installedJourneyPause(ctx context.Context, delay time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func installedJourneyEarlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// installedJourneyHold is a local debugging aid, never set by CI: with
// ASSERVAT_JOURNEY_HOLD=<dir> the journey pauses with the installation live and
// runs commands written to <dir>/cmd one at a time: "preview" makes one
// preview_capture call and appends its outcome to <dir>/out, "diagnose" logs
// the hub processes, "continue" resumes the journey and "stop" fails the test.
// The hold ends on its own ten minutes before the test context's deadline.
func installedJourneyHold(t *testing.T, ctx context.Context, dir string, wire *contracts.InvestigationContracts, session *sdk.ClientSession, preview map[string]any, diagnose func()) {
	t.Helper()
	out, err := os.OpenFile(filepath.Join(dir, "out"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("journey hold output", err)
	}
	defer out.Close()
	until := time.Now().Add(90 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Add(-10*time.Minute).Before(until) {
		until = d.Add(-10 * time.Minute)
	}
	fmt.Fprintf(out, "%s hold ready until %s\n", time.Now().Format(time.TimeOnly), until.Format(time.TimeOnly))
	for time.Now().Before(until) {
		raw, err := os.ReadFile(filepath.Join(dir, "cmd"))
		if err != nil {
			if installedJourneyPause(ctx, 500*time.Millisecond) != nil {
				return
			}
			continue
		}
		_ = os.Remove(filepath.Join(dir, "cmd"))
		switch command := strings.TrimSpace(string(raw)); command {
		case "preview":
			started := time.Now()
			call, end := context.WithTimeout(ctx, 30*time.Second)
			result, err := session.CallTool(call, &sdk.CallToolParams{Name: "preview_capture", Arguments: preview})
			end()
			line := fmt.Sprintf("%s preview after %s: ", started.Format(time.TimeOnly), time.Since(started).Round(time.Millisecond))
			if err != nil {
				line += "transport " + err.Error()
			} else if reply, e := installedJourneyReply(wire, "preview_capture", result); e != nil {
				line += "contract " + e.Error()
			} else {
				line += reply.Status + " request " + reply.RequestID + " " + string(reply.Data)
			}
			fmt.Fprintln(out, line)
		case "request":
			// One preview, then a capture request on it under a fresh key.
			started := time.Now()
			call, end := context.WithTimeout(ctx, 30*time.Second)
			result, err := session.CallTool(call, &sdk.CallToolParams{Name: "preview_capture", Arguments: preview})
			end()
			var reply installedJourneyEnvelope
			if err == nil {
				reply, err = installedJourneyReply(wire, "preview_capture", result)
			}
			var previewed struct {
				PreviewID string `json:"preview_id"`
			}
			if err != nil || reply.Status != "ok" || json.Unmarshal(reply.Data, &previewed) != nil || previewed.PreviewID == "" {
				fmt.Fprintf(out, "%s request: preview after %s failed: %v %s\n", started.Format(time.TimeOnly), time.Since(started).Round(time.Millisecond), err, reply.Status)
				continue
			}
			requested := time.Now()
			call, end = context.WithTimeout(ctx, 30*time.Second)
			result, err = session.CallTool(call, &sdk.CallToolParams{Name: "request_capture", Arguments: map[string]string{"preview_id": previewed.PreviewID, "idempotency_key": "hold-" + requested.Format("150405.000")}})
			end()
			line := fmt.Sprintf("%s request after %s: ", requested.Format(time.TimeOnly), time.Since(requested).Round(time.Millisecond))
			if err != nil {
				line += "transport " + err.Error()
			} else if reply, e := installedJourneyReply(wire, "request_capture", result); e != nil {
				line += "contract " + e.Error()
			} else {
				line += reply.Status + " request " + reply.RequestID + " " + string(reply.Data)
			}
			fmt.Fprintln(out, line)
		case "diagnose":
			diagnose()
			fmt.Fprintf(out, "%s diagnosed\n", time.Now().Format(time.TimeOnly))
		case "continue":
			fmt.Fprintf(out, "%s continuing\n", time.Now().Format(time.TimeOnly))
			return
		case "stop":
			t.Fatal("journey hold stopped")
		default:
			fmt.Fprintf(out, "%s unknown command\n", time.Now().Format(time.TimeOnly))
		}
	}
	fmt.Fprintf(out, "%s hold expired\n", time.Now().Format(time.TimeOnly))
}

// installedJourneyFocus splits the installed journey into runs of at most 20
// minutes. "chain": install through the full installation-process checks and
// a short journey in one workload cluster, nothing else. "journey": install
// and the first workload cluster's full journey. "restart": install, a short
// journey, the PostgreSQL restart and another short journey. "clusters":
// install and short journeys in both workload clusters, then the replay.
// "alert": install with an in-cluster Alertmanager and the alert policy phase.
// "share": install, a short journey and the ADR-232 share/read/revoke checks.
// Empty runs everything in one (longer) run.
func installedJourneyFocus() string { return os.Getenv("ASSERVAT_JOURNEY_FOCUS") }

// installedFastFixture selects the feature focuses that start from the shortest
// path to a working installation. They run the same product installation,
// enrollment and authority steps, but skip the checks that qualify the
// installation process itself: the interrupted-and-resumed runner, the
// administrator's baseline edit, the demand-lane sampling, the regional
// installer rerun, connector restart and source-write denial. Their workload
// exists before its cluster joins. Only the chain focus (and the unsplit run)
// keeps the full chain, so the feature focuses keep a margin under the
// 20-minute limit; docs/implementation-progress.md records the split.
func installedFastFixture() bool {
	switch installedJourneyFocus() {
	case "policy", "alert", "browser", "restart", "upgrade", "journey", "clusters", "share":
		return true
	}
	return false
}

// installedRegionalInstallerChecks reports whether workload cluster index
// runs the regional installer's own checks (rerun exactness, connector
// readmission, source-write denial and the demand lane). The fast fixture
// skips them in the first workload cluster, which the chain focus covers;
// the second workload cluster, installed only by the clusters focus and the
// unsplit run, always runs them.
func installedRegionalInstallerChecks(index int) bool {
	return !installedFastFixture() || index > 1
}

// installedJourneyRuns counts journey runs in this installation; only the
// first initializes processing.
var installedJourneyRuns int
