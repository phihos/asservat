package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/google/pprof/profile"
)

// The named template is operator configuration; the request cannot supply a
// URL or select another container. Only the fixture's declared port matches.
func manualProfileEndpoints() []contracts.RegionalProfileEndpoint {
	return []contracts.RegionalProfileEndpoint{{Name: "go-pprof-loopback", Kind: "template", AddressModes: []string{"targetLoopback"}, LoopbackFamily: "ipv4", MinPort: 6060, MaxPort: 6060}}
}

// Exercise the installed history-read + target + recorder composition without
// starting another capture. Each operation gets one attempt, so retries cannot
// conceal the preview deadline failure this qualification is intended to detect.
func qualifyManualProfileRepeatPreview(t *testing.T, captureID string, original installedApprovedRecordingPreview, invoke func(string, any) (installedJourneyEnvelope, string)) {
	t.Helper()
	type settings struct {
		CaptureID       string         `json:"capture_id"`
		Digest          string         `json:"settings_digest"`
		ExecutionDigest string         `json:"original_execution_digest"`
		ExpiresAt       time.Time      `json:"expires_at"`
		Settings        map[string]any `json:"settings"`
	}
	read := func(name string, args, out any) {
		t.Helper()
		started := time.Now()
		var reply installedJourneyEnvelope
		var code string
		defer func() {
			t.Logf("manual profile history %s: single attempt elapsed=%s status=%s code=%s", name, time.Since(started), reply.Status, code)
		}()
		reply, code = invoke(name, args)
		if code != "" || reply.Status != "ok" || json.Unmarshal(reply.Data, out) != nil {
			t.Fatal("manual profile history operation failed", name, reply.Status, code)
		}
	}
	var source settings
	read("get_capture_settings", map[string]string{"capture_id": captureID}, &source)
	var originalComposition map[string]any
	if json.Unmarshal(original.Composition, &originalComposition) != nil || len(originalComposition) != 3 || source.CaptureID != captureID || source.Digest == "" || source.ExecutionDigest != original.Digest || !time.Now().Before(source.ExpiresAt) || !reflect.DeepEqual(source.Settings["profile_composition"], originalComposition) {
		t.Fatal("stored profile settings differ from the original reviewed composition")
	}
	var repeated struct {
		installedApprovedRecordingPreview
		RepeatedFrom string `json:"repeated_from_capture_id"`
	}
	read("preview_capture", map[string]string{"history_capture_id": captureID}, &repeated)
	var repeatedComposition map[string]any
	if !repeated.readyForApproval(time.Now()) || repeated.ID == original.ID || repeated.RepeatedFrom != captureID || json.Unmarshal(repeated.Composition, &repeatedComposition) != nil || !reflect.DeepEqual(repeatedComposition, originalComposition) {
		t.Fatal("repeat preview lost fresh review or immutable authored/profile/action-map composition")
	}
	var after settings
	read("get_capture_settings", map[string]string{"capture_id": captureID}, &after)
	if !reflect.DeepEqual(source, after) || !time.Now().Before(after.ExpiresAt) {
		t.Fatal("repeat preview changed original settings, digest or expiry")
	}
	t.Logf("manual profile %s: fresh repeat preview %s preserved original composition and source expiry %s; no repeat capture requested", captureID, repeated.ID, source.ExpiresAt.Format(time.RFC3339Nano))
}

func manualProfileStopArguments(cluster, namespace, workload string) map[string]any {
	arguments := manualProfileArguments(cluster, namespace, workload)
	composition := arguments["profile_composition"].(map[string]any)
	composition["maxDuration"] = "45s"
	component := composition["components"].([]any)[0].(map[string]any)
	component["overrides"] = []any{
		map[string]any{"actionID": "cpu", "field": "profileDuration", "value": "30s"},
		map[string]any{"actionID": "cpu", "field": "actionTimeout", "value": "40s"},
	}
	return arguments
}

func manualProfileStopRequests(preview installedApprovedRecordingPreview, now time.Time) (map[string]any, map[string]any) {
	original := map[string]any{"preview_id": preview.ID, "idempotency_key": "profile-stop-" + preview.ID}
	resolution := map[string]any{"preview_id": preview.ID, "idempotency_key": original["idempotency_key"]}
	// Raw collection currently requires a selected result-access instruction,
	// even when this separate capture is intended to be stopped before output.
	// Keep the original expiry and instruction unchanged across submission retries.
	if len(preview.Lifecycle.Actions) == 1 {
		original["result_access"] = map[string]any{"actionIds": []string{preview.Lifecycle.Actions[0].ActionID}, "operations": []string{"download_artifact"}, "clientIDs": []string{"mcp"}, "maxArtifacts": 1, "maxBytes": 64 << 20, "maxOperations": 100, "notAfter": now.Add(time.Hour).UTC().Format(time.RFC3339)}
	}
	return original, resolution
}

// This is a second, independently reviewed capture. Stop never mutates or
// deletes the successfully downloaded first profile, and no endpoint probe
// starts an unapproved sampler to discover whether the target is busy.
func qualifyManualProfileStop(t *testing.T, ctx context.Context, arguments map[string]any, read func(string, any, any), invoke func(string, any) (installedJourneyEnvelope, string), approve func(string)) {
	t.Helper()
	var preview installedApprovedRecordingPreview
	read("preview_capture", arguments, &preview)
	if !preview.readyForApproval(time.Now()) || len(preview.Lifecycle.Actions) != 1 {
		t.Fatal("Stop profile lacks an approvable preview", preview.Blockers)
	}
	original, resolution := manualProfileStopRequests(preview, time.Now())
	pending, code := invoke("request_capture", original)
	var review struct {
		URI string `json:"navigation_uri"`
	}
	if code != "ApprovalRequired" || json.Unmarshal(pending.Data, &review) != nil {
		t.Fatal("Stop profile did not require separate approval", code)
	}
	u, err := url.Parse(review.URI)
	if err != nil {
		t.Fatal(err)
	}
	grant := strings.TrimPrefix(u.Path, "/approvals/")
	if len(grant) != 36 || grant == u.Path {
		t.Fatal("Stop profile review identity")
	}
	approve(grant)
	var receipt struct {
		CaptureID string `json:"capture_id"`
	}
	submit := func(input map[string]any) string {
		reply, code := invoke("request_capture", input)
		if code == "" && json.Unmarshal(reply.Data, &receipt) != nil {
			t.Fatal("Stop profile receipt")
		}
		return code
	}
	initial := submit(original)
	for retry := 0; initial == "StorageRefreshing" && retry < 5; retry++ {
		if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		initial = submit(original)
	}
	continuation := map[string]any{"preview_id": preview.ID, "idempotency_key": original["idempotency_key"], "continue_acquisition": true}
	resolve := func() (installedJourneyDisposition, error) {
		var d installedJourneyDisposition
		read("resolve_capture_request", resolution, &d)
		if d.State == "accepted" {
			receipt.CaptureID = d.CaptureID
		}
		return d, nil
	}
	closed, err := installedJourneyRecoverCapture(ctx, initial, resolve, func() (string, string) { code := submit(continuation); return code, receipt.CaptureID }, func() error {
		d, err := resolve()
		if err != nil || d.State != "accepted" || d.CaptureID != receipt.CaptureID {
			return errors.New("Stop profile original request not accepted")
		}
		return nil
	}, installedJourneyPause, func(id string) (installedJourneyCaptureProgress, error) {
		var p installedJourneyCaptureProgress
		read("get_capture", map[string]string{"capture_id": id}, &p)
		return p, nil
	})
	if err != nil || closed || receipt.CaptureID == "" {
		t.Fatal("Stop profile was not admitted", err, closed)
	}
	var current struct {
		CaptureID string `json:"capture_id"`
		Phase     string `json:"phase"`
		Revision  int64  `json:"revision"`
		CaseID    string `json:"case_id"`
	}
	end := time.Now().Add(time.Minute)
	for time.Now().Before(end) {
		read("get_capture", map[string]string{"capture_id": receipt.CaptureID}, &current)
		if current.CaptureID != receipt.CaptureID || current.Revision < 1 {
			t.Fatal("Stop profile progress identity", current)
		}
		if current.Phase == "Running" {
			break
		}
		if current.Phase == "Succeeded" || current.Phase == "Failed" || current.Phase == "Partial" || current.Phase == "Cancelled" || current.Phase == "Indeterminate" {
			t.Fatal("Stop profile ended before live Stop", current)
		}
		if err := installedJourneyPause(ctx, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if current.Phase != "Running" {
		t.Fatal("Stop profile never entered Running", current)
	}
	if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	read("get_capture", map[string]string{"capture_id": receipt.CaptureID}, &current)
	if current.Phase != "Running" {
		t.Fatal("Stop profile completed before cancellation", current)
	}
	var stopped struct {
		CaptureID string `json:"capture_id"`
		Requested bool   `json:"cancellation_requested"`
	}
	read("cancel_capture", map[string]any{"capture_id": receipt.CaptureID, "expected_revision": current.Revision, "idempotency_key": "stop-" + receipt.CaptureID}, &stopped)
	if stopped.CaptureID != receipt.CaptureID || !stopped.Requested {
		t.Fatal("live Stop was not accepted", stopped)
	}
	for time.Now().Before(end) {
		read("get_capture", map[string]string{"capture_id": receipt.CaptureID}, &current)
		if current.Phase == "Cancelled" {
			break
		}
		if err := installedJourneyPause(ctx, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if current.CaptureID != receipt.CaptureID || current.Phase != "Cancelled" {
		t.Fatal("Stop profile did not reach terminal cancellation", current)
	}
	if current.CaseID != "" {
		var evidence struct {
			Artifacts []json.RawMessage `json:"artifacts"`
		}
		read("get_case", map[string]string{"case_id": current.CaseID}, &evidence)
		if len(evidence.Artifacts) != 0 {
			t.Fatal("stopped profile published an artifact")
		}
	}
	t.Logf("manual profile %s: public Stop accepted while Running and terminal Cancelled observed; application profiler stop is not claimed", receipt.CaptureID)
}

func manualProfileArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components":    []any{map[string]any{"id": "cpu", "profileRef": map[string]string{"catalog": "builtin", "name": "go-cpu", "version": "v1"}}},
			"maxTotalBytes": 16 << 20, "maxDuration": "30s",
		},
	}
}

func qualifyManualProfileNative(t *testing.T, ctx context.Context, native []byte, captureID string) {
	t.Helper()
	p, err := profile.ParseData(native)
	if err != nil || p.CheckValid() != nil || len(p.Sample) == 0 || p.DurationNanos < 9_000_000_000 {
		t.Fatal("downloaded CPU profile has no valid ten-second sample interval", err)
	}
	path := "../results/manual-profile.pb.gz"
	if err := os.WriteFile(path, native, 0600); err != nil {
		t.Fatal(err)
	}
	// Disable symbol lookup: all names must come from the native artifact.
	out, err := exec.CommandContext(ctx, "go", "tool", "pprof", "-top", "-symbolize=none", path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "main.burnCPU") {
		t.Fatalf("native pprof cannot open the synthetic CPU sample: %v\n%s", err, out)
	}
	if err := os.WriteFile("../results/manual-profile-pprof.txt", out, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("manual profile %s: %d native bytes, %d samples, duration %dns; authenticated download hash matched; go tool pprof opened the original", captureID, len(native), len(p.Sample), p.DurationNanos)
}
