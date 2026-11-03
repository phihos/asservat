package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
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

// This is a second, independently reviewed capture. Stop never mutates or
// deletes the successfully downloaded first profile, and no endpoint probe
// starts an unapproved sampler to discover whether the target is busy.
func qualifyManualProfileStop(t *testing.T, ctx context.Context, arguments map[string]any, read func(string, any, any), invoke func(string, any) (installedJourneyEnvelope, string), approve func(string)) {
	t.Helper()
	var preview installedApprovedRecordingPreview
	read("preview_capture", arguments, &preview)
	if !preview.readyForApproval(time.Now()) {
		t.Fatal("Stop profile lacks an approvable preview", preview.Blockers)
	}
	original := map[string]any{"preview_id": preview.ID, "idempotency_key": "profile-stop-" + preview.ID}
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
		read("resolve_capture_request", original, &d)
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
