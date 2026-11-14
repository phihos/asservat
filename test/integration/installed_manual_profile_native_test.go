package integration

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// The named template is operator configuration; the request cannot supply a
// URL or select another container. Only the fixture's declared port matches.
func manualProfileEndpoints() []contracts.RegionalProfileEndpoint {
	return []contracts.RegionalProfileEndpoint{{Name: "go-pprof-loopback", Kind: "template", AddressModes: []string{"targetLoopback"}, LoopbackFamily: "ipv4", MinPort: 6060, MaxPort: 6060}}
}

// Exercise the installed history-read + target + recorder composition without
// starting another capture. Each operation gets one attempt, so retries cannot
// conceal the preview deadline failure this qualification is intended to detect.
func qualifyManualRecorderRepeatPreview(t *testing.T, captureID string, original installedApprovedRecordingPreview, invoke func(string, any) (installedJourneyEnvelope, string), diagnose func()) {
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
		reply, code := invoke(name, args)
		elapsed := time.Since(started) // Exclude the failure-only diagnostic reads.
		// Failure diagnostics may outlive the runner's remaining budget. Retain
		// this original reply before entering them, without retrying the call.
		t.Logf("manual recorder history %s: single attempt elapsed=%s status=%s code=%s", name, elapsed, reply.Status, code)
		if code != "" || reply.Status != "ok" || json.Unmarshal(reply.Data, out) != nil {
			// Keep the original single attempt and capture the owner's fixed
			// preview phase before the owned installed environment is removed.
			diagnose()
			t.Fatal("manual recorder history operation failed", name, reply.Status, code)
		}
	}
	var source settings
	read("get_capture_settings", map[string]string{"capture_id": captureID}, &source)
	var originalComposition map[string]any
	if json.Unmarshal(original.Composition, &originalComposition) != nil || len(originalComposition) != 3 || source.CaptureID != captureID || source.Digest == "" || source.ExecutionDigest != original.Digest || !time.Now().Before(source.ExpiresAt) || !reflect.DeepEqual(source.Settings["profile_composition"], originalComposition) {
		t.Fatal("stored recorder settings differ from the original reviewed composition")
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
	t.Logf("manual recorder %s: fresh repeat preview %s preserved original composition and source expiry %s; no repeat capture requested", captureID, repeated.ID, source.ExpiresAt.Format(time.RFC3339Nano))
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
	return manualRecorderStopRequests(preview, now, "profile")
}

func manualRecorderStopRequests(preview installedApprovedRecordingPreview, now time.Time, kind string) (map[string]any, map[string]any) {
	original := map[string]any{"preview_id": preview.ID, "idempotency_key": kind + "-stop-" + preview.ID}
	resolution := map[string]any{"preview_id": preview.ID, "idempotency_key": original["idempotency_key"]}
	// Raw collection currently requires a selected result-access instruction,
	// even when this separate capture is intended to be stopped before output.
	// Keep the original expiry and instruction unchanged across submission retries.
	if len(preview.Lifecycle.Actions) == 1 {
		original["result_access"] = map[string]any{"actionIds": []string{preview.Lifecycle.Actions[0].ActionID}, "operations": []string{"download_artifact"}, "clientIDs": []string{"mcp"}, "maxArtifacts": 1, "maxBytes": 64 << 20, "maxOperations": 100, "notAfter": now.Add(time.Hour).UTC().Format(time.RFC3339)}
	}
	return original, resolution
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
