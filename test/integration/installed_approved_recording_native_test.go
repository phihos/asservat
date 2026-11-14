package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// approvedRecordingArguments is the actual public request, validated offline
// before the expensive installed qualification. It is never authority.
func approvedRecordingArguments(cluster, namespace, workload string) map[string]any {
	if installedJourneyFocus() == "manual-arguments" {
		return manualArgumentsCaptureInput(cluster, namespace, workload, false)
	}
	if installedProfileFocus() {
		if installedRuntimeTraceVariant() {
			return manualRuntimeTraceArguments(cluster, namespace, workload)
		}
		if installedHeapProfileVariant() {
			return manualHeapProfileArguments(cluster, namespace, workload)
		}
		return manualProfileArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-raw" {
		// ADR-279: one finite raw packet recording from a namespace profile.
		return manualRawArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-http" {
		// ADR-282: one finite HTTP response-header recording from a namespace profile.
		return manualHTTPArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-peers" {
		// ADR-283: one finite packet-header recording limited to a Kubernetes peer.
		return manualPeersArguments(cluster, namespace, workload)
	}
	if installedJourneyFocus() == "manual-mixed" {
		// ADR-276: packet and syscall finite recordings of one Pod at once.
		return map[string]any{
			"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
			"requested_retention_seconds": 600,
			"profile_composition": map[string]any{
				"components": []any{
					map[string]any{
						"id":         "network",
						"profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"},
						"overrides": []any{
							map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
							map[string]any{"actionID": "sample", "field": "packetAfter", "value": "10s"},
							map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "20s"},
						},
					},
					map[string]any{
						"id":         "calls",
						"profileRef": map[string]string{"catalog": "builtin", "name": "syscall-activity", "version": "v1"},
						"overrides": []any{
							map[string]any{"actionID": "syscalls", "field": "actionExecutionMode", "value": "onTrigger"},
							map[string]any{"actionID": "syscalls", "field": "syscallBefore", "value": "0s"},
							map[string]any{"actionID": "syscalls", "field": "syscallAfter", "value": "10s"},
							map[string]any{"actionID": "syscalls", "field": "actionTimeout", "value": "20s"},
						},
					},
				},
				"maxTotalBytes": 32 << 20,
				"maxDuration":   "20s",
			},
		}
	}
	if installedJourneyFocus() == "manual-syscall" {
		// B3: one finite manual syscall metadata recording of 5 seconds.
		return map[string]any{
			"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
			"requested_retention_seconds": 600,
			"profile_composition": map[string]any{
				"components": []any{map[string]any{
					"id":         "calls",
					"profileRef": map[string]string{"catalog": "builtin", "name": "syscall-activity", "version": "v1"},
					"overrides": []any{
						map[string]any{"actionID": "syscalls", "field": "actionExecutionMode", "value": "onTrigger"},
						map[string]any{"actionID": "syscalls", "field": "syscallBefore", "value": "0s"},
						map[string]any{"actionID": "syscalls", "field": "syscallAfter", "value": "5s"},
						map[string]any{"actionID": "syscalls", "field": "actionTimeout", "value": "15s"},
					},
				}},
				"maxTotalBytes": 16 << 20,
				"maxDuration":   "15s",
			},
		}
	}
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "2s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "10s",
		},
	}
}

// installedNativeDownload prepares, awaits and reads one native artifact whose
// filename extension is one of extensions.
func installedNativeDownload(t *testing.T, ctx context.Context, transport http.RoundTripper, identity *installedIdentity, origin, artifactID, key string, invoke func(string, any) (installedJourneyEnvelope, string), read func(string, any, any), diagnose func(), extensions ...string) ([]byte, string) {
	t.Helper()
	var download installedJourneyDownload
	// As in the main flow: preparation is an effect, so only the server's
	// continuation flag permits another exact same-key prepare.
	prepare := func() {
		t.Helper()
		reply, code := invoke("prepare_artifact_download", map[string]string{"artifact_id": artifactID, "idempotency_key": key})
		if code != "" || reply.Status != "ok" || json.Unmarshal(reply.Data, &download) != nil {
			diagnose()
			t.Fatal("mixed download preparation failed", code)
		}
	}
	prepare()
	for until := time.Now().Add(3 * time.Minute); download.State == "Preparing" && time.Now().Before(until); {
		if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		if download.ContinuePreparation {
			prepare()
		} else {
			read("get_artifact_download", map[string]string{"download_id": download.DownloadID}, &download)
		}
	}
	if download.State != "Ready" || download.SizeBytes == nil {
		diagnose()
		t.Fatal("mixed download not ready", download.State)
	}
	response := installedJourneyContent(t, ctx, &http.Client{Transport: transport, Timeout: time.Minute}, strings.TrimSuffix(origin, "/")+download.ContentPath, identity.downloadToken(), nil)
	defer response.Body.Close()
	_, disposition, err := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	name := disposition["filename"]
	extension := filepath.Ext(name)
	native, readErr := io.ReadAll(io.LimitReader(response.Body, artifact.RecordingNativeLimit+1))
	digest := sha256.Sum256(native)
	if err != nil || readErr != nil || name != "artifact-"+artifactID+extension || !slices.Contains(extensions, extension) || response.StatusCode != http.StatusOK || int64(len(native)) != *download.SizeBytes || hex.EncodeToString(digest[:]) != download.SHA256 {
		t.Fatal("mixed native download does not match its metadata", name, err, readErr)
	}
	return native, extension
}
