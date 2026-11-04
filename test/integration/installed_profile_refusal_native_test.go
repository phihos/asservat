package integration

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
)

// These are two independently reviewed captures of the original Pod, before
// the separate Stop journey. Only this synthetic application's owner changes
// its profiler/endpoint. Production preview and acquisition get no control URL.
func qualifyManualProfileRefusals(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, pod, uid string, arguments map[string]any, read func(string, any, any), readContext func(context.Context, string, any, any), invoke func(string, any) (installedJourneyEnvelope, string), approve func(string), check func(string, string, string) time.Time) {
	t.Helper()
	if check == nil {
		t.Fatal("profile refusal evidence reader missing")
	}
	control := func(command string) profileWorkloadState {
		t.Helper()
		state, err := profileWorkloadControl(ctx, api, namespace, pod, uid, command)
		if err != nil {
			t.Fatal("exact original profile workload control", command, err)
		}
		return state
	}
	defer func() {
		// The fixture stop operation affects only the profiler it started. An
		// expired capture never authorizes the product to stop the application.
		cleanup, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		for _, command := range []string{"stop", "normal"} {
			if _, err := profileWorkloadControl(cleanup, api, namespace, pod, uid, command); err != nil {
				t.Error("original profile workload cleanup", command, err)
			}
		}
	}()
	for _, scenario := range []struct{ name, reason string }{{"busy", "ProfilerBusy"}, {"unavailable", "ProfileUnavailable"}} {
		control("normal")
		if scenario.name == "busy" {
			control("start")
		} else {
			control("missing")
		}
		before := control("state")
		busy := scenario.name == "busy"
		if before.OwnerRunning != busy || before.RuntimeBusy != busy {
			t.Fatal("fixture profiler does not match refusal scenario", scenario.name, before)
		}
		capture, grant := requestRefusedManualProfile(t, ctx, scenario.name, pod, uid, arguments, read, invoke, approve, func() {
			state := control("state")
			if state != before {
				t.Fatal("preview or approval probed/changed the application profiler", before, state)
			}
		})
		var progress installedJourneyCaptureProgress
		until := time.Now().Add(30 * time.Second)
		pollContext, cancelPoll := context.WithDeadline(ctx, until)
		defer cancelPoll()
		for {
			readContext(pollContext, "get_capture", map[string]string{"capture_id": capture}, &progress)
			if progress.CaptureID != capture {
				t.Fatal("profile refusal progress replaced capture identity")
			}
			if progress.Phase == "Failed" {
				break
			}
			if progress.Phase != "Pending" && progress.Phase != "Running" || time.Now().After(until) {
				t.Fatal("profile refusal did not reach expected terminal failure", scenario.reason, progress)
			}
			if err := installedJourneyPause(pollContext, time.Second); err != nil {
				t.Fatal(err)
			}
		}
		cancelPoll()
		if progress.CaseID != "" || len(progress.Actions) != 1 || progress.Actions[0].Phase != "Failed" || progress.Actions[0].ReasonCode != scenario.reason {
			t.Fatal("profile refusal lost its exact public reason or exposed a result", scenario.reason, progress)
		}
		cutoff := check(capture, grant, scenario.reason)
		// HTTP refusal does not prove a remote profiler never started. The
		// node retains its original runtime slot until this persisted cutoff;
		// a new capture must not mistake that quarantine for endpoint busy.
		if cutoff.IsZero() {
			t.Fatal("original profile refusal runtime cutoff missing")
		}
		if remaining := time.Until(cutoff); remaining > 0 {
			if err := installedJourneyPause(ctx, remaining); err != nil {
				t.Fatal(err)
			}
		}
		after := control("state")
		if after.ProfileRequests != before.ProfileRequests+1 || after.OwnerRunning != busy || after.RuntimeBusy != busy {
			t.Fatal("profile refusal retried or interrupted the application-owned profiler", before, after)
		}
		var replay installedJourneyCaptureProgress
		read("get_capture", map[string]string{"capture_id": capture}, &replay)
		if replay.CaptureID != capture || replay.Phase != "Failed" || replay.CaseID != "" || len(replay.Actions) != 1 || replay.Actions[0] != progress.Actions[0] {
			t.Fatal("terminal refusal changed on passive progress replay", replay)
		}
		if control("state") != after {
			t.Fatal("terminal refusal replay started another HTTP request")
		}
		control("stop")
		control("normal")
		t.Logf("installed manual profile %s: capture=%s, exact public Failed/%s; one HTTP attempt, no artifact/retry; original application-owned profiler preserved=%t; admission/control debit retained", scenario.name, capture, scenario.reason, busy)
	}
}

// A refusal is an expected terminal outcome of an accepted request. Resolve an
// uncertain reply under the original identity; continue only a still-Pending
// accepted request. Never continue a Running or terminal failed acquisition.
func requestRefusedManualProfile(t *testing.T, ctx context.Context, name, pod, uid string, arguments map[string]any, read func(string, any, any), invoke func(string, any) (installedJourneyEnvelope, string), approve func(string), beforeSubmit func()) (string, string) {
	t.Helper()
	var preview installedApprovedRecordingPreview
	read("preview_capture", arguments, &preview)
	if !preview.readyForApproval(time.Now()) || len(preview.Lifecycle.Actions) != 1 || preview.Pods[0].Name != pod || preview.Pods[0].UID != uid {
		t.Fatal("profile refusal preview changed the original reviewed Pod", preview.Blockers)
	}
	original, resolution := manualRecorderStopRequests(preview, time.Now(), "profile-refusal-"+name)
	reply, code := invoke("request_capture", original)
	var review struct {
		URI string `json:"navigation_uri"`
	}
	if code != "ApprovalRequired" || json.Unmarshal(reply.Data, &review) != nil {
		t.Fatal("profile refusal bypassed independent collection approval", code)
	}
	location, err := url.Parse(review.URI)
	if err != nil || !strings.HasPrefix(location.Path, "/approvals/") {
		t.Fatal("profile refusal approval identity unavailable")
	}
	grant := strings.TrimPrefix(location.Path, "/approvals/")
	if len(grant) != 36 {
		t.Fatal("profile refusal grant identity invalid")
	}
	approve(grant)
	beforeSubmit()
	var receipt struct {
		CaptureID string `json:"capture_id"`
	}
	submit := func(input map[string]any) string {
		response, result := invoke("request_capture", input)
		if result == "" && (json.Unmarshal(response.Data, &receipt) != nil || receipt.CaptureID == "") {
			t.Fatal("profile refusal request receipt invalid")
		}
		return result
	}
	code = submit(original)
	for attempt := 0; code == "StorageRefreshing" && attempt < 5; attempt++ {
		if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		code = submit(original)
	}
	for continued := 0; ; continued++ {
		if code != "" && code != "OutcomeUnknown" && code != "AcquisitionNotStarted" {
			t.Fatal("profile refusal admission failed before endpoint acquisition", code)
		}
		var disposition installedJourneyDisposition
		read("resolve_capture_request", resolution, &disposition)
		if disposition.State != "accepted" || disposition.CaptureID == "" || receipt.CaptureID != "" && receipt.CaptureID != disposition.CaptureID {
			t.Fatal("profile refusal original admission was not acknowledged", disposition.State)
		}
		receipt.CaptureID = disposition.CaptureID
		if code == "" {
			return receipt.CaptureID, grant
		}
		var progress installedJourneyCaptureProgress
		read("get_capture", map[string]string{"capture_id": receipt.CaptureID}, &progress)
		if progress.CaptureID != receipt.CaptureID {
			t.Fatal("profile refusal recovery changed accepted identity")
		}
		if progress.Phase == "Running" || progress.Phase == "Failed" {
			return receipt.CaptureID, grant
		}
		if progress.Phase != "Pending" || continued == 4 {
			t.Fatal("profile refusal original request cannot continue", progress.Phase)
		}
		if err := installedJourneyPause(ctx, 2*time.Second); err != nil {
			t.Fatal(err)
		}
		code = submit(map[string]any{"preview_id": preview.ID, "idempotency_key": original["idempotency_key"], "continue_acquisition": true})
	}
}
