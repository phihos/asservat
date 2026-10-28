package integration

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// Invalid request wiring should fail before spending an installed collector run.
// Contract validation grants no capture authority and runs no collector.
func TestInstalledApprovedRecordingPublicInput(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	input := approvedRecordingArguments("00000000-0000-4000-8000-000000000001", "payments", "api")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateInput("preview_capture", raw); err != nil {
		t.Fatal("actual approved recording preview input", err)
	}
}

// Both the harness and bootstrap consumer must agree on the owned fixture:
// one hub plus one workload cluster for this fast focus. The real service
// assertion stays strict; this test catches shape drift without starting Kind.
func TestInstalledApprovedRecordingFixtureShape(t *testing.T) {
	for _, tc := range []struct {
		focus    string
		clusters int
		fast     bool
	}{
		{"approved-recording", 2, true}, {"policy-recording", 2, true}, {"native-paced", 2, true}, {"journey", 2, true}, {"browser", 2, true},
		{"policy", 2, true}, {"alert", 2, true}, {"logresource", 2, true},
		{"restart", 2, true}, {"upgrade", 2, true}, {"share", 2, true},
		{"chain", 2, false}, {"clusters", 3, true}, {"", 3, false}, {"unknown", 3, false},
	} {
		t.Run(tc.focus, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", tc.focus)
			if got := installedClusterCount(); got != tc.clusters {
				t.Fatalf("owned fixture clusters=%d; want %d", got, tc.clusters)
			}
			if got := installedFastFixture(); got != tc.fast {
				t.Fatalf("fast feature fixture=%v; want %v", got, tc.fast)
			}
			wantRecording := tc.focus == "approved-recording" || tc.focus == "native-paced" || tc.focus == "policy-recording"
			if got := installedRecordingFocus(); got != wantRecording {
				t.Fatalf("recording focus parent-return guard=%v; want %v", got, wantRecording)
			}
			if (tc.focus == "approved-recording" || tc.focus == "native-paced") && (installedRegionalInstallerChecks(1) || !installedRegionalInstallerChecks(2)) {
				t.Fatal("approved focus changed regional feature/chain coverage")
			}
		})
	}
}

// The collector stage must never apply the chart's installation-intent
// ConfigMap into an invented release namespace or mutate connector staging.
// This checks the exact runtime command builder without requiring Helm/Kind.
func TestInstalledApprovedRecordingCollectorRenderStage(t *testing.T) {
	for _, namespace := range []string{"asservat-connector", "connector-selected-by-the-installer"} {
		args := approvedRecordingCollectorRenderArgs(namespace, "operator-values.json")
		value := func(flag string) string {
			for i := range args {
				if args[i] == flag && i+1 < len(args) {
					return args[i+1]
				}
			}
			return ""
		}
		if value("--show-only") != "templates/collector.yaml" {
			t.Fatal("collector stage includes unrelated foundation resources")
		}
		if value("--namespace") != namespace {
			t.Fatal("render namespace does not match the actual regional installation")
		}
		if value("-f") != "operator-values.json" {
			t.Fatal("render lost its exact installed endpoint/image values")
		}
	}
}

func TestInstalledApprovedRecordingRejectsPlanOnlyBeforeApproval(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, blockers string
		want           bool
	}{
		{"approval-only", `[{"code":"ApprovalRequired"}]`, true},
		{"plan-only", `[{"code":"ApprovalRequired"},{"code":"RecorderUnavailable"}]`, false},
		{"collection-disabled", `[{"code":"ApprovalRequired"},{"code":"CollectionDisabled"}]`, false},
		{"missing-blocker", `[]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"preview_id":"00000000-0000-4000-8000-000000000001","expires_at":"` + now.Add(time.Minute).Format(time.RFC3339Nano) + `","approval_required":true,"capture_enabled":false,"selected_pods":[{"uid":"exact-pod","name":"api-a"}],"blockers":` + tc.blockers + `}`
			var p installedApprovedRecordingPreview
			if json.Unmarshal([]byte(raw), &p) != nil || p.readyForApproval(now) != tc.want {
				t.Fatal("unrecordable preview passed the initial approval guard", tc.name)
			}
		})
	}
}

func TestInstalledApprovedRecordingRetriesOnlyTypedTransientReads(t *testing.T) {
	for _, tc := range []struct {
		code        string
		retry, want bool
	}{
		{"NotAvailable", true, true}, {"NotAvailable", false, false}, {"RecorderUnavailable", false, false}, {"ReviewChanged", false, false}, {"CapacityUnavailable", true, false}, {"ApprovalRequired", false, false},
	} {
		t.Run(tc.code+fmt.Sprint(tc.retry), func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"code": tc.code, "retryable": tc.retry})
			reply := installedJourneyEnvelope{Status: "error", Data: raw}
			if installedApprovedRecordingCanRetry(reply, tc.code) != tc.want {
				t.Fatal("unexpected read retry", tc.code)
			}
		})
	}
}
