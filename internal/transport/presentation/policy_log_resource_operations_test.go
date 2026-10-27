package presentation

import (
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-241: log and resource occurrences report their second as failed_at;
// the detector shows its match mode or condition but never the pattern, and
// the overlong suppression is a content-free count. The output schema
// accepts both.
func TestPolicyStatusReportsLogAndResourceDetectors(t *testing.T) {
	created := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, d := range []value.PolicyDetector{
		{Kind: "log", LogMatch: "regexp", LogJSON: true, WindowSeconds: 60},
		{Kind: "resource", Resource: &targets.ResourceCondition{Metric: "memoryLimitRatio", Operator: "gte", Threshold: 0.9, MaxAgeSeconds: 60}},
	} {
		f := &policyOperationsFixture{scopes: []string{"evidence:read"}}
		s, err := NewPolicyOperations("https://asservat.example.invalid", time.Now, func() string { return "88888888-8888-4888-8888-888888888888" }, f, f, f)
		if err != nil {
			t.Fatal(err)
		}
		f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: "99999999-9999-4999-8999-999999999999", Generation: 1, AcceptedGeneration: 1, IntentVersion: 1, AcceptedIntentVersion: 1, MaxExecutions: 10, NotAfter: time.Now().Add(time.Hour),
			Detector:     &d,
			Recent:       []value.PolicyOccurrenceStatus{{ID: "11111111-1111-4111-8111-111111111111", Outcome: "captured", CaptureID: "22222222-2222-4222-8222-222222222222", Detector: d.Kind, Restarts: created.Add(-time.Minute).Unix(), CreatedAt: created}},
			Suppressions: []value.PolicySuppression{{Reason: "overlong", Count: 4, FirstAt: created, LastAt: created}}}
		out := policyCall(t, s, f, "get_policy_status", `{"policy_name":"signals"}`)
		data, _ := out["data"].(map[string]any)
		detector, _ := data["detector"].(map[string]any)
		recent, _ := data["recent"].([]any)
		if out["status"] != "ok" || detector["kind"] != d.Kind || len(recent) != 1 {
			t.Fatal(d.Kind, "status", out)
		}
		if o := recent[0].(map[string]any); o["detector"] != d.Kind || o["failed_at"] != "2026-10-27T11:59:00Z" || o["restarts"] != nil {
			t.Fatal(d.Kind, "occurrence", o)
		}
		switch d.Kind {
		case "log":
			if detector["match"] != "regexp" || detector["json_field"] != true || detector["window_seconds"] != float64(60) || detector["metric"] != nil {
				t.Fatal("log detector", detector)
			}
		case "resource":
			if detector["metric"] != "memoryLimitRatio" || detector["operator"] != "gte" || detector["threshold"] != 0.9 || detector["sample_interval_seconds"] != float64(60) || detector["match"] != nil {
				t.Fatal("resource detector", detector)
			}
		}
	}
}

// A region without the metrics API refuses a resource policy's activation
// with a fixed reason naming metrics-server.
func TestPolicyActivationNamesMissingMetricsAPI(t *testing.T) {
	f := publicPolicyFailure(targets.ErrUnsupported)
	if f.Code != "DetectorUnavailable" || f.Retryable || !strings.Contains(f.Message, "metrics-server") {
		t.Fatal(f)
	}
}
