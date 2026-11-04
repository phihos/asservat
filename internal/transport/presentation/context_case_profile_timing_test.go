package presentation

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProfileAcquisitionCaseClosedContract(t *testing.T) {
	s, _, current := caseOperationsFixture(t)
	reply, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(reply.Body, &out) != nil {
		t.Fatal("case output")
	}
	row := out["data"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)
	row["kind"], row["data_class"], row["native_format"] = "profile", "raw", "pprof"
	acquisition := map[string]any{
		"requested_type": "cpu", "mode": "interval", "requested_duration_ms": float64(10000), "force_gc": false,
		"execution_mode": "onTrigger", "started_at": "2026-11-04T08:30:00.123456Z", "completed_at": "2026-11-04T08:30:10.654321Z",
		"clock_uncertainty_ms": nil, "process_attribution": "unknown", "window_kind": "httpAcquisition", "timestamp_precision": "microsecond",
	}
	row["profile_acquisition"] = acquisition
	validate := func() error {
		b, e := json.Marshal(out)
		if e != nil {
			t.Fatal(e)
		}
		if err := s.contracts.ValidateOutput("get_case", b); err != nil {
			return err
		}
		return s.contracts.ValidateBrowserOutput("get_case", b)
	}
	if err := validate(); err != nil {
		t.Fatal("verified profile acquisition metadata rejected", err)
	}
	for _, field := range []string{"started_at", "completed_at", "clock_uncertainty_ms", "process_attribution", "execution_mode", "requested_duration_ms"} {
		saved := acquisition[field]
		delete(acquisition, field)
		if validate() == nil {
			t.Fatal("missing required field accepted", field)
		}
		acquisition[field] = saved
	}
	for _, edit := range []struct {
		field string
		value any
	}{
		{"source_ref", "private-source"}, {"composition", map[string]any{}}, {"endpoint_digest", "private-digest"},
		{"clock_uncertainty_ms", float64(0)}, {"process_attribution", "sameProcess"}, {"execution_mode", "ongoing"},
		{"started_at", nil}, {"completed_at", nil}, {"requested_duration_ms", nil}, {"requested_duration_ms", float64(0)},
		{"force_gc", true}, {"mode", "cumulative"}, {"requested_type", "unknown"},
	} {
		saved, present := acquisition[edit.field]
		acquisition[edit.field] = edit.value
		if validate() == nil {
			t.Fatal("invalid acquisition accepted", edit.field, edit.value)
		}
		if present {
			acquisition[edit.field] = saved
		} else {
			delete(acquisition, edit.field)
		}
	}
	acquisition["requested_type"], acquisition["mode"], acquisition["requested_duration_ms"] = "allocs", "cumulative", nil
	acquisition["started_at"], acquisition["completed_at"] = nil, nil
	if err := validate(); err != nil {
		t.Fatal("legacy unknown or absent requested interval rejected", err)
	}
	acquisition["requested_type"], acquisition["mode"], acquisition["force_gc"] = "heap", "snapshot", true
	if err := validate(); err != nil {
		t.Fatal("forced-GC heap snapshot rejected", err)
	}
}

func TestProfileAcquisitionCasePresenterPreservesRequestedAndVerifiedFacts(t *testing.T) {
	for _, which := range []string{"interval", "snapshot", "legacy-cumulative", "no-profile-metadata"} {
		t.Run(which, func(t *testing.T) {
			s, f, current := caseOperationsFixture(t)
			a := &f.view.Artifacts[0]
			a.EvidenceType, a.DataClass, a.NativeType = "profile", "raw", artifact.PprofArtifact
			start := time.Date(2026, 11, 4, 8, 30, 0, 123456000, time.UTC)
			end := start.Add(10*time.Second + 222*time.Millisecond)
			p := &artifact.ProfileAcquisitionMetadata{Type: "cpu", Mode: "interval", DurationMillis: 10000, Acquisition: &artifact.AcquisitionWindow{StartedAt: start, CompletedAt: end}}
			switch which {
			case "snapshot":
				p.Type, p.Mode, p.DurationMillis, p.ForceGC = "heap", "snapshot", 0, true
			case "legacy-cumulative":
				p.Type, p.Mode, p.DurationMillis, p.Acquisition = "allocs", "cumulative", 0, nil
			case "no-profile-metadata":
				p = nil
			}
			a.ProfileAcquisition = p
			reply, err := s.Call(t.Context(), current, "get_case", []byte(caseInput))
			if err != nil {
				t.Fatal(err)
			}
			var out struct {
				Data struct {
					Artifacts []map[string]json.RawMessage
					Timeline  []any
				}
			}
			if json.Unmarshal(reply.Body, &out) != nil {
				t.Fatal("invalid case output")
			}
			raw, present := out.Data.Artifacts[0]["profile_acquisition"]
			if present != (p != nil) || len(out.Data.Timeline) != 0 {
				t.Fatal("legacy shape/timeline changed", string(reply.Body))
			}
			if !present {
				return
			}
			var got map[string]any
			if json.Unmarshal(raw, &got) != nil || len(got) != 11 || got["requested_type"] != p.Type || got["mode"] != p.Mode || got["force_gc"] != p.ForceGC || got["execution_mode"] != "onTrigger" || got["window_kind"] != "httpAcquisition" || got["timestamp_precision"] != "microsecond" || got["clock_uncertainty_ms"] != nil || got["process_attribution"] != "unknown" {
				t.Fatal("public facts changed", string(raw))
			}
			if p.DurationMillis == 0 {
				if got["requested_duration_ms"] != nil {
					t.Fatal("snapshot/cumulative interval invented")
				}
			} else if got["requested_duration_ms"] != float64(10000) {
				t.Fatal("requested duration lost")
			}
			if p.Acquisition == nil {
				if got["started_at"] != nil || got["completed_at"] != nil {
					t.Fatal("legacy time invented")
				}
			} else if got["started_at"] != start.Format(time.RFC3339Nano) || got["completed_at"] != end.Format(time.RFC3339Nano) {
				t.Fatal("verified microsecond window changed", got)
			}
			for _, forbidden := range []string{"composition", "source_ref", "endpoint_digest", "TriggeredAt", "1970-01-01"} {
				if strings.Contains(string(reply.Body), forbidden) {
					t.Fatal("private or invented fact", forbidden)
				}
			}
		})
	}
}
