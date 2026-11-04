package browser

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/transport/presentation"
)

type browserProfileCaseFixture struct {
	browserCaseFixture
	profile *artifact.ProfileAcquisitionMetadata
}

func (f *browserProfileCaseFixture) GetContextCase(ctx context.Context, current identities.CurrentIdentity, id string) (catalog.ContextCase, error) {
	view, err := f.browserCaseFixture.GetContextCase(ctx, current, id)
	a := &view.Artifacts[0]
	a.EvidenceType, a.DataClass, a.NativeType = "profile", "raw", artifact.PprofArtifact
	a.ProfileAcquisition = f.profile
	return view, err
}

// Actual browser HTTP/session/presenter/closed-contract composition. The already
// authorized catalog result is synthetic; this is not native verification proof.
func TestProfileAcquisitionCaseBrowserHTTPPreservesVerifiedAndLegacyTiming(t *testing.T) {
	var handler *InvestigationHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	start := time.Date(2026, 11, 4, 8, 30, 0, 123456000, time.UTC)
	f := &browserProfileCaseFixture{profile: &artifact.ProfileAcquisitionMetadata{Type: "cpu", Mode: "interval", DurationMillis: 10000, Acquisition: &artifact.AcquisitionWindow{StartedAt: start, CompletedAt: start.Add(10 * time.Second)}}}
	ops, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, f)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewInvestigationHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{readOnly: true}}, ops, 4)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, known := range []bool{true, false} {
		if !known {
			f.profile.Type, f.profile.Mode, f.profile.DurationMillis, f.profile.Acquisition = "allocs", "cumulative", 0, nil
		}
		req, err := http.NewRequest("POST", server.URL+"/api/v1/operations/get_case", strings.NewReader(`{"case_id":"`+browserCaseID+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store, private" || wire.ValidateOutput("get_case", body) != nil || wire.ValidateBrowserOutput("get_case", body) != nil {
			t.Fatal("profile case HTTP/closed contract failed", response.StatusCode, readErr, string(body))
		}
		var out struct {
			Data struct {
				Artifacts []struct {
					Profile presentation.ProfileAcquisitionData `json:"profile_acquisition"`
				}
			}
		}
		if json.Unmarshal(body, &out) != nil || len(out.Data.Artifacts) != 1 {
			t.Fatal("profile case output")
		}
		got := out.Data.Artifacts[0].Profile
		if got.RequestedType != f.profile.Type || got.ExecutionMode != "onTrigger" || got.ProcessAttribution != "unknown" || got.ClockUncertaintyMillis != nil {
			t.Fatal("accepted facts changed", got)
		}
		if known {
			if got.StartedAt == nil || !got.StartedAt.Equal(start) || got.RequestedDurationMillis == nil || *got.RequestedDurationMillis != 10000 {
				t.Fatal("verified/requested timing lost", got)
			}
		} else if got.StartedAt != nil || got.CompletedAt != nil || got.RequestedDurationMillis != nil {
			t.Fatal("legacy time or cumulative interval invented", got)
		}
	}
	if f.calls != 2 {
		t.Fatal("extra case reads", f.calls)
	}
}
