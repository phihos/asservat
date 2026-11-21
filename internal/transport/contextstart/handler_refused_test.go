package contextstart

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

type refusingIngress struct{}

func (refusingIngress) AuthenticateContextStart(context.Context, contracts.APIContextHello, fleet.ConnectorCluster, time.Time) (fleet.APIContextReceiver, ReceiverCheck, error) {
	return fleet.APIContextReceiver{}, nil, fleet.ErrDenied
}

// testTokens accepts the token "connector-token" for the test cluster.
type testTokens struct{}

func (testTokens) VerifyConnectorUntil(_ context.Context, token string) (fleet.ConnectorCluster, time.Time, error) {
	if token != "connector-token" {
		return fleet.ConnectorCluster{}, time.Time{}, fleet.ErrDenied
	}
	return fleet.ConnectorCluster{}, time.Now().Add(time.Hour), nil
}

func TestNilHandlerReturnsUnavailable(t *testing.T) {
	var h *Handler
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, contracts.APIContextStartPath, nil))
	if w.Code != http.StatusNotFound || w.Header().Get("Cache-Control") != "no-store" || w.Body.String() != "Unavailable\n" {
		t.Fatalf("code=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
	}
}

func TestHandlerReportsRefusalStage(t *testing.T) {
	router, e := NewRouter(nil)
	if e != nil {
		t.Fatal(e)
	}
	h, e := NewHandler("hub.example:9444", router, refusingIngress{}, testTokens{}, 1)
	if e != nil {
		t.Fatal(e)
	}
	var stages []string
	h.Refused = func(s string) { stages = append(stages, s) }
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, contracts.APIContextStartPath, nil))
	if w.Code != http.StatusNotFound || len(stages) != 1 || stages[0] != "request" {
		t.Fatalf("code=%d stages=%v", w.Code, stages)
	}
}
