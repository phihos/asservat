package contextstart

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

type refusingIngress struct{}

func (refusingIngress) AuthenticateContextStart(context.Context, *tls.ConnectionState, contracts.APIContextHello, app.ConnectorIdentitySourceReader) (fleet.APIContextReceiver, ReceiverCheck, error) {
	return fleet.APIContextReceiver{}, nil, fleet.ErrDenied
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
	router, e := NewRouter(RouterLimits{Standby: 1, Captures: 1})
	if e != nil {
		t.Fatal(e)
	}
	h, e := NewHandler("hub.example:9444", router, refusingIngress{}, 1)
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
