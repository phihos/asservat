package contextstart

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

type residenceWriter struct{ *httptest.ResponseRecorder }

func (residenceWriter) SetReadDeadline(time.Time) error  { return nil }
func (residenceWriter) SetWriteDeadline(time.Time) error { return nil }

type residenceIngress struct {
	calls int
	until time.Time
}

func (i *residenceIngress) AuthenticateContextStart(ctx context.Context, _ contracts.APIContextHello, _ fleet.ConnectorCluster, _ time.Time) (fleet.APIContextReceiver, ReceiverCheck, error) {
	i.calls++
	i.until, _ = ctx.Deadline()
	<-ctx.Done()
	return fleet.APIContextReceiver{}, nil, fleet.ErrDenied
}

func TestHandlerRefusesInvalidOriginalConversationEndBeforeIngress(t *testing.T) {
	for _, mode := range []string{"missing", "null", "malformed", "expired", "overlong"} {
		t.Run(mode, func(t *testing.T) {
			router, e := NewRouter(nil)
			if e != nil {
				t.Fatal(e)
			}
			defer router.Close()
			ingress := &residenceIngress{}
			h, e := NewHandler("hub.example:9444", router, ingress, testTokens{}, 1)
			if e != nil {
				t.Fatal(e)
			}
			stage := ""
			h.Refused = func(s string) { stage = s }
			hello := map[string]any{"format": contracts.APIContextExchangeFormat, "channel": map[string]any{}}
			switch mode {
			case "null":
				hello["standbyUntil"] = nil
			case "malformed":
				hello["standbyUntil"] = "bad"
			case "expired":
				hello["standbyUntil"] = time.Now().Add(-time.Second)
			case "overlong":
				hello["standbyUntil"] = time.Now().Add(31 * time.Second)
			}
			body, e := json.Marshal(hello)
			if e != nil {
				t.Fatal(e)
			}
			var framed bytes.Buffer
			if e = contracts.WriteAPIContextFrame(&framed, contracts.APIContextFrame{Kind: contracts.APIContextHelloFrame, Payload: body}); e != nil {
				t.Fatal(e)
			}
			// Malformed or expired availability is refused before the ingress.
			r := httptest.NewRequest(http.MethodPost, "https://hub.example:9444"+contracts.APIContextStartPath, &framed)
			r.ProtoMajor = 2
			r.ContentLength = -1
			r.RequestURI = contracts.APIContextStartPath
			r.URL.Scheme = ""
			r.URL.Host = ""
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "h2"}
			r.Header.Set("Content-Type", contracts.APIContextStartMedia)
			r.Header.Set("Accept", contracts.APIContextStartMedia)
			r.Header.Set("Authorization", "Bearer connector-token")
			w := residenceWriter{httptest.NewRecorder()}
			h.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound || stage != "hello" || ingress.calls != 0 {
				t.Fatal("invalid residence reached the ingress", w.Code, stage, ingress.calls)
			}
		})
	}
}
