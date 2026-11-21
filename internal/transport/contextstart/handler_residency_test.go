package contextstart

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
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
			r := framedHelloRequest(framed.Bytes())
			w := residenceWriter{httptest.NewRecorder()}
			h.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound || stage != "hello" || ingress.calls != 0 {
				t.Fatal("invalid residence reached the ingress", w.Code, stage, ingress.calls)
			}
		})
	}
}

func framedHelloRequest(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://hub.example:9444"+contracts.APIContextStartPath, bytes.NewReader(body))
	r.ProtoMajor = 2
	r.ContentLength = -1
	r.RequestURI = contracts.APIContextStartPath
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "h2"}
	r.Header.Set("Content-Type", contracts.APIContextStartMedia)
	r.Header.Set("Accept", contracts.APIContextStartMedia)
	r.Header.Set("Authorization", "Bearer connector-token")
	return r
}

type historyIngress struct{ receiver fleet.APIContextReceiver }

func (i historyIngress) AuthenticateContextStart(context.Context, contracts.APIContextHello, fleet.ConnectorCluster, time.Time) (fleet.APIContextReceiver, ReceiverCheck, error) {
	return i.receiver, func(context.Context) (fleet.APIContextReceiver, error) { return i.receiver, nil }, nil
}

type pausedHandshake struct {
	residenceWriter
	resume chan error
}

func (w pausedHandshake) FlushError() error { return <-w.resume }

func TestHistoryWaitsForInitializedHandlerStream(t *testing.T) {
	for _, handshake := range []string{"flushed", "failed", "caller expired"} {
		t.Run(handshake, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				work := workFixture().Work
				cluster := work.Channel.Connector.Binding.ClusterID
				router, _ := NewRouter([]ClusterLimit{{cluster, 1, 1}})
				defer router.Close()
				router.RequestExchange = func(context.Context, string) error { return nil }
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				result := make(chan error, 1)
				go func() {
					a, err := router.AttachHistory(ctx, cluster, work.CaptureID)
					if err == nil {
						defer a.Close()
						_, err = a.Receiver(ctx)
					}
					result <- err
				}()
				synctest.Wait()
				receiver := fleet.APIContextReceiver{Channel: work.Channel, Window: identity.Check(time.Now(), identity.Recheck)}
				h, err := NewHandler("hub.example:9444", router, historyIngress{receiver}, testTokens{}, 1)
				if err != nil {
					t.Fatal(err)
				}
				body := helloBody(t, contracts.APIContextHello{Format: contracts.APIContextExchangeFormat, Channel: contracts.APIContextChannel{RootID: work.Channel.RootID, ExchangeID: work.Channel.ExchangeID}, StandbyUntil: time.Now().Add(30 * time.Second), Protocol: contracts.ConnectorProtocolMajor, Capabilities: contracts.APIContextCapabilities()})
				r := framedHelloRequest(body)
				w := pausedHandshake{residenceWriter{httptest.NewRecorder()}, make(chan error, 1)}
				go h.ServeHTTP(w, r)
				synctest.Wait()
				if len(result) != 0 {
					t.Error("history observed a receiver before the handshake flush")
				}
				if handshake == "caller expired" {
					time.Sleep(5 * time.Second)
					if err := <-result; !errors.Is(err, fleet.ErrUnavailable) {
						t.Fatal("history caller did not observe its deadline", err)
					}
					w.resume <- nil
					synctest.Wait()
					router.mu.Lock()
					orphan := len(router.standby) != 0
					router.mu.Unlock()
					if orphan {
						t.Error("handshake kept a connector slot after its caller expired")
					}
					return
				}
				if handshake == "failed" {
					w.resume <- errors.New("connection lost")
				} else {
					w.resume <- nil
				}
				if err := <-result; (err != nil) != (handshake == "failed") {
					t.Fatal("history receiver", err)
				}
				if handshake == "failed" && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
					t.Fatal("failed handshake ended the wait before its deadline")
				}
			})
		})
	}
}
