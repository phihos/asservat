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

	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

type fleetService struct {
	requests []fleetapp.FleetBootstrapRequest
	err      error
}

func (s *fleetService) Issue(ctx context.Context, current identities.CurrentIdentity, r fleetapp.FleetBootstrapRequest) (value.BootstrapIntent, error) {
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return value.BootstrapIntent{}, err
	}
	s.requests = append(s.requests, r)
	if s.err != nil {
		return value.BootstrapIntent{}, s.err
	}
	now := time.Now().UTC()
	return value.BootstrapIntent{Issued: true, Credential: &value.BootstrapCredential{Version: 1, SecretDigest: artifact.Digest{9}},
		Slot: value.BootstrapSlot{ID: "00000000-0000-4000-8000-000000000031", Binding: value.PeerBinding{InstallationID: "00000000-0000-4000-8000-000000000032", ClusterID: "00000000-0000-4000-8000-000000000033", PeerID: "00000000-0000-4000-8000-000000000034", IssuerEpoch: "00000000-0000-4000-8000-000000000035", Role: value.ConnectorPeer}, DeliveryProfile: r.DeliveryProfile, NotBefore: now, NotAfter: now.Add(5 * time.Minute)}}, nil
}

// ADR-193 step 4: the route needs the session, CSRF and one Idempotency-Key,
// forwards only the three operator fields, maps a denial to 403 and never
// returns secret material.
func TestFleetBootstrapRoute(t *testing.T) {
	var handler *FleetHandler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	service := &fleetService{}
	var err error
	handler, err = NewFleetHandler(SessionHandler{Origin: server.URL, Sessions: &investigationSession{}}, service)
	if err != nil {
		t.Fatal(err)
	}
	send := func(body string, header func(*http.Request)) (int, string) {
		r, _ := http.NewRequest("POST", server.URL+FleetBootstrapPath, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", server.URL)
		r.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		r.Header.Set("Idempotency-Key", "operator-key-0123456789")
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: strings.Repeat("A", 43)})
		if header != nil {
			header(r)
		}
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		b, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(b)
	}
	body := `{"displayName":"eu cluster","region":"eu-test","deliveryProfile":"regional-installer"}`
	status, reply := send(body, nil)
	var out map[string]any
	if status != http.StatusCreated || json.Unmarshal([]byte(reply), &out) != nil || out["bootstrapID"] != "00000000-0000-4000-8000-000000000031" || strings.Contains(strings.ToLower(reply), "secret") || len(service.requests) != 1 || service.requests[0].IdempotencyKey != "operator-key-0123456789" {
		t.Fatal("issuance reply", status, reply)
	}
	for name, mutate := range map[string]func(*http.Request){
		"missing CSRF":   func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"missing key":    func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"two keys":       func(r *http.Request) { r.Header.Add("Idempotency-Key", "second") },
		"foreign origin": func(r *http.Request) { r.Header.Set("Origin", "https://attacker.invalid") },
		"text body":      func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
	} {
		if status, _ := send(body, mutate); status < 400 || status == http.StatusCreated {
			t.Fatal("request accepted without", name, status)
		}
	}
	if status, _ := send(`{"displayName":"x","region":"y","deliveryProfile":"z","clusterID":"chosen"}`, nil); status != http.StatusBadRequest {
		t.Fatal("client-chosen field accepted", status)
	}
	service.err = value.ErrDenied
	if status, _ := send(body, nil); status != http.StatusForbidden {
		t.Fatal("denial not mapped to 403", status)
	}
	service.err = value.ErrCapacity
	if status, _ := send(body, nil); status != http.StatusTooManyRequests {
		t.Fatal("ceiling not mapped to 429", status)
	}
	if len(service.requests) != 3 {
		t.Fatal("refused requests reached the service", len(service.requests))
	}
}
