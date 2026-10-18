package mtls

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"
)

func nativeControlFixture(t *testing.T) map[string]any {
	t.Helper()
	ca := newOwnerTestCA(t, time.Now())
	roots := [][]byte{ca.cert.Raw}
	return map[string]any{
		"format": "asservat-worker-control/v2", "installationID": ownerTestID, "clusterID": ownerOtherID,
		"endpoint": "https://enroll.invalid", "serverRoots": roots, "issuerRoots": roots,
		"native": map[string]any{
			"format": "asservat-context-native-startup/v1", "exchangeEndpoint": "https://exchange.invalid/internal/download-native/v1/worker", "exchangeServerRoots": roots,
			"objectStore": map[string]any{"id": ownerOtherID, "endpoint": "https://objects.invalid", "region": "synthetic", "bucket": "evidence", "serverRoots": roots, "credentialSecretName": "native-reader", "credentialSecretUID": ownerOtherID},
			"keyService":  map[string]any{"endpoint": "https://keys.invalid", "serverRoots": roots, "scope": map[string]any{"installationID": ownerTestID, "purpose": "artifact", "keyID": "evidence"}},
		},
	}
}

func TestNativeWorkerControlVersionAndBoundaries(t *testing.T) {
	for _, kind := range []string{"valid", "legacy-with-native", "v2-without-native", "v2-null-native", "unknown", "raw-key", "custom-path", "escaped-path", "query", "fragment", "userinfo", "insecure-exchange", "foreign-installation", "audit-key", "empty-store-id", "secret-replacement-unpinned", "secret-path", "bucket-path", "empty-roots", "duplicate-roots", "bad-certificate"} {
		t.Run(kind, func(t *testing.T) {
			wire := nativeControlFixture(t)
			native := wire["native"].(map[string]any)
			store := native["objectStore"].(map[string]any)
			key := native["keyService"].(map[string]any)
			switch kind {
			case "legacy-with-native":
				wire["format"] = "asservat-worker-control/v1"
			case "v2-without-native":
				delete(wire, "native")
			case "v2-null-native":
				wire["native"] = nil
			case "unknown":
				native["callback"] = "https://other.invalid"
			case "raw-key":
				key["privateKey"] = "not-allowed"
			case "custom-path":
				native["exchangeEndpoint"] = "https://exchange.invalid/chosen"
			case "escaped-path":
				native["exchangeEndpoint"] = "https://exchange.invalid/internal/download-native/v1/%77orker"
			case "query":
				native["exchangeEndpoint"] = native["exchangeEndpoint"].(string) + "?"
			case "fragment":
				native["exchangeEndpoint"] = native["exchangeEndpoint"].(string) + "#"
			case "userinfo":
				native["exchangeEndpoint"] = "https://secret@exchange.invalid/internal/download-native/v1/worker"
			case "insecure-exchange":
				native["exchangeEndpoint"] = "http://exchange.invalid/internal/download-native/v1/worker"
			case "foreign-installation":
				key["scope"].(map[string]any)["installationID"] = ownerOtherID
			case "audit-key":
				key["scope"].(map[string]any)["purpose"] = "audit"
			case "empty-store-id":
				store["id"] = ""
			case "secret-replacement-unpinned":
				delete(store, "credentialSecretUID")
			case "secret-path":
				store["credentialSecretName"] = "../other"
			case "bucket-path":
				store["bucket"] = "../other"
			case "empty-roots":
				key["serverRoots"] = [][]byte{}
			case "duplicate-roots":
				r := native["exchangeServerRoots"].([][]byte)
				native["exchangeServerRoots"] = append(r, r[0])
			case "bad-certificate":
				store["serverRoots"] = [][]byte{[]byte("not a certificate")}
			}
			raw, _ := json.Marshal(wire)
			_, err := ParseWorkerControl(raw)
			if kind == "valid" {
				if err != nil {
					t.Fatal("native worker has no supported startup contract", err)
				}
			} else if err == nil {
				t.Fatal("unsafe native startup accepted", kind)
			}
		})
	}
}

// ADR-204 decision 9: optional connectivity-only dial addresses for both
// endpoints; the verified names stay the endpoints' own.
func TestWorkerControlDialAddresses(t *testing.T) {
	for _, address := range []string{"owner.hub.svc:9443", "10.0.0.7:9443", "[fd00::7]:9443", "", "owner.hub.svc", "owner.hub.svc:0", "owner.hub.svc:65536", "owner.hub.svc:09443", "owner/hub:9443", "user@owner:9443", ":9443", "owner.hub.svc:9443 "} {
		for _, field := range []string{"address", "exchangeAddress"} {
			wire := nativeControlFixture(t)
			if field == "address" {
				wire["address"] = address
			} else {
				wire["native"].(map[string]any)["exchangeAddress"] = address
			}
			raw, _ := json.Marshal(wire)
			trust, err := ParseWorkerControl(raw)
			valid := address == "owner.hub.svc:9443" || address == "10.0.0.7:9443" || address == "[fd00::7]:9443"
			if valid != (err == nil) {
				t.Fatal("dial address", field, address, err)
			}
			if !valid {
				continue
			}
			if field == "address" && (trust.Address != address || trust.Endpoint != "https://enroll.invalid") || field == "exchangeAddress" && (trust.Native().Settings().ExchangeAddress != address || trust.Native().Settings().ExchangeEndpoint != "https://exchange.invalid/internal/download-native/v1/worker") {
				t.Fatal("dial address replaced a verified endpoint", field)
			}
		}
	}
	// Omitted addresses keep the original bytes and meaning.
	raw, _ := json.Marshal(nativeControlFixture(t))
	trust, err := ParseWorkerControl(raw)
	if err != nil || trust.Address != "" || trust.Native().Settings().ExchangeAddress != "" {
		t.Fatal("documents without dial addresses changed", err)
	}
}

func TestWorkerDialUsesAddressOnlyForTheEndpointAuthority(t *testing.T) {
	u, _ := workerEndpoint("https://fixed.synthetic.invalid:9443")
	var dialed []string
	dial := workerDial(u, "owner.hub.svc:9443", func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, network+" "+address)
		return nil, errors.New("synthetic dial")
	})
	for _, authority := range []string{"fixed.synthetic.invalid:9443", "other.synthetic.invalid:9443", "fixed.synthetic.invalid:443"} {
		_, _ = dial(context.Background(), "tcp", authority)
	}
	if len(dialed) != 1 || dialed[0] != "tcp owner.hub.svc:9443" {
		t.Fatal("address dialed for another authority", dialed)
	}
	if workerDial(u, "", nil) != nil {
		t.Fatal("empty address replaced the transport dialer")
	}
	defaultPort, _ := workerEndpoint("https://fixed.synthetic.invalid")
	dialed = nil
	_, _ = workerDial(defaultPort, "owner.hub.svc:9443", func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, errors.New("synthetic dial")
	})(context.Background(), "tcp", "fixed.synthetic.invalid:443")
	if len(dialed) != 1 {
		t.Fatal("default HTTPS authority not matched")
	}
}
