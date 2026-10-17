package mtls

import (
	"encoding/json"
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
