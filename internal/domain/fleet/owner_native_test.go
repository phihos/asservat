package fleet_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/domain/fleet"
)

// Persisted registration/configuration JSON predates NativePort. Its absent
// representation is immutable; adding a zero field must not change old hashes.
func TestOwnerPoolNativePortPreservesHistoricalEncoding(t *testing.T) {
	const old = `{"InstallationID":"11111111-1111-4111-8111-111111111111","ClusterID":"11111111-1111-4111-8111-111111111111","IssuerEpoch":"11111111-1111-4111-8111-111111111111","Namespace":"hub","NamespaceUID":"11111111-1111-4111-8111-111111111111","Service":"owner","ServiceUID":"11111111-1111-4111-8111-111111111111","Deployment":"owner","DeploymentUID":"11111111-1111-4111-8111-111111111111","ServiceAccount":"owner","AccountUID":"11111111-1111-4111-8111-111111111111","Port":9443}`
	var pool fleet.OwnerPool
	if json.Unmarshal([]byte(old), &pool) != nil || !pool.Valid() {
		t.Fatal("historical pool rejected")
	}
	b, err := json.Marshal(pool)
	if err != nil || string(b) != old {
		t.Fatal("historical accepted encoding changed", string(b), err)
	}
	for _, port := range []int{-1, 1, 1023, 9443, 65536} {
		pool.NativePort = port
		if pool.Valid() {
			t.Fatal("invalid or enrollment-overlapping native port", port)
		}
	}
	pool.NativePort = 9444
	if !pool.Valid() {
		t.Fatal("separate native port rejected")
	}
	b, err = json.Marshal(pool)
	if err != nil || bytes.Equal(b, []byte(old)) || !bytes.Contains(b, []byte(`"NativePort":9444`)) {
		t.Fatal("native port is not bound to configuration bytes")
	}
}
