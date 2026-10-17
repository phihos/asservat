package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicRuntimeWorkerOmissionPreservesOriginalInputBytes(t *testing.T) {
	const original = `{"format":"asservat-public-runtime-roles/v1","installationID":"10000000-0000-4000-8000-000000000001","initialClaimID":"10000000-0000-4000-8000-000000000002","clusterID":"10000000-0000-4000-8000-000000000003","ownerConfigurationUID":"10000000-0000-4000-8000-000000000004","namespace":{"name":"owners","uid":"10000000-0000-4000-8000-000000000005"},"layoutDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	input, err := DecodePublicRuntimeRoles(strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	if input.Worker != (PublicRuntimeWorkerBinding{}) {
		t.Fatal("omitted field acquired worker provenance")
	}
	encoded, err := json.Marshal(input)
	if err != nil || string(encoded) != original {
		t.Fatal("legacy input bytes changed", err)
	}
	input.Worker.Resources = WorkerObjectReference{Name: "original-resource-journal", UID: "10000000-0000-4000-8000-000000000006"}
	encoded, err = json.Marshal(input)
	if err != nil || !bytes.Contains(encoded, []byte(`"worker":`)) {
		t.Fatal("explicit worker provenance omitted")
	}
	decoded, err := DecodePublicRuntimeRoles(bytes.NewReader(encoded))
	if err != nil || decoded != input {
		t.Fatal("exact comparable worker input changed", err)
	}
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	fields["worker"].(map[string]any)["arbitraryAuthority"] = true
	encoded, _ = json.Marshal(fields)
	if _, err = DecodePublicRuntimeRoles(bytes.NewReader(encoded)); err == nil {
		t.Fatal("unknown nested worker field accepted")
	}
}
