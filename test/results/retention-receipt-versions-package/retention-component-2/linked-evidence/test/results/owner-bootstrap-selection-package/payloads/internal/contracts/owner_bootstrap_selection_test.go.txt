package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOwnerBootstrapSelectionCodecsStayClosedAndBounded(t *testing.T) {
	plan := OwnerBootstrapPlan{Format: OwnerBootstrapPlanFormat, PKIMount: "pki", Connections: 4, Concurrency: 2, Peers: []OwnerBootstrapPeerPlan{{ClusterID: "20000000-0000-4000-8000-000000000001", Roots: [][]byte{[]byte("public-test-DER-placeholder")}}}}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeOwnerBootstrapPlan(bytes.NewReader(raw)); err != nil {
		t.Fatal("closed public shape", err)
	}
	for _, field := range []string{`"permissionRootID":"caller-selected"`, `"token":"secret"`, `"privatePayloadDigest":"digest"`, `"processEpoch":"future"`} {
		bad := append([]byte(nil), raw[:len(raw)-1]...)
		bad = append(bad, ',')
		bad = append(bad, field...)
		bad = append(bad, '}')
		if _, err = DecodeOwnerBootstrapPlan(bytes.NewReader(bad)); err == nil {
			t.Fatal("unknown authority/private field accepted", field)
		}
	}
	if _, err = DecodeOwnerBootstrapPlan(strings.NewReader(strings.Repeat(" ", OwnerDeploymentMaxBytes+1) + string(raw))); err == nil {
		t.Fatal("aggregate byte limit bypassed")
	}
	// Neither optional journal omission nor its existing byte ceiling changes.
	empty, _ := json.Marshal(InitialRuntimeResourceState{})
	if bytes.Contains(empty, []byte("ownerBootstrap")) || InitialRuntimeResourcesMaxBytes != 32<<10 {
		t.Fatal("legacy journal contract changed")
	}
}
