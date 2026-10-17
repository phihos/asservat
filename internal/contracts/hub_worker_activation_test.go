package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHubWorkerActivationLegacyOmissionPreservesBytes(t *testing.T) {
	var original HubWorkerDeployment
	b, err := json.Marshal(original)
	if err != nil || bytes.Contains(b, []byte("activation")) {
		t.Fatal("legacy encoding acquired activation")
	}
	decoded, err := DecodeHubWorkerDeployment(bytes.NewReader(b))
	if err != nil || decoded.Activation != nil {
		t.Fatal("legacy input acquired installed activation")
	}
	again, _ := json.Marshal(decoded)
	if !bytes.Equal(b, again) {
		t.Fatal("legacy roundtrip changed")
	}
	original.Activation = &HubWorkerRuntimeActivation{WorkerLayout: HubWorkerInstalledLayout}
	b, _ = json.Marshal(original)
	bad := strings.Replace(string(b), `"workerLayout":`, `"unknown":true,"workerLayout":`, 1)
	if _, err = DecodeHubWorkerDeployment(strings.NewReader(bad)); err == nil {
		t.Fatal("unknown activation input accepted")
	}
}
