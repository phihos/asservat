package kubernetes

import (
	"encoding/json"
	"strconv"
	"testing"

	"asservat.local/asservat/internal/contracts"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func syntheticHandoverConflict(group, resource, name string) []byte {
	raw, _ := json.Marshal(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Code: 409, Reason: meta.StatusReasonConflict, Message: "synthetic resourceVersion conflict", Details: &meta.StatusDetails{Group: group, Kind: resource, Name: name}})
	return raw
}

func setSyntheticHandoverRoot(t *testing.T, f *preparerFixture, p *InitialPreparer, root contracts.InitialPreparationRoot) {
	t.Helper()
	if !p.validActivation(root) {
		t.Fatal("invalid synthetic handover root")
	}
	raw, _ := json.Marshal(root)
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.objects[p.rootPath()]
	v["data"].(map[string]any)["root.json"] = string(raw)
	f.serial++
	v["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(f.serial)
}
