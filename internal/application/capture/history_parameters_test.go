package capture

import (
	"bytes"
	"encoding/json"
	"testing"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func TestHistoryKeysSeparateAuthoredSettingsFromExecutionFacts(t *testing.T) {
	k, e := auditapp.NewOperationMAC("input-v1", bytes.Repeat([]byte{1}, 32), "account-v1", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer k.Close()
	root := "10000000-0000-4000-8000-000000000001"
	p := value.HistoryParameters{Format: value.HistoryParametersFormat, Target: targets.WorkloadRequest{ClusterID: root, Namespace: "payments", Kind: "Deployment", Name: "api"}, NamespaceUID: "namespace", WorkloadUID: "workload", RecipeJSON: json.RawMessage(`{"actions":[]}`), DependencyJSON: json.RawMessage(`[]`), RequestedSeconds: 120, OriginalEffectiveSeconds: 60, OriginalExecutionDigest: artifact.Digest{1}, Composition: &planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "network", Profile: planning.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, Edits: []planning.ProfileEdit{{ActionID: "packets", Field: "packetFilter", Text: "tcp port 443"}}}}, MaxTotalBytes: 8 << 20, MaxDuration: "10s"}}
	s, a, e := HistoryParameterKeys(k, root, p)
	if e != nil {
		t.Fatal(e)
	}
	p.OriginalExecutionDigest = artifact.Digest{2}
	p.OriginalEffectiveSeconds = 30
	s2, a2, e := HistoryParameterKeys(k, root, p)
	if e != nil || s != s2 || a != a2 {
		t.Fatal("execution facts regrouped authored settings", e)
	}
	p.Composition = p.Composition.Clone()
	p.Composition.Components[0].Edits[0].Text = "tcp port 80"
	s2, a2, e = HistoryParameterKeys(k, root, p)
	if e != nil || s != s2 || a == a2 {
		t.Fatal("filter change not separated under same selector", e)
	}
	p.WorkloadUID = "recreated"
	s2, _, e = HistoryParameterKeys(k, root, p)
	if e != nil || s == s2 {
		t.Fatal("recreated workload inherited selector", e)
	}
	// Ordinary audit-input key rotation leaves stable history identity intact.
	rotated, e := auditapp.NewOperationMAC("input-v2", bytes.Repeat([]byte{3}, 32), "account-v1", bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer rotated.Close()
	a3, e := rotated.HistoryDigest("settings", []byte("same"))
	a4, e4 := k.HistoryDigest("settings", []byte("same"))
	if e != nil || e4 != nil || a3 != a4 {
		t.Fatal("input-key rotation reset history keys")
	}
	if v, e := k.HistoryDigest("selector", []byte("same")); e != nil || v == a4 {
		t.Fatal("MAC domains overlap")
	}
}
