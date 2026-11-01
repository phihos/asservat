package capture

import (
	"bytes"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

func TestRecordingSaveHistoryRetainsPreferencesWithoutOldSourceAuthority(t *testing.T) {
	f := newInvestigationFixture()
	p := value.HistoryParameters{Format: value.HistoryParametersFormat, Target: targets.WorkloadRequest{ClusterID: f.target.Request.ClusterID, Namespace: f.target.Request.Namespace.Name, Kind: f.target.Request.Workload.Kind, Name: f.target.Request.Workload.Name}, NamespaceUID: f.target.Request.Namespace.UID, WorkloadUID: f.target.Request.Workload.UID, AuthoredTargetJSON: []byte(`{"namespace":"payments","workloadRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"api","uid":"deployment"},"maxPods":1,"selection":"allWithinLimit","adoption":"pinUID"}`), RequestedSeconds: 60, OriginalEffectiveSeconds: 60, OriginalExecutionDigest: artifact.Digest{1}, Selection: "recordingSelectionRequired", RecordingSave: &value.RecordingSaveSettings{PolicyUID: "policy", PolicyExecutionDigest: artifact.Digest{2}, Windows: []value.RecordingSavePreference{{ActionID: "packets", Before: 20 * time.Second}}}}
	p.SelectorIdentity = &value.HistorySelector{ClusterID: p.Target.ClusterID, NamespaceUID: p.NamespaceUID, WorkloadKind: p.Target.Kind, WorkloadUID: p.WorkloadUID}
	raw, err := value.CanonicalHistoryParameters(p)
	if err != nil {
		t.Fatal("typed recording settings", err)
	}
	parsed, err := value.ParseHistoryParameters(raw)
	if err != nil || parsed.RecordingSave == nil || parsed.RecordingSave.Windows[0].Before != 20*time.Second || parsed.Composition != nil || parsed.Diagnostic != "" {
		t.Fatal("typed settings became recipe", err)
	}
	for _, forbidden := range [][]byte{[]byte("SourceID"), []byte("SnapshotID"), []byte("SourceTarget"), []byte("BindingDigest"), []byte("IssuedAt"), []byte("Grant"), []byte("Sharing")} {
		if bytes.Contains(raw, forbidden) {
			t.Fatal("old source capability retained in repeat", string(forbidden))
		}
	}
	keys, err := auditapp.NewOperationMAC("input-v1", bytes.Repeat([]byte{1}, 32), "account-v1", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	selector, settings, err := HistoryParameterKeys(keys, f.svc.RootID, p)
	if err != nil {
		t.Fatal(err)
	}
	changed := p
	changed.RecordingSave = p.RecordingSave.Clone()
	changed.RecordingSave.Windows[0].Before = 10 * time.Second
	otherSelector, otherSettings, err := HistoryParameterKeys(keys, f.svc.RootID, changed)
	if err != nil || selector != otherSelector || settings == otherSettings {
		t.Fatal("manual lookback absent from protected settings identity", err)
	}
	p.RecipeJSON = []byte(`{"actions":[{"kind":"liveCore"}]}`)
	if p.Valid() {
		t.Fatal("manual repeat accepted broader policy recipe")
	}
}
