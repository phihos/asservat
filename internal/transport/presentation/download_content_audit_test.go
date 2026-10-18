package presentation

import (
	"context"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/audit"
)

type contentAuditProfiles struct{}

func (contentAuditProfiles) ReadCapacityAuditProfiles(context.Context) (value.AcceptedCapacityAuditProfiles, error) {
	return value.AcceptedCapacityAuditProfiles{}, auditapp.ErrUnavailable
}

// The installed hub-api's normal lane is the per-profile selection (ADR-190);
// journey runs 33 and 34 stopped at handler/downloads/content-auditor because
// only a single healthy auditor was accepted.
func TestNativeContentAuditorAcceptsTheSelectedNormalLane(t *testing.T) {
	shared, _, _ := auditedFixture(t)
	now := shared.config.Now()
	input := NativeContentInput{DownloadID: "00000000-0000-4000-8000-000000000091"}
	selected, err := auditapp.NewSelectedOperationAuditor("normal", contentAuditProfiles{}, func(context.Context, value.OperationLifecyclePolicy) (*auditapp.HealthyOperationAuditor, error) {
		return nil, auditapp.ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	shared.audit["normal"] = selected
	if _, err = NewNativeContentAuditor(shared, input, now.Add(time.Second)); err != nil {
		t.Fatal("selected normal lane refused", err)
	}
	shared.audit["normal"] = &auditapp.SelectedOperationAuditor{}
	if _, err = NewNativeContentAuditor(shared, input, now.Add(time.Second)); err == nil {
		t.Fatal("unconfigured selected lane accepted")
	}
}

func TestNativeContentAuditSharesCapacityAndNeverClaimsBodyCompletion(t *testing.T) {
	shared, identity, gate := auditedFixture(t)
	now := shared.config.Now()
	input := NativeContentInput{DownloadID: "00000000-0000-4000-8000-000000000090", IfMatch: []string{`"etag"`}}
	auditor, e := newNativeContentAuditor(shared, input, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	input.IfMatch[0] = "changed"
	request := evidence.DownloadResponseRequest{SessionID: input.DownloadID, HardUntil: now.Add(time.Hour)}
	h, e := auditor.BeginDownloadContent(context.Background(), identity, request)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	if _, e = auditor.BeginDownloadContent(context.Background(), identity, request); e == nil {
		t.Fatal("separate unbacked HTTP capacity")
	}
	if len(gate.intents) != 1 || gate.intents[0].Name != "download_artifact_content" || !gate.intents[0].WriteUntil.Equal(now.Add(time.Second)) || !gate.intents[0].Valid() {
		t.Fatal("unbounded/invalid preflight intent")
	}
	if _, e = h.Finish(context.Background(), evidence.DownloadContentNotModified); e != nil {
		t.Fatal(e)
	}
	if len(gate.outcomes) != 1 || gate.outcomes[0].Effect != "none" || gate.outcomes[0].OutputBytes != 0 || gate.outcomes[0].ClientReceipt != "unknown" || !gate.outcomes[0].Valid() {
		t.Fatal("preflight claimed body completion")
	}
	if _, e = h.Finish(context.Background(), evidence.DownloadContentReady); e == nil {
		t.Fatal("repeated outcome")
	}
	h.Close()
	h.Close()
	if len(shared.lanes["normal"]) != 0 || len(shared.active) != 0 {
		t.Fatal("audit admission not released")
	}
	if _, ok := shared.Tool("download_artifact_content"); ok {
		t.Fatal("HTTP content advertised as tool")
	}
	if _, e = NewNativeContentAuditor(shared, input, now.Add(time.Second)); e == nil {
		t.Fatal("legacy/synthetic gate accepted by production constructor")
	}
}
