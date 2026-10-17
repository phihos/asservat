package presentation

import (
	"asservat.local/asservat/internal/application/evidence"
	"context"
	"testing"
	"time"
)

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
