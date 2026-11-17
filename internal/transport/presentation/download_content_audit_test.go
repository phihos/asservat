package presentation

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
)

func TestNativeContentAuditWritesOneRowAndNeverClaimsBodyCompletion(t *testing.T) {
	shared, identity, gate := auditedFixture(t)
	now := shared.config.Now()
	input := NativeContentInput{DownloadID: "00000000-0000-4000-8000-000000000090", IfMatch: []string{`"etag"`}}
	auditor, e := NewNativeContentAuditor(shared, input, now.Add(time.Second))
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
	if len(gate.events) != 0 {
		t.Fatal("row written before the content result")
	}
	if _, e = h.Finish(context.Background(), evidence.DownloadContentNotModified); e != nil {
		t.Fatal(e)
	}
	if len(gate.events) != 1 {
		t.Fatal("missing content row")
	}
	row := gate.events[0]
	if row.Kind != "call" || row.Operation != "download_artifact_content" || row.Status != "success" || row.OutputBytes != 0 || row.InputDigest == nil || row.OutputDigest == nil || !row.Valid() {
		t.Fatal("content row misreported or claimed body completion", row)
	}
	if _, e = h.Finish(context.Background(), evidence.DownloadContentReady); e == nil || len(gate.events) != 1 {
		t.Fatal("repeated outcome")
	}
	if _, ok := shared.Tool("download_artifact_content"); ok {
		t.Fatal("HTTP content advertised as tool")
	}
	if _, e = NewNativeContentAuditor(shared, input, now.Add(time.Minute)); e == nil {
		t.Fatal("content audit bound beyond five seconds accepted")
	}
}
