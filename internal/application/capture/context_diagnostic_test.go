package capture

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestDiagnosticCheckDoesNotCreatePreviewOrStartWork(t *testing.T) {
	f := newInvestigationFixture()
	ctx := context.Background()
	if _, err := f.svc.CheckDiagnostic(ctx, f.source(t, ctx), f.intent().Target); err != nil {
		t.Fatal(err)
	}
	if f.newIDs.Load() != 0 || len(f.previews) != 0 || f.admissions.Load() != 0 {
		t.Fatal("catalog discovery created work or consumed a draft")
	}
	f.cap.ExecutionClass = artifact.ContextAPIExecution
	if _, err := f.svc.CheckDiagnostic(ctx, f.source(t, ctx), f.intent().Target); err == nil {
		t.Fatal("unqualified target/collector class advertised")
	}
}

func TestContextAPIPreviewPreservesClassAtSubmission(t *testing.T) {
	f := newInvestigationFixture()
	f.target.ExecutionClass = artifact.ContextAPIExecution
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.cap.ExecutionClass = artifact.ContextAPIExecution
	p := f.preview(t)
	if p.ExecutionClass != artifact.ContextAPIExecution || p.Pin.NodeName != "" {
		t.Fatal("API preview fabricated a node")
	}
	if _, err := f.request(t, p, "api-key"); err != nil {
		t.Fatal(err)
	}
	// A replacement resolver cannot reinterpret this API review as node work.
	f2 := newInvestigationFixture()
	f2.target.ExecutionClass = artifact.ContextAPIExecution
	f2.target.NodeUID, f2.target.NodeBootID, f2.target.Pin.NodeName = "", "", ""
	f2.cap.ExecutionClass = artifact.ContextAPIExecution
	p2 := f2.preview(t)
	f2.target.ExecutionClass = artifact.ContextNodeExecution
	if _, err := f2.request(t, p2, "api-key"); err == nil {
		t.Fatal("changed execution class admitted")
	}
}
