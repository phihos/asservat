package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestProfileSummaryEligibilityNeverGrantsRawReads(t *testing.T) {
	i, p, e, now := fixture()
	e.DataClass, e.NativeType = "raw", artifact.PprofArtifact
	if !Evaluate(i, p, ReadProfileSummary, p.Target, &e, now).Eligible {
		t.Fatal("ordinary retained audience cannot read approved profile aggregate")
	}
	for _, op := range []Operation{ReadApproved, DownloadApproved, CollectContext, ApproveAction} {
		if Evaluate(i, p, op, p.Target, &e, now).Eligible {
			t.Fatal("profile summary admitted another operation", op)
		}
	}
	for _, kind := range []string{artifact.GoTraceArtifact, "core", artifact.RawPCAPNGArtifact, ""} {
		e.NativeType = kind
		if Evaluate(i, p, ReadProfileSummary, p.Target, &e, now).Eligible {
			t.Fatal("profile summary admitted another raw source", kind)
		}
	}
	e.NativeType, e.DataClass = artifact.PprofArtifact, "extract"
	if Evaluate(i, p, ReadProfileSummary, p.Target, &e, now).Eligible {
		t.Fatal("profile summary admitted reclassified source")
	}
}
