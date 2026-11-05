package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestRawPacketSummaryEligibilityIsDistinctFromRawDisclosure(t *testing.T) {
	i, p, e, now := fixture()
	e.DataClass, e.NativeType = "raw", artifact.RawPCAPNGArtifact
	summary := Operation("readPacketSummary")
	if !Evaluate(i, p, summary, p.Target, &e, now).Eligible {
		t.Fatal("ordinary retained audience cannot inspect fixed raw packet aggregate")
	}
	for _, op := range []Operation{ReadApproved, ReadProfileSummary, ReadSyscallProjection, DownloadApproved, CollectContext, ApproveAction} {
		if Evaluate(i, p, op, p.Target, &e, now).Eligible {
			t.Fatal("raw packet summary granted unrelated raw operation", op)
		}
	}
	for _, kind := range []string{artifact.PCAPNGArtifact, artifact.PprofArtifact, artifact.GoTraceArtifact, artifact.SyscallArgumentsArtifact, ""} {
		e.NativeType = kind
		if Evaluate(i, p, summary, p.Target, &e, now).Eligible {
			t.Fatal("aggregate admitted different source", kind)
		}
	}
	e.NativeType, e.DataClass = artifact.RawPCAPNGArtifact, "metadata"
	if Evaluate(i, p, summary, p.Target, &e, now).Eligible {
		t.Fatal("reclassified raw source admitted")
	}
}
