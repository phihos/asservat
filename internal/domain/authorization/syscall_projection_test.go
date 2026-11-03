package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestSyscallProjectionEligibilityNeverAdmitsRawDisclosure(t *testing.T) {
	i, p, e, now := fixture()
	e.DataClass, e.NativeType = "raw", artifact.SyscallArgumentsArtifact
	if !Evaluate(i, p, ReadSyscallProjection, p.Target, &e, now).Eligible {
		t.Fatal("retained audience cannot read fixed syscall metadata")
	}
	for _, op := range []Operation{ReadApproved, ReadProfileSummary, DownloadApproved, CollectContext, ApproveAction} {
		if Evaluate(i, p, op, p.Target, &e, now).Eligible {
			t.Fatal("syscall projection admitted another operation", op)
		}
	}
	for _, kind := range []string{artifact.PprofArtifact, artifact.GoTraceArtifact, artifact.RawPCAPNGArtifact, artifact.SyscallRecordsArtifact, ""} {
		e.NativeType = kind
		if Evaluate(i, p, ReadSyscallProjection, p.Target, &e, now).Eligible {
			t.Fatal("syscall projection admitted another raw source", kind)
		}
	}
	e.NativeType, e.DataClass = artifact.SyscallArgumentsArtifact, "extract"
	if Evaluate(i, p, ReadSyscallProjection, p.Target, &e, now).Eligible {
		t.Fatal("reclassified raw source admitted")
	}
}
