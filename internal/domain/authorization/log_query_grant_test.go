package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestRawLogQueryUsesExactOperationAndRawClient(t *testing.T) {
	now := time.Now().UTC()
	g, _ := rawQueryFixture(now)
	g.RawQuery.Operations = []string{"get_logs"}
	g.RawQuery.MaxBytes = 128
	if !g.Valid() {
		t.Fatal("exact logs query output pool refused")
	}
	g.RawQuery.Operations = []string{GrantDownloadOperation, "get_logs", "pcap_query", "syscall_query"}
	if g.Valid() {
		t.Fatal("mixed download pool lost whole-native coverage")
	}
	g.RawQuery.MaxBytes = 1600
	if !g.Valid() {
		t.Fatal("three distinct approved operations refused")
	}
	i, p, e, at := fixture()
	e.DataClass, e.NativeType = "raw", artifact.LogsArtifact
	if Evaluate(i, p, Operation("readLogQuery"), p.Target, &e, at).Eligible {
		t.Fatal("missing raw client scope admitted")
	}
	i.Scopes = append(i.Scopes, "evidence:raw")
	if !Evaluate(i, p, Operation("readLogQuery"), p.Target, &e, at).Eligible {
		t.Fatal("ordinary retained raw logs reader refused")
	}
	for _, kind := range []string{artifact.RawPCAPNGArtifact, artifact.SyscallRecordsArtifact, artifact.PprofArtifact} {
		e.NativeType = kind
		if Evaluate(i, p, Operation("readLogQuery"), p.Target, &e, at).Eligible {
			t.Fatal("wrong raw source admitted", kind)
		}
	}
}
