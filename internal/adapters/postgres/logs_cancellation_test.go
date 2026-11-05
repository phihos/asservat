package postgres

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
	"testing"
)

func TestLogsProgressOffersStopButRequestRemainsNonterminal(t *testing.T) {
	f := progressFactsFixture(t, "pending")
	var e artifact.ContextExpectation
	if err := json.Unmarshal(f.ContextCapture.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.NativeType, e.DataClass, e.ActionID = artifact.LogsArtifact, "raw", "a111111111111111111111111"
	e.Registration.NativeLimit = artifact.LogNativeLimit
	e.Logs = &artifact.LogCapture{ActionID: e.ActionID, BeforeMillis: 10000, TimeoutMillis: 10000, Streams: "combined", MaxNativeBytes: artifact.LogNativeLimit, Composition: []byte("{}")}
	if err := e.Validate(); err != nil {
		t.Fatal("argument progress fixture", err)
	}
	f.ContextCapture.ExpectationJson, _ = json.Marshal(e)
	f.RequestDigest = digest(normalized(e.Registration))
	out, err := progressFacts(f)
	if err != nil || !out.CanCancel {
		t.Fatal("finite logs lack public Stop affordance", out, err)
	}
	f.ContextCapture.SnapshotCancelRequestedAt = f.ContextCapture.CreatedAt
	out, err = progressFacts(f)
	if err != nil || out.CanCancel || !out.CancellationRequested || out.Phase == "Cancelled" {
		t.Fatal("request alone reported joined", out, err)
	}
	f.ContextCapture.SnapshotCancelJoinedAt = f.ContextCapture.CreatedAt
	out, err = progressFacts(f)
	if err != nil || out.Phase != "Cancelled" || out.ReasonCode != "CancellationJoined" {
		t.Fatal("logs join acquired profile uncertainty", out, err)
	}
}
