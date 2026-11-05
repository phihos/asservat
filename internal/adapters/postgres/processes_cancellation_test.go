package postgres

import (
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
	"testing"
)

func TestProcessesProgressOffersStopButRequestRemainsNonterminal(t *testing.T) {
	f := progressFactsFixture(t, "pending")
	var e artifact.ContextExpectation
	if err := json.Unmarshal(f.ContextCapture.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextAPIExecution, "", ""
	e.NativeType, e.DataClass, e.ActionID = artifact.ProcessesArtifact, "metadata", "a111111111111111111111111"
	e.Registration.NativeLimit = artifact.ProcessNativeLimit
	e.Processes = &artifact.ProcessCapture{ActionID: e.ActionID, Mode: artifact.ProcessMain, TimeoutMillis: 5000, MaxNativeBytes: artifact.ProcessNativeLimit, Composition: []byte("{}")}
	if err := e.Validate(); err != nil {
		t.Fatal("processes progress fixture", err)
	}
	f.ContextCapture.ExpectationJson, _ = json.Marshal(e)
	f.RequestDigest = digest(normalized(e.Registration))
	out, err := progressFacts(f)
	if err != nil || !out.CanCancel {
		t.Fatal("finite process snapshot lack public Stop affordance", out, err)
	}
	f.ContextCapture.SnapshotCancelRequestedAt = f.ContextCapture.CreatedAt
	out, err = progressFacts(f)
	if err != nil || out.CanCancel || !out.CancellationRequested || out.Phase == "Cancelled" {
		t.Fatal("request alone reported joined", out, err)
	}
	f.ContextCapture.SnapshotCancelJoinedAt = f.ContextCapture.CreatedAt
	out, err = progressFacts(f)
	if err != nil || out.Phase != "Cancelled" || out.ReasonCode != "CancellationJoined" {
		t.Fatal("processes join acquired profile uncertainty", out, err)
	}
}
