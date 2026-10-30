package presentation

import (
	"context"
	"encoding/json"
	"testing"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

type recordingTypedCapture struct{ *contextOperationFixture }

func (f recordingTypedCapture) Request(context.Context, identities.CurrentIdentity, string, string) (value.Accepted, error) {
	return value.Accepted{MetadataValidUntil: f.metadataUntil, CaptureID: "00000000-0000-4000-8000-000000000030", Expectation: artifact.ContextExpectation{Snapshot: &artifact.SourceSnapshotRequest{}}}, nil
}
func (f recordingTypedCapture) ResolveContextRequest(ctx context.Context, current identities.CurrentIdentity, p, key string) (value.ContextRequestDisposition, error) {
	a, err := f.Request(ctx, current, p, key)
	return value.ContextRequestDisposition{State: value.RequestAccepted, Accepted: &a, ValidUntil: f.metadataUntil}, err
}
func (f recordingTypedCapture) Get(ctx context.Context, current identities.CurrentIdentity, id string) (value.ContextProgress, error) {
	p, err := f.contextOperationFixture.Get(ctx, current, id)
	p.Operation = "recordingSave"
	p.ActionID = "a0123456789abcdef01234567"
	return p, err
}
func TestRecordingSaveProgressAndReplayKeepTypedOperation(t *testing.T) {
	base, current := operationFixture(t, true)
	service := recordingTypedCapture{current}
	ops, err := NewContextOperations(base.config, service, service)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"request_capture", "resolve_capture_request", "get_capture"} {
		input := wireRequest
		if name == "get_capture" {
			input = `{"capture_id":"00000000-0000-4000-8000-000000000030"}`
		}
		reply, err := ops.Call(t.Context(), current, name, json.RawMessage(input))
		if err != nil {
			t.Fatal(name, err)
		}
		var out struct{ Data map[string]any }
		if json.Unmarshal(reply.Body, &out) != nil || out.Data["operation"] != "recordingSave" {
			t.Fatal("saved source became ordinary collection", name, string(reply.Body))
		}
		if name == "get_capture" {
			actions := out.Data["actions"].([]any)
			if actions[0].(map[string]any)["action_id"] != "a0123456789abcdef01234567" {
				t.Fatal("saved packet action became pod-status", string(reply.Body))
			}
		}
	}
}
