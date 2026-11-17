package presentation

import (
	"asservat.local/asservat/internal/contracts"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResultBoundDeliveryBudgetRequiresPrivateProducer(t *testing.T) {
	for _, kind := range []string{"browser", "MCP", "ordinary", "one over browser", "one over MCP", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			reply := OperationReply{Body: bytes.Repeat([]byte{'x'}, 2*contracts.InvestigationResultBound), ValidUntil: until, resultBound: kind != "ordinary"}
			name := "preview_capture"
			if kind == "one over browser" || kind == "one over MCP" {
				reply.Body = bytes.Repeat([]byte{'x'}, OperationResultBoundFrameLimit+1)
			}
			if kind == "cancelled" {
				cancel()
			}
			w := &operationWriter{ResponseRecorder: httptest.NewRecorder()}
			var sent bool
			var err error
			if kind == "MCP" || kind == "ordinary" || kind == "one over MCP" {
				sent, err = WriteOperationReplyResponse(ctx, w, http.StatusOK, reply.Body, reply, until, reply.CheckDisclosure)
			} else {
				sent, err = WriteBrowserOperationResponse(ctx, w, http.StatusOK, name, reply, until)
			}
			if kind == "browser" || kind == "MCP" {
				if err != nil || !sent || w.Body.Len() != len(reply.Body) {
					t.Fatal("named preview write failed", err)
				}
			} else if err == nil || sent || w.Body.Len() != 0 {
				t.Fatal("unnamed/over/expired response escaped", err)
			}
		})
	}
}
func TestResultBoundRejectsOneOverWithoutChangingOtherContracts(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	ops, _, current, _, _ := recordingOperationTestFixture(t)
	reply, err := ops.Call(t.Context(), current, "preview_capture", []byte(`{"recording_handles":["opaque-recording-handle"]}`))
	if err != nil {
		t.Fatal(err)
	}
	exact := append(append([]byte(nil), reply.Body...), bytes.Repeat([]byte{' '}, contracts.InvestigationResultBound-len(reply.Body))...)
	if wire.ValidateOutput("preview_capture", exact) != nil {
		t.Fatalf("valid JSON at exact preview bound refused: %s", reply.Body)
	}
	if wire.ValidateOutput("preview_capture", append(exact, ' ')) == nil {
		t.Fatal("valid JSON one over preview bound admitted")
	}
	for _, name := range []string{"list_recordings", "list_capture_history", "cancel_capture"} {
		if wire.ValidateOutput(name, bytes.Repeat([]byte{' '}, contracts.InvestigationOutputLimit+1)) == nil {
			t.Fatal("ordinary output limit widened", name)
		}
	}
}
