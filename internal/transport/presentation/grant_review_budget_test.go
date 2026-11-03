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

func TestRawGrantReviewDeliveryBudgetRequiresPrivateProducer(t *testing.T) {
	for _, kind := range []string{"browser", "MCP", "ordinary", "wrong name", "one over browser", "one over MCP", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			reply := OperationReply{Body: bytes.Repeat([]byte{'x'}, contracts.InvestigationGrantReviewOutputLimit), ValidUntil: until, grantReview: kind != "ordinary"}
			name := "get_grant"
			if kind == "one over browser" {
				reply.Body = append(reply.Body, 'x')
			}
			if kind == "one over MCP" {
				reply.Body = bytes.Repeat([]byte{'x'}, OperationGrantReviewFrameLimit+1)
			}
			if kind == "wrong name" {
				name = "get_capture"
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
					t.Fatal("named grant review write failed", err)
				}
			} else if err == nil || sent || w.Body.Len() != 0 {
				t.Fatal("unnamed/over/expired response escaped", err)
			}
		})
	}
}
