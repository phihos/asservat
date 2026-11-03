package presentation

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"strings"
	"testing"
)

func TestRawDownloadApprovalProjectionIsTypedAndPrepareOnly(t *testing.T) {
	s, f, c := downloadProjection(t)
	f.err = authorization.ErrApprovalRequired
	reply, err := s.Call(t.Context(), c, "prepare_artifact_download", []byte(`{"artifact_id":"`+artifactID+`","idempotency_key":"same-key"}`))
	if err != nil || !strings.Contains(string(reply.Body), `"code":"RawApprovalRequired"`) || !strings.Contains(string(reply.Body), `"retryable":false`) {
		t.Fatal(err, string(reply.Body))
	}
	reply, err = s.Call(t.Context(), c, "get_artifact_download", []byte(`{"download_id":"`+downloadID+`"}`))
	if err != nil || strings.Contains(string(reply.Body), "RawApprovalRequired") {
		t.Fatal("status became approval", err, string(reply.Body))
	}
	f.err = artifact.ErrDownloadUnavailable
	reply, err = s.Call(t.Context(), c, "prepare_artifact_download", []byte(`{"artifact_id":"`+artifactID+`","idempotency_key":"same-key"}`))
	if err != nil || strings.Contains(string(reply.Body), "RawApprovalRequired") {
		t.Fatal("unavailable became approval", err, string(reply.Body))
	}
}
