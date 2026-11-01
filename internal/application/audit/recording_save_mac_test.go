package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"bytes"
	"testing"
)

func TestRecordingSavePreviewMACRetainsDomainKeyAndBound(t *testing.T) {
	m, err := NewOperationMAC("audit", bytes.Repeat([]byte{1}, 32), "account", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ordinary, err := m.Digest("mcp-result/v1", []byte("same bytes"))
	if err != nil {
		t.Fatal(err)
	}
	named, err := m.RecordingSavePreviewResultDigest([]byte("same bytes"))
	if err != nil || ordinary != named {
		t.Fatal("named preview changed key or MAC domain", err)
	}
	body := bytes.Repeat([]byte{'x'}, value.OperationRecordingSavePreviewOutputLimit)
	original, err := m.RecordingSavePreviewResultDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] = 'y'
	tampered, err := m.RecordingSavePreviewResultDigest(body)
	if err != nil || tampered == original {
		t.Fatal("changed preview not bound", err)
	}
	if _, err = m.RecordingSavePreviewResultDigest(append(body, 'x')); err == nil {
		t.Fatal("one over named128KiB accepted")
	}
	if _, err = m.Digest("mcp-result/v1", body); err == nil {
		t.Fatal("ordinary MAC input bound widened")
	}
	m.Close()
	if _, err = m.RecordingSavePreviewResultDigest([]byte("closed")); err == nil {
		t.Fatal("closed MAC retained signing ability")
	}
}
