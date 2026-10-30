package contracts

import (
	"strings"
	"testing"
)

func TestOutputViolationNamesLocationNotValue(t *testing.T) {
	v, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	b := []byte(`{"schema_version":"mcp-result/v1","request_id":"00000000-0000-4000-8000-000000000001","data_class":"metadata","status":"ok","data":{"kind":"secret-value"},"truncated":false,"next_cursor":null,"narrowing_hint":null,"warnings":[],"provenance":[]}`)
	got := v.OutputViolation("preview_recording_save", b)
	if !strings.HasPrefix(got, "/") || strings.Contains(got, "secret-value") {
		t.Fatal(got)
	}
}
