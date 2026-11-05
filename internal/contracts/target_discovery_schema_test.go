package contracts

import (
	"strings"
	"testing"
)

func TestTargetDiscoveryReadsOnlyExistingProcessCaptures(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := wire.Tool("get_target_discovery"); !ok {
		t.Fatal("saved process discovery is missing from the shared runtime contract")
	}
	const input = `{"capture_id":"00000000-0000-4000-8000-000000000001","section":"processes","limit":100}`
	for _, good := range []string{input, strings.Replace(input, "processes", "summary", 1)} {
		if err := wire.ValidateInput("get_target_discovery", []byte(good)); err != nil {
			t.Fatal("bounded existing-capture read rejected", err)
		}
	}
	for _, bad := range []string{
		strings.Replace(input, `"processes"`, `"flows"`, 1),
		strings.Replace(input, `100`, `101`, 1),
		strings.Replace(input, `100`, `0`, 1),
		strings.Replace(input, `100`, `null`, 1),
		strings.Replace(input, `"section":"processes",`, ``, 1),
		strings.Replace(input, `"limit":100`, `"limit":100,"pod_uid":"replacement"`, 1),
		strings.Replace(input, `"limit":100`, `"limit":100,"refresh":true`, 1),
		strings.Replace(input, `"capture_id"`, `"case_id"`, 1),
	} {
		if wire.ValidateInput("get_target_discovery", []byte(bad)) == nil {
			t.Fatal("unsupported or acquisition-bearing input accepted", bad)
		}
	}
}
