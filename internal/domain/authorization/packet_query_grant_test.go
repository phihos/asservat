package authorization

import (
	"testing"
	"time"
)

func TestPacketQueryDisclosurePoolIsNotWholeNativeCoverage(t *testing.T) {
	now := time.Now().UTC()
	g, _ := rawQueryFixture(now)
	g.RawQuery.Operations = []string{"pcap_query"}
	g.RawQuery.MaxBytes = 128
	if !g.Valid() {
		t.Fatal("query-only output pool rejected because smaller than original")
	}
	g.RawQuery.Operations = []string{GrantDownloadOperation, "pcap_query"}
	if g.Valid() {
		t.Fatal("mixed download lost whole-file coverage")
	}
	g.RawQuery.MaxBytes = 1600
	if !g.Valid() {
		t.Fatal("mixed operation pool refused")
	}
	g.RawQuery.Operations = []string{"syscall_query"}
	if g.Valid() {
		t.Fatal("unimplemented operation widened")
	}
}
