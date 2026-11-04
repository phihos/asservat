package node

import (
	"bytes"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
)

func TestProfileAuthorizationMaximumPollPrefix(t *testing.T) {
	maximum := maximumProfileTLSWork(t)
	maximum.Profile.AuthorizationRequired = true
	work := make([]collector.Work, collector.MaxWorkPerPoll)
	for i := range work {
		work[i] = maximum
		work[i].Sequence = ^uint64(0) - uint64(len(work)-1-i)
	}
	out := pollPrefix(work)
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > contracts.NodeMaxResponse {
		t.Fatalf("private poll prefix exceeds unchanged response ceiling: items=%d encoded=%d ceiling=%d err=%v", len(out.Work), len(raw), contracts.NodeMaxResponse, err)
	}
	if _, err := contracts.DecodeNodePollResponse(bytes.NewReader(raw)); err != nil {
		t.Fatal("actual closed receiver refused bounded prefix", err)
	}
}
