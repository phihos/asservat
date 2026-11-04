package node

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
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
	if len(out.Work) == 0 || len(out.Work) >= len(work) {
		t.Fatal("maximum prefix was empty or silently full")
	}
	for offset := 0; offset < len(work); {
		prefix := pollPrefix(work[offset:])
		if len(prefix.Work) == 0 {
			t.Fatal("continuation made no progress")
		}
		for i, wire := range prefix.Work {
			wire.ProfileCapture.Authorization = bytes.Repeat([]byte{'x'}, execution.GoProfileAuthorizationLimit)
			delivered, ok := ReceivedWork(wire)
			if !ok || !reflect.DeepEqual(delivered.Work, work[offset+i]) || len(delivered.ProfileAuthorization) != execution.GoProfileAuthorizationLimit {
				t.Fatal("prefix reordered, changed or renewed original work")
			}
			public, _ := json.Marshal(delivered)
			if bytes.Contains(public, []byte("authorization\"")) || bytes.Contains(public, bytes.Repeat([]byte{'x'}, 128)) {
				t.Fatal("receive-only value exposed credential via JSON")
			}
			clear(delivered.ProfileAuthorization)
		}
		offset += len(prefix.Work)
	}
	t.Logf("maximum full16=332219B; bounded prefix=%d/%d encoded=%d ceiling=%d", len(out.Work), len(work), len(raw), contracts.NodeMaxResponse)
}

func TestProfileAuthorizationDecoderIsReceiveOnlyAndClosed(t *testing.T) {
	work := maximumProfileTLSWork(t)
	work.Profile.AuthorizationRequired = true
	for _, mode := range []string{"current", "missing", "no-requirement", "plaintext", "bad-value", "oversize", "wrong-kind"} {
		t.Run(mode, func(t *testing.T) {
			wire := WireWork(work)
			wire.ProfileCapture.Authorization = []byte("Bearer private-wire-sentinel")
			switch mode {
			case "missing":
				wire.ProfileCapture.Authorization = nil
			case "no-requirement":
				wire.ProfileCapture.AuthorizationRequired = false
			case "plaintext":
				wire.ProfileCapture.TLS = contracts.NodeProfileTLS{}
			case "bad-value":
				wire.ProfileCapture.Authorization = []byte("bad\nvalue")
			case "oversize":
				wire.ProfileCapture.Authorization = bytes.Repeat([]byte{'x'}, execution.GoProfileAuthorizationLimit+1)
			case "wrong-kind":
				wire.Kind = string(collector.WorkArmSource)
			}
			if len(wire.ProfileCapture.Authorization) > 0 {
				if _, ok := DomainWork(wire); ok {
					t.Fatal("public queue decoder accepted private value")
				}
			}
			got, ok := ReceivedWork(wire)
			if (mode == "current") != ok {
				t.Fatal("private envelope accepted/refused wrong branch", mode)
			}
			if ok {
				wire.ProfileCapture.Authorization[0] = 'X'
				if string(got.ProfileAuthorization) != "Bearer private-wire-sentinel" {
					t.Fatal("received material aliases wire storage")
				}
				clear(got.ProfileAuthorization)
			}
		})
	}
}
