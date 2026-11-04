package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	query "asservat.local/asservat/internal/domain/analysis"
)

// Real headers-only PCAPNG writer + independent numeric tshark field contract;
// no product current identity, SQL authority, collector or installed claim.
func TestInstalledPacketSummaryNativeParity(t *testing.T) {
	started := time.Now().UTC().Add(-2 * time.Second)
	native := syntheticRecording(t, started)
	drops := int64(0)
	summary := query.PacketSummary{CaptureMode: "networkHeaders", Packets: 50, Drops: &drops, DropReporting: "captureExclusions", Conversations: []query.PacketConversation{{Source: "10.0.0.1:40000", Destination: "10.0.0.2:80", Protocol: "TCP", Packets: 50}}, ConversationsTotal: 1}
	var fields strings.Builder
	for i := 1; i <= 50; i++ {
		fields.WriteString(strconv.Itoa(i) + "\t10.0.0.1\t\t10.0.0.2\t\t40000\t80\t\t\t6\t\n")
	}
	if err := installedPacketSummaryMatchesNative(summary, native, fields.String()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"count", "endpoint", "drops", "label", "framing"} {
		t.Run(mode, func(t *testing.T) {
			bad := query.ClonePacketSummary(summary)
			body := native
			switch mode {
			case "count":
				bad.Packets++
				bad.Conversations[0].Packets++
			case "endpoint":
				bad.Conversations[0].Destination = "10.0.0.3:80"
			case "drops":
				*bad.Drops = 1
			case "label":
				bad.DropReporting = "snapshotOutputLimit"
			case "framing":
				body = body[:len(body)-1]
			}
			if installedPacketSummaryMatchesNative(bad, body, fields.String()) == nil {
				t.Fatal("native parity mismatch accepted", mode)
			}
		})
	}
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Log("tshark absent; numeric field/independentPCAPNG parity tested, actual local CLI not run")
		return
	}
	path := filepath.Join(t.TempDir(), "same-native.pcapng")
	if err := os.WriteFile(path, native, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	installedPacketSummaryTshark(t, ctx, path, native, summary)
}

func TestInstalledPacketSummaryOriginalQueryFunding(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-mixed")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "")
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "")
	t.Setenv("ASSERVAT_PROFILE_AUTH", "")
	p := *nativeCapacityProfile()
	q, source := installedProfileComparisonCapacityFixture(t, p)
	const queries = 2 // one ordinary MCP query and one independent console query.
	needed := int64(queries * query.PacketSummaryQueryUnits)
	if p.Records != 8 || q.ContextQuery.WorkloadQueries < needed || q.ContextQuery.PrincipalQueries < query.PacketSummaryQueryUnits || q.ContextQuery.RootQueries < needed {
		t.Fatal("original manual-mixed query reservation cannot fund both clients")
	}
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = capacity.CompileQualifiedRootBacking(q, pool); err != nil {
		t.Fatal("original manual-mixed combined backing", err)
	}
	t.Logf("manual-mixed retains original8record reservation: two independent2unit reads=%d<=workload%d; each principal charged2, no capture/query/pool ceiling increase", needed, q.ContextQuery.WorkloadQueries)
}

// C18 stamps each current response observation separately. The paid query
// handle/expiry stay fixed while pending and ready observations advance.
func TestInstalledPacketSummaryResponseObservationAdvances(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	source := installedPacketSummarySource{CaseID: "00000000-0000-4000-8000-000000000001", ArtifactID: "00000000-0000-4000-8000-000000000002", Version: strings.Repeat("a", 64), PodUID: "original-pod", Expires: now.Add(time.Minute)}
	handle := "00000000-0000-4000-8000-000000000003"
	operation := "00000000-0000-4000-8000-000000000004"
	until := now.Add(5 * time.Second)
	reply := func(status, id string, data any) installedComparisonReply {
		class, provenance := "extract", []any{map[string]string{"artifactID": source.ArtifactID, "digest": source.Version}}
		if status == "pending" {
			class, provenance = "metadata", []any{}
		}
		b, err := json.Marshal(map[string]any{"request_id": id, "status": status, "data_class": class, "data": data, "provenance": provenance})
		if err != nil {
			t.Fatal(err)
		}
		var r installedComparisonReply
		if json.Unmarshal(b, &r) != nil {
			t.Fatal("synthetic envelope")
		}
		return r
	}
	pending := func(at time.Time) map[string]any {
		return map[string]any{"query_handle": handle, "retry_after_seconds": 1, "query_observed_at": at, "query_expires_at": until}
	}
	readyAt := now.Add(-3 * time.Second)
	content := map[string]any{"capture_mode": "networkHeaders", "packets": 1, "drops": 0, "drop_reporting": "captureExclusions", "conversations": []any{map[string]any{"source": "10.0.0.1:40000", "destination": "10.0.0.2:80", "protocol": "TCP", "packets": 1}}, "conversations_total": 1, "conversations_truncated": false, "query_observed_at": readyAt, "query_expires_at": until}
	ready := reply("ok", "00000000-0000-4000-8000-000000000006", content)
	replies := []installedComparisonReply{reply("pending", operation, pending(now.Add(-5*time.Second))), reply("pending", "00000000-0000-4000-8000-000000000005", pending(now.Add(-4*time.Second))), reply("ok", ready.RequestID, map[string]any{"query_handle": handle, "tool_name": "get_pcap_summary", "result": ready, "query_observed_at": readyAt, "query_expires_at": until})}
	calls, verified := 0, 0
	call := func(name string, args any) installedComparisonReply {
		t.Helper()
		if calls >= len(replies) {
			t.Fatal("unexpected extra poll")
		}
		if calls == 0 {
			if name != "get_pcap_summary" {
				t.Fatal("unexpected initial call")
			}
		} else {
			if name != "get_query_result" || args.(map[string]string)["query_handle"] != handle {
				t.Fatal("changed paid handle")
			}
		}
		r := replies[calls]
		calls++
		return r
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	result := queryInstalledPacketSummaryWithCall(t, ctx, source, call, func(q, op string) func() {
		if q != handle || op != operation {
			t.Fatal("changed source operation")
		}
		verified++
		return func() {}
	})
	if !result.Valid() || calls != 3 || verified != 1 {
		t.Fatal("pending/current ready sequence did not join exactly once", calls, verified)
	}
}
