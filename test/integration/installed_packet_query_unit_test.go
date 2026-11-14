package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestInstalledPacketQueryOriginalFunding(t *testing.T) {
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "manual-raw")
	t.Setenv("ASSERVAT_PROFILE_VARIANT", "")
	t.Setenv("ASSERVAT_PROFILE_TRANSPORT", "")
	t.Setenv("ASSERVAT_PROFILE_AUTH", "")
	reserveBytes, reserveObjects := installedRegionalContextReserve()
	if reserveObjects != 64 || min(reserveBytes/1544192, reserveObjects/4) < 16 {
		t.Fatal("initial regional protocol backing cannot fund16records", reserveBytes, reserveObjects)
	}
	p := *nativeCapacityProfile()
	q, source := installedProfileComparisonCapacityFixture(t, p)
	const needed = 2*query.PacketSummaryQueryUnits + 2*query.PacketQueryQueryUnits
	if p.Records != 16 || q.ContextQuery.WorkloadQueries < needed || q.ContextQuery.PrincipalQueries < needed || q.ContextQuery.RootQueries < needed {
		t.Fatalf("initial manualraw funding records=%d root=%d principal=%d workload=%d needs12 in16", p.Records, q.ContextQuery.RootQueries, q.ContextQuery.PrincipalQueries, q.ContextQuery.WorkloadQueries)
	}
	pool, err := capacity.CompileProtectedPoolPlan(source, "capacity")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = capacity.CompileQualifiedRootBacking(q, pool); err != nil {
		t.Fatal("original16-record shared backing", err)
	}
	t.Logf("initial manualraw records16 funds two summaries4units plus two packet queries8units=12; pool objects system%d, no topup/refund", pool.System.Objects)
}

func TestInstalledPacketQueryRequestAndPendingReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	source := installedPacketQuerySource{CaseID: "00000000-0000-4000-8000-000000000001", ArtifactID: "00000000-0000-4000-8000-000000000002", GrantID: "00000000-0000-4000-8000-000000000003", Version: strings.Repeat("a", 64), PodUID: "originalPod", Expires: now.Add(time.Minute)}
	request := installedPacketQueryRequest(source, "same-key")
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(request)
	if wire.ValidateInput("pcap_query", b) != nil {
		t.Fatal("installed request does not match product contract")
	}
	handle := "00000000-0000-4000-8000-000000000004"
	operation := "00000000-0000-4000-8000-000000000005"
	until := now.Add(5 * time.Second)
	reply := func(status, id string, data any) installedComparisonReply {
		class := "metadata"
		provenance := []any{}
		if status == "ok" {
			class = "raw"
			provenance = []any{map[string]string{"artifactID": source.ArtifactID, "digest": source.Version}}
		}
		b, _ := json.Marshal(map[string]any{"request_id": id, "status": status, "data_class": class, "data": data, "provenance": provenance})
		var r installedComparisonReply
		if json.Unmarshal(b, &r) != nil {
			t.Fatal("reply fixture")
		}
		return r
	}
	pending := func(at time.Time) any {
		return map[string]any{"query_handle": handle, "retry_after_seconds": 1, "query_observed_at": at, "query_expires_at": until}
	}
	readyAt := now.Add(-2 * time.Second)
	page := map[string]any{"capture_mode": "rawPackets", "fields": request["fields"], "rows": [][]any{{1, readyAt.Format(time.RFC3339Nano), 64, 64, "10.0.0.1", "10.0.0.2", 40000, 8080, "TCP", 16, 0, 0, 0, nil, nil, strings.Repeat("ff", 64)}}, "scanned_bytes": 64, "scanned_packets": 1, "row_limit_reached": false, "scan_limit_reached": false, "output_limit_reached": false, "query_observed_at": readyAt, "query_expires_at": until}
	ready := reply("ok", "00000000-0000-4000-8000-000000000008", page)
	replies := []installedComparisonReply{reply("pending", operation, pending(now.Add(-5*time.Second))), reply("pending", "00000000-0000-4000-8000-000000000006", pending(now.Add(-4*time.Second))), reply("pending", "00000000-0000-4000-8000-000000000007", pending(now.Add(-3*time.Second))), reply("ok", ready.RequestID, map[string]any{"query_handle": handle, "tool_name": "pcap_query", "result": ready, "query_observed_at": readyAt, "query_expires_at": until})}
	calls, verified := 0, 0
	call := func(name string, args any) installedComparisonReply {
		t.Helper()
		if calls >= len(replies) {
			t.Fatal("extra operation")
		}
		if calls < 2 {
			if name != "pcap_query" || !reflect.DeepEqual(args, request) {
				t.Fatal("same-key input changed")
			}
		} else if name != "get_query_result" || args.(map[string]string)["query_handle"] != handle {
			t.Fatal("poll changed paid query")
		}
		r := replies[calls]
		calls++
		return r
	}
	out := queryInstalledPacketQueryWithCall(t, context.Background(), source, request, call, func(q, op string) func() {
		if q != handle || op != operation {
			t.Fatal("original operation changed")
		}
		verified++
		return func() {}
	}, true)
	if calls != 4 || verified != 1 || out.Rows[0][11].Number == nil || *out.Rows[0][11].Number != 0 || out.Rows[0][13].Number != nil {
		t.Fatal("pending replay/current observation/zero-null semantics", calls, verified)
	}

	calls = 0
	readyCall := func(name string, args any) installedComparisonReply {
		calls++
		if name != "pcap_query" || !reflect.DeepEqual(args, request) {
			t.Fatal("ready Begin replay changed public input")
		}
		if calls == 1 {
			return ready
		}
		if calls == 2 {
			return reply("pending", operation, pending(now.Add(-time.Second)))
		}
		t.Fatal("ready initial result started another paid page")
		return installedComparisonReply{}
	}
	queryInstalledPacketQueryWithCall(t, context.Background(), source, request, readyCall, func(q, op string) func() {
		if q != handle || op != ready.RequestID {
			t.Fatal("ready original paid operation/query identity changed")
		}
		return func() {}
	}, true)
	if calls != 2 {
		t.Fatal("initial ready response omitted same-key replay", calls)
	}
}

// This tests only the independent native/CLI parity checker. The packet and
// numeric fields are synthetic; no collector, current authority or SQL claim.
func TestInstalledPacketQueryNativeParity(t *testing.T) {
	at := time.Unix(1780000000, 123456000).UTC()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 8080}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	frame := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(frame, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload("synthetic-page-payload")); err != nil {
		t.Fatal(err)
	}
	raw := frame.Bytes()
	var native bytes.Buffer
	w, err := pcapgo.NewNgWriter(&native, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(raw), Length: len(raw) + 100}, raw); err != nil {
		t.Fatal(err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	number := func(n uint32) query.PacketQueryCell { return query.PacketQueryCell{Number: &n} }
	text := func(s string) query.PacketQueryCell { return query.PacketQueryCell{Text: &s} }
	row := []query.PacketQueryCell{number(1), text(at.Format(time.RFC3339Nano)), number(uint32(len(raw))), number(uint32(len(raw) + 100)), text("10.0.0.1"), text("10.0.0.2"), number(40000), number(8080), text("TCP"), number(0), number(0), number(0), number(0), {}, {}, text(hex.EncodeToString(raw[:64]))}
	page := query.PacketQueryResult{CaptureMode: "rawPackets", Fields: installedPacketQuerySelection().Fields, Rows: [][]query.PacketQueryCell{row}, ScannedBytes: int64(len(raw)), ScannedPackets: 1}
	fields := fmt.Sprintf("1\t1780000000.123456000\t%d\t%d\t10.0.0.1\t10.0.0.2\t\t\t40000\t8080\t0x0000\t0\t0\t0\t20\t20\n", len(raw), len(raw)+100)
	if err = installedPacketQueryMatchesNative(page, native.Bytes(), fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []int{1, 3, 10, 15} {
		bad := query.ClonePacketQueryResult(page)
		if field == 1 {
			v := at.Add(time.Nanosecond).Format(time.RFC3339Nano)
			bad.Rows[0][field].Text = &v
		} else if field == 15 {
			v := strings.Repeat("00", 64)
			bad.Rows[0][field].Text = &v
		} else {
			v := *bad.Rows[0][field].Number + 1
			bad.Rows[0][field].Number = &v
		}
		if installedPacketQueryMatchesNative(bad, native.Bytes(), fields) == nil {
			t.Fatal("mismatched native row accepted", field)
		}
	}
}

// Model ONLY the fixture's terminal inspection critical path using the actual
// FIFO. Each public read costs28s and each already-admitted worker ends60s after
// admission. No authority/source freshness or runtime performance is simulated.
func TestInstalledPacketQueryOriginalWorkerPipelineOverlaps(t *testing.T) {
	var p installedPacketTerminalPipeline
	now := time.Duration(0)
	ends := map[string]time.Duration{}
	var order []string
	admit := func(name string) {
		end := now + 60*time.Second
		ends[name] = end
		order = append(order, "read-"+name)
		p.add(t, func() {
			if now < end {
				now = end
			}
			if ends[name] != end {
				t.Fatal("original worker deadline changed")
			}
			order = append(order, "terminal-"+name)
		})
		now += 28 * time.Second
	}
	admit("summary-mcp")
	admit("summary-react")
	if now != 56*time.Second || p.joined != 0 {
		t.Fatal("summary reads serialized on terminal lifetime")
	}
	p.drain(t)
	admit("query-mcp")
	p.drain(t)
	admit("query-react")
	p.drain(t)
	p.drain(t)
	if now != 148*time.Second || p.admitted != 4 || p.joined != 4 || len(p.pending) != 0 || !reflect.DeepEqual(order, []string{"read-summary-mcp", "read-summary-react", "terminal-summary-mcp", "read-query-mcp", "terminal-summary-react", "read-query-react", "terminal-query-mcp", "terminal-query-react"}) {
		t.Fatal("raw four-query two-slot critical path changed", now, order, p)
	}
	t.Log("modeled fixture only: four reads/two original60s worker slots148s vs old two serial lifetimes120s;28s incremental, no early termination/refund/deadline mutation")
}
