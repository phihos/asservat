package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/gopacket/gopacket/pcapgo"
)

func installedPacketSummaryTshark(t *testing.T, ctx context.Context, path string, native []byte, summaries ...query.PacketSummary) {
	t.Helper()
	// -n forbids address/name resolution. Explicit numeric fields independently
	// reconstruct directional conversation counts from the original native file.
	out, err := exec.CommandContext(ctx, "tshark", "-n", "-r", path, "-T", "fields", "-E", "occurrence=f", "-e", "frame.number", "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "ip.proto", "-e", "ipv6.nxt").Output()
	if err != nil {
		t.Fatal("original packet file failed numeric tshark decode", err)
	}
	if len(summaries) == 0 {
		t.Fatal("missing summary parity inputs")
	}
	for _, summary := range summaries {
		if err = installedPacketSummaryMatchesNative(summary, native, string(out)); err != nil {
			t.Fatal("packet summary/native tshark parity", err)
		}
		t.Logf("installed packet summary: %d saved records/%d directional conversations and original producer-reported exclusions match SAME authenticated nativePCAPNG; no traffic-loss/unique-datagram inference", summary.Packets, summary.ConversationsTotal)
	}
}

func installedPacketSummaryMatchesNative(summary query.PacketSummary, native []byte, fields string) error {
	if !summary.Valid() || summary.Packets < 1 {
		return errors.New("invalid/empty real-traffic summary")
	}
	counts := map[[3]string]int64{}
	lines := strings.Split(strings.TrimSuffix(fields, "\n"), "\n")
	for n, line := range lines {
		f := strings.Split(line, "\t")
		if len(f) != 11 || f[0] != strconv.Itoa(n+1) {
			return errors.New("tshark packet field/ordinal mismatch")
		}
		src, dst := f[1], f[3]
		if src == "" {
			src, dst = f[2], f[4]
		}
		a, err := netip.ParseAddr(src)
		if err != nil {
			return err
		}
		b, err := netip.ParseAddr(dst)
		if err != nil {
			return err
		}
		protocol, p1, p2 := "", f[5], f[6]
		switch {
		case f[5] != "":
			protocol = "TCP"
		case f[7] != "":
			protocol, p1, p2 = "UDP", f[7], f[8]
		case f[9] == "1":
			protocol = "ICMPv4"
		case f[10] == "58":
			protocol = "ICMPv6"
		default:
			return errors.New("unsupported tshark transport")
		}
		from, to := a.String(), b.String()
		if protocol == "TCP" || protocol == "UDP" {
			x, err := strconv.ParseUint(p1, 10, 16)
			if err != nil {
				return err
			}
			y, err := strconv.ParseUint(p2, 10, 16)
			if err != nil {
				return err
			}
			from, to = netip.AddrPortFrom(a, uint16(x)).String(), netip.AddrPortFrom(b, uint16(y)).String()
		}
		counts[[3]string{protocol, from, to}]++
	}
	rows := make([]query.PacketConversation, 0, len(counts))
	for k, n := range counts {
		rows = append(rows, query.PacketConversation{Protocol: k[0], Source: k[1], Destination: k[2], Packets: n})
	}
	slices.SortFunc(rows, func(a, b query.PacketConversation) int {
		if query.PacketConversationBefore(a, b) {
			return -1
		}
		if query.PacketConversationBefore(b, a) {
			return 1
		}
		return 0
	})
	if summary.Packets != int64(len(lines)) || summary.ConversationsTotal != len(rows) || summary.ConversationsTruncated != (len(rows) > query.PacketSummaryMaxConversations) || !reflect.DeepEqual(summary.Conversations, rows[:min(len(rows), query.PacketSummaryMaxConversations)]) {
		return errors.New("saved packet/conversation totals differ")
	}
	// Existing native writer emits one interface statistics block. pcapgo's
	// independent decoder checks its actual drop option, not the summary parser.
	stats, unknown := 0, false
	var drops uint64
	reader, err := pcapgo.NewNgReader(bytes.NewReader(native), pcapgo.NgReaderOptions{StatisticsCallback: func(_ int, s pcapgo.NgInterfaceStatistics) {
		stats++
		if s.PacketsDropped == pcapgo.NgNoValue64 {
			unknown = true
		} else {
			drops = s.PacketsDropped
		}
	}})
	if err != nil {
		return err
	}
	for {
		_, _, err = reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	if stats != 1 || unknown || drops > uint64(query.PacketSummaryMaxCount) || summary.Drops == nil || *summary.Drops != int64(drops) || summary.DropReporting != "captureExclusions" {
		return fmt.Errorf("original single-interface capture exclusions differ (statistics_blocks=%d)", stats)
	}
	return nil
}
