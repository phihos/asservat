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

	"asservat.local/asservat/internal/adapters/packets"
	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/gopacket/gopacket/pcapgo"
)

func installedPacketSummaryTshark(t *testing.T, ctx context.Context, path string, native []byte, summaries ...query.PacketSummary) {
	t.Helper()
	// -n forbids address/name resolution. Explicit numeric fields independently
	// reconstruct directional conversation counts from the original native file.
	args := []string{"-n", "-r", path, "-T", "fields", "-E", "occurrence=f", "-e", "frame.number", "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport", "-e", "ip.proto", "-e", "ipv6.nxt"}
	for _, summary := range summaries {
		if summary.CaptureMode == "rawPackets" {
			args = append(args, "-e", "frame.cap_len", "-e", "ip.hdr_len", "-e", "tcp.hdr_len")
			break
		}
	}
	out, err := exec.CommandContext(ctx, "tshark", args...).Output()
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
	raw := summary.CaptureMode == "rawPackets"
	if raw {
		if n, err := packets.CheckRaw(bytes.NewReader(native), packets.RawLimits{Snaplen: 96, TCP: manualRawTCPCap}); err != nil || int64(n) != summary.Packets {
			return errors.New("raw canonical caps/count mismatch")
		}
	}
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
	counts := map[[3]string]int64{}
	lines := strings.Split(strings.TrimSuffix(fields, "\n"), "\n")
	var unclassified int64
	for n, line := range lines {
		f := strings.Split(line, "\t")
		expected := 11
		if raw {
			expected = 14
		}
		if len(f) != expected || f[0] != strconv.Itoa(n+1) {
			return errors.New("tshark packet field/ordinal mismatch")
		}
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			return err
		}
		if raw {
			cap, err := strconv.Atoi(f[11])
			if err != nil || cap != len(data) || cap != ci.CaptureLength {
				return errors.New("tshark raw capture length differs from native")
			}
		}
		src, dst := f[1], f[3]
		ipHeader := 40
		if src == "" {
			src, dst = f[2], f[4]
		} else if raw {
			ipHeader, _ = strconv.Atoi(f[12])
		}
		a, errA := netip.ParseAddr(src)
		b, errB := netip.ParseAddr(dst)
		protocol, p1, p2, transportHeader := "", f[5], f[6], 0
		switch {
		case f[5] != "":
			protocol = "TCP"
			if raw {
				transportHeader, _ = strconv.Atoi(f[13])
			}
		case f[7] != "":
			protocol, p1, p2, transportHeader = "UDP", f[7], f[8], 8
		case f[9] == "1":
			protocol, transportHeader = "ICMPv4", 8
		case f[10] == "58":
			protocol, transportHeader = "ICMPv6", 4
		}
		// tshark may expose ports before the stored TCP header is complete. Such
		// prefixes stay unclassified: do not invent the missing header length.
		if raw && (errA != nil || errB != nil || ipHeader < 20 || ipHeader > 60 || protocol == "" || transportHeader < 1 || protocol == "TCP" && (transportHeader < 20 || transportHeader > 60) || len(data) < 14+ipHeader+transportHeader) {
			unclassified++
			continue
		}
		if errA != nil || errB != nil || protocol == "" {
			return errors.New("unsupported/incomplete tshark tuple")
		}
		from, to := a.Unmap().String(), b.Unmap().String()
		if protocol == "TCP" || protocol == "UDP" {
			x, err := strconv.ParseUint(p1, 10, 16)
			if err != nil {
				if raw {
					unclassified++
					continue
				}
				return err
			}
			y, err := strconv.ParseUint(p2, 10, 16)
			if err != nil {
				if raw {
					unclassified++
					continue
				}
				return err
			}
			from, to = netip.AddrPortFrom(a.Unmap(), uint16(x)).String(), netip.AddrPortFrom(b.Unmap(), uint16(y)).String()
		}
		counts[[3]string{protocol, from, to}]++
	}
	if raw && (summary.UnclassifiedPackets == nil || *summary.UnclassifiedPackets != unclassified) {
		return errors.New("raw incomplete-header count differs")
	}
	if _, _, err = reader.ReadPacketData(); !errors.Is(err, io.EOF) {
		return errors.New("native has missing tshark rows or malformed tail")
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
	if stats != 1 || unknown || drops > uint64(query.PacketSummaryMaxCount) || summary.Drops == nil || *summary.Drops != int64(drops) || summary.DropReporting != "captureExclusions" {
		return fmt.Errorf("original single-interface capture exclusions differ (statistics_blocks=%d)", stats)
	}
	return nil
}
