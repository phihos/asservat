package integration

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Offline maintained CLI only, never a collector. The default Go gates can
// skip when tshark is absent; an explicit CLI qualification requires no skip.
func TestInstalledPolicyRecordingNativeFieldCLI(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Skip("offline tshark tool unavailable")
	}
	for _, kind := range []string{"sanitized-ACK", "non-ACK", "payload"} {
		t.Run(kind, func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{192, 0, 2, 2}}
			tcp := &layers.TCP{SrcPort: 40000, DstPort: 8080, Seq: 1, ACK: kind != "non-ACK", Window: 512}
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			frame := gopacket.NewSerializeBuffer()
			payload := gopacket.Payload(nil)
			if kind != "non-ACK" {
				payload = gopacket.Payload([]byte("synthetic-payload-only"))
			}
			err := gopacket.SerializeLayers(frame, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, payload)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Unix(1800000000, 0).UTC()
			var native []byte
			if kind == "sanitized-ACK" {
				filter, err := (installedPolicyRecordingFilters{}).CompileFilter(installedPolicyRecordingFilter)
				if err != nil {
					t.Fatal(err)
				}
				recorder, err := packets.NewRecorder(filter.Program, 4096, at, "synthetic CLI check")
				if err != nil {
					t.Fatal(err)
				}
				recorder.Add(frame.Bytes(), uint32(len(frame.Bytes())), at)
				var counts packets.Counters
				native, counts, err = recorder.Close(at.Add(time.Second), 0)
				if err != nil || counts.Retained != 1 {
					t.Fatal("actual recorder witness", counts, err)
				}
				if n, err := packets.CheckHeadersOnly(bytes.NewReader(native)); err != nil || n != 1 {
					t.Fatal("actual header projection", n, err)
				}
			} else {
				var buffer bytes.Buffer
				writer, err := pcapgo.NewNgWriter(&buffer, layers.LinkTypeEthernet)
				if err != nil {
					t.Fatal(err)
				}
				if err = writer.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(frame.Bytes()), Length: len(frame.Bytes())}, frame.Bytes()); err != nil {
					t.Fatal(err)
				}
				if err = writer.Flush(); err != nil {
					t.Fatal(err)
				}
				native = buffer.Bytes()
			}
			file := filepath.Join(t.TempDir(), "synthetic.pcapng")
			if err = os.WriteFile(file, native, 0600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.CommandContext(t.Context(), "tshark", policyRecordingFieldArgs(file)...).Output()
			if err != nil {
				t.Fatal("actual offline CLI", err)
			}
			fields := strings.Split(strings.TrimRight(string(out), "\r\n"), "\t")
			if len(fields) == 3 {
				t.Logf("synthetic CLI: columns=3 ACK=%q payloadFieldBytes=%d", fields[1], len(fields[2]))
			} else {
				t.Logf("synthetic CLI: columns=%d", len(fields))
			}
			n, err := policyRecordingPacketFields(out)
			if kind == "sanitized-ACK" && (err != nil || n != 1) {
				t.Fatal("genuine header-only ACK refused", n, err)
			}
			if kind != "sanitized-ACK" && err == nil {
				t.Fatal("invalid packet accepted", kind, n)
			}
		})
	}
}
