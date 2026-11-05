package objectstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func packetEncryptedFixture(t *testing.T, dir, mode string, sealers ...evidence.KeySealer) profileEncryptedFixture {
	t.Helper()
	unused, e, _ := writerFixture(t, http.NotFoundHandler())
	unused.Close()
	e.NativeType, e.DataClass, e.ActionID = artifact.PCAPNGArtifact, "metadata", "a0123456789abcdef01234567"
	e.ExecutionClass, e.NodeUID, e.NodeBootID = artifact.ContextNodeExecution, e.WorkloadUID, e.CaptureUID
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.RequestedAgeSeconds, e.MaximumAgeSeconds = 3600, 7200
	e.Registration.ExpiresAt = e.Registration.AnchorAt.Add(time.Hour)
	e.Registration.DeleteBy = e.Registration.ExpiresAt.Add(time.Minute)
	e.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "networkHeaders", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: artifact.RecordingNativeLimit, Snaplen: artifact.RecordingSnaplen}
	var native bytes.Buffer
	w, err := pcapgo.NewNgWriterInterface(&native, pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: artifact.RecordingSnaplen, TimestampResolution: 9}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{192, 0, 2, 2}}
	tcp := &layers.TCP{SrcPort: 42000, DstPort: 443, DataOffset: 5}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()[:54] // Ethernet padding is not part of the header-only native profile.
	for range 3 {
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: e.TriggeredAt, CaptureLength: len(data), Length: 1500}, data); err != nil {
			t.Fatal(err)
		}
	}
	if mode != "unknown-stats" {
		if err = w.WriteInterfaceStats(0, pcapgo.NgInterfaceStatistics{LastUpdate: e.TriggeredAt.Add(time.Second), StartTime: e.TriggeredAt, EndTime: e.TriggeredAt.Add(time.Second), PacketsReceived: 5, PacketsDropped: 2}); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	if mode == "malformed-tail" {
		native.Write([]byte{1, 2, 3})
	}
	if mode == "bad-stats" {
		b := make([]byte, 28)
		binary.LittleEndian.PutUint32(b, 5)
		binary.LittleEndian.PutUint32(b[4:], 28)
		binary.LittleEndian.PutUint16(b[20:], 5)
		binary.LittleEndian.PutUint16(b[22:], 8)
		binary.LittleEndian.PutUint32(b[24:], 28)
		native.Write(b)
	}
	if err = e.Validate(); err != nil {
		t.Fatal(err)
	}
	copies := prepareEncryptedProjectionSource(t, dir, bytes.NewReader(native.Bytes()), e, mode == "whole-hash", sealers...)
	f := profileEncryptedFixture{Source: evidence.NativeContextSource{Expectation: e, Copies: copies}, Scope: testProjectionScope()}
	s := &f.Scope
	s.CaseID, s.CaptureID, s.ArtifactID, s.ClusterID = e.CaseID, e.CaptureUID, e.Registration.Location.ArtifactID, e.Registration.Location.ClusterID
	s.NamespaceUID, s.WorkloadUID, s.PodUID = e.NamespaceUID, e.WorkloadUID, e.PodUID
	s.Version, s.NativeType, s.SourceFormat, s.DisplayVersion = evidence.ContextCopiesDigest(copies), e.NativeType, e.Type().Format, query.PacketSummaryDisplayVersion
	s.Selection, s.SourceProjectionDigest = query.LineSelection{}, artifact.Digest{}
	if !s.Valid() || !f.Source.Valid(s.Version) {
		t.Fatal("invalid encrypted packet fixture")
	}
	return f
}

// Actual encrypted frame/manifest/index/commit, TLS range store and all three
// synthetic key-role unwraps compose the new adapter, not just the low-level parser.
func TestPacketSummaryEncryptedCompleteReadAndAuthenticationFailures(t *testing.T) {
	for _, mode := range []string{"complete", "unknown-stats", "malformed-tail", "bad-stats", "whole-hash", "ciphertext", "cancel", "unconfigured"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			f := packetEncryptedFixture(t, dir, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			verifier, keys, entered, unblock := profileEncryptedVerifier(t, dir, f, mode == "cancel")
			r, err := NewContextProjectionReader(verifier.store)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "unconfigured" {
				r.ServePacketSummaries(packets.SummarizePCAPNG)
			}
			if mode == "ciphertext" {
				file, err := os.OpenFile(filepath.Join(dir, "data"), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				_, _ = file.ReadAt(b[:], 32)
				b[0] ^= 1
				_, err = file.WriteAt(b[:], 32)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			type answer struct {
				result query.ProjectionResult
				err    error
			}
			done := make(chan answer, 1)
			go func() {
				until, _ := ctx.Deadline()
				out, err := r.ReadProjectionNative(ctx, f.Source, f.Scope, keys, until)
				done <- answer{out, err}
			}()
			if mode == "cancel" {
				select {
				case <-entered:
					cancel()
					unblock()
				case <-ctx.Done():
					t.Fatal("source not entered")
				}
			}
			select {
			case got := <-done:
				if mode == "complete" || mode == "unknown-stats" {
					if got.err != nil || got.result.PacketSummary == nil || !got.result.Valid(f.Scope) || keys.calls != 3 {
						t.Fatal("packet adapter refused full authenticated result", got.err, keys.calls)
					}
					s := got.result.PacketSummary
					if s.Packets != 3 || len(s.Conversations) != 1 || s.Conversations[0].Source != "192.0.2.1:42000" {
						t.Fatal("wrong authenticated aggregate")
					}
					if mode == "complete" && (s.Drops == nil || *s.Drops != 2) || mode == "unknown-stats" && s.Drops != nil {
						t.Fatal("counter provenance changed")
					}
				} else if got.err == nil || got.result.PacketSummary != nil || got.result.TooLarge {
					t.Fatal("failed source disclosed data", mode, got.err)
				}
				if mode == "unconfigured" && keys.calls != 0 {
					t.Fatal("unconfigured interpreter spent keys")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("packet adapter did not join")
			}
		})
	}
}
