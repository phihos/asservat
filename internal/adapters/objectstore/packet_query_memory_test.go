package objectstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type packetQueryProbeInput struct {
	Shape                  string
	Packets, CapturedBytes int64
	DistinctWireLengths    int64
	NativeSHA256           string
	NativeBytes            int64
	Files                  map[string]string
}
type packetQueryProbeFixture struct {
	BinarySHA256 string
	Inputs       []packetQueryProbeInput
}

// This explicit process component never starts a container. The independent
// runner must retain actual cgroup counters/limits; RSS is only an observation.
func TestPacketQueryEncryptedProcess(t *testing.T) {
	if dir := os.Getenv("ASSERVAT_PACKET_QUERY_GENERATE"); dir != "" {
		packetQueryProbeGenerate(t, dir)
		return
	}
	dir := os.Getenv("ASSERVAT_PACKET_QUERY_FIXTURE")
	if dir == "" {
		t.Skip("explicit prepared saved-packet-query resource component")
	}
	shape, mode := os.Getenv("ASSERVAT_PACKET_QUERY_SHAPE"), os.Getenv("ASSERVAT_PACKET_QUERY_MODE")
	if mode != "complete" && mode != "cancel" && mode != "source-error" {
		t.Fatal("explicit complete/cancel/source-error required")
	}
	var fixture packetQueryProbeFixture
	comparisonProbeLoad(t, filepath.Join(dir, "probe.json"), &fixture)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binarySHA, _ := comparisonProbeDigest(t, executable)
	if fixture.BinarySHA256 != binarySHA {
		t.Fatal("producer/consumer binary differs")
	}
	var input *packetQueryProbeInput
	for i := range fixture.Inputs {
		if fixture.Inputs[i].Shape == shape {
			input = &fixture.Inputs[i]
		}
	}
	if input == nil {
		t.Fatal("unknown prepared shape")
	}
	for name, want := range input.Files {
		got, _ := comparisonProbeDigest(t, filepath.Join(dir, shape, name))
		if got != want {
			t.Fatal("immutable prepared source changed", name)
		}
	}
	var f profileEncryptedFixture
	comparisonProbeLoad(t, filepath.Join(dir, shape, "fixture.json"), &f)
	if input.NativeBytes != artifact.RecordingNativeLimit || len(f.Scope.PacketQuery.Selection().Program.Instructions) != 256 {
		t.Fatal("not maximum source/program")
	}
	until := time.Now().Add(value.NativeConversationWindow(value.NativeProjection))
	ctx, cancel := context.WithDeadline(t.Context(), until)
	defer cancel()
	var before, after syscall.Rusage
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, readErr, roles, joined, cancelJoin := savedPacketProbeRead(t, ctx, cancel, filepath.Join(dir, shape), f, mode, func(r *NativeContextReader) { r.ServePacketQueries(packets.QueryPCAPNG) })
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	valid := readErr == nil && result.Valid(f.Scope)
	expected := false
	var rows, scanned int
	var logicalBytes int64
	if valid && result.PacketQuery != nil {
		rows = len(result.PacketQuery.Rows)
		scanned = int(result.PacketQuery.ScannedPackets)
		logicalBytes = result.PacketQuery.ScannedBytes
		// The first matches occur only in the final100 records. Authentication still
		// covers the complete source after a logical output/row limit is reached.
		expected = rows > 0 && rows <= 100 && int64(scanned) >= input.Packets-100 && int64(scanned) <= input.Packets && (result.PacketQuery.OutputLimitReached || result.PacketQuery.RowLimitReached)
		if shape == "tiny-prefix-wire-cache" {
			expected = expected && rows == 100 && int64(scanned) == input.Packets && logicalBytes == input.CapturedBytes && result.PacketQuery.RowLimitReached
		}
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	report := map[string]any{"format": "packet-query-resource-component/v1", "shape": shape, "mode": mode, "binary_sha256": binarySHA, "input": input, "go_version": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0), "gogc": os.Getenv("GOGC"), "gomemlimit": os.Getenv("GOMEMLIMIT"), "operation_elapsed_ns": time.Since(started).Nanoseconds(), "operation_user_cpu_ns": comparisonProbeCPU(after.Utime) - comparisonProbeCPU(before.Utime), "operation_system_cpu_ns": comparisonProbeCPU(after.Stime) - comparisonProbeCPU(before.Stime), "process_peak_rss_kib": after.Maxrss, "heap_inuse": memory.HeapInuse, "command_until": until, "conversation_bound_ns": value.NativeConversationWindow(value.NativeProjection).Nanoseconds(), "synthetic_unwraps": roles, "receiver_joined": joined, "cancel_join_ns": cancelJoin, "result_valid": valid, "expected_shape_match": expected, "read_failed": readErr != nil, "rows": rows, "logical_scanned_packets": scanned, "logical_scanned_bytes": logicalBytes, "program_instructions": 256, "selected_unique_fields": len(f.Scope.PacketQuery.Selection().Fields), "frame_prefix_bytes": 64, "scope": "Actual approved receiver, NativeContextReader, installed GoVM query parser, complete framed/canonical authentication and local TLS range/key RPC; synthetic current source/key authority. Provider servers share measured consumer process. No hub/libpcap compilation, SQL, real KMS, native command/owner/public transport, worker bootstrap/enrollment or installed maximum-input claim. Cgroup enforcement/counters require independent external runner/probe evidence."}
	if path := os.Getenv("ASSERVAT_PACKET_QUERY_REPORT"); path != "" {
		comparisonProbeWrite(t, path, report)
	}
	if !joined || roles < 1 || roles > 3 || mode == "complete" && roles != 3 {
		t.Fatal("exact role/join contract", roles, joined)
	}
	if mode == "complete" && !expected || mode != "complete" && (readErr == nil || result.PacketQuery != nil) {
		t.Fatal("resource result/refusal contract", mode)
	}
	result.Clear()
}

func packetQueryProbeSelection() query.PacketQuerySelection {
	// LD_LEN,252 legal non-mutating ALU instructions, JEQ, accept, reject.
	// Every nonmatching original wire length specializes the actual GoVM. Beyond
	// its existing4096-entry cache the remaining distinct lengths are uncached.
	instructions := make([]artifact.FilterInstruction, 256)
	instructions[0] = artifact.FilterInstruction{Code: 0x80}
	for i := 1; i <= 252; i++ {
		instructions[i] = artifact.FilterInstruction{Code: 0x04}
	}
	instructions[253] = artifact.FilterInstruction{Code: 0x15, Jf: 1, K: ^uint32(0)}
	instructions[254] = artifact.FilterInstruction{Code: 0x06, K: 65535}
	instructions[255] = artifact.FilterInstruction{Code: 0x06}
	program := query.PacketQueryProgram{CompilerDigest: query.PacketQueryCompilerDigest(), ProgramDigest: query.PacketQueryProgramDigest(instructions), Instructions: instructions}
	return query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex, query.PacketTime, query.PacketCapturedLength, query.PacketWireLength, query.PacketSourceAddress, query.PacketDestinationAddress, query.PacketSourcePort, query.PacketDestinationPort, query.PacketProtocol, query.PacketTCPFlags, query.PacketTCPSeq, query.PacketTCPAck, query.PacketTCPWindow, query.PacketICMPType, query.PacketICMPCode, query.PacketFramePrefixHex}, Program: program, FramePrefix: &query.PacketQueryFramePrefix{Length: 64}, MaxPackets: 100, MaxScanBytes: 8 << 20}
}
func packetQueryProbeGenerate(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binarySHA, _ := comparisonProbeDigest(t, executable)
	fixture := packetQueryProbeFixture{BinarySHA256: binarySHA}
	for _, shape := range []string{"payload-output", "tiny-prefix-wire-cache"} {
		folder := filepath.Join(dir, shape)
		if err = os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		keyScope := value.KeyScope{InstallationID: testProjectionScope().RootID, Purpose: "artifact", KeyID: "synthetic"}
		sealer := comparisonRemoteFixtureSealer{scope: keyScope}
		f := packetEncryptedFixtureSource(t, folder, "complete", true, sealer)
		if shape == "tiny-prefix-wire-cache" {
			f.Source.Expectation.Recording.Snaplen = 1
		}
		native, input := packetQueryProbeNative(t, shape, f.Source.Expectation.TriggeredAt)
		if err = os.WriteFile(filepath.Join(folder, "native.pcapng"), native, 0600); err != nil {
			t.Fatal(err)
		}
		f.Source.Copies = prepareEncryptedProjectionSource(t, folder, bytes.NewReader(native), f.Source.Expectation, false, sealer)
		f.Scope.Version = evidence.ContextCopiesDigest(f.Source.Copies)
		f.Scope.DisplayVersion = query.PacketQueryDisplayVersion
		f.Scope.RawGrantID = f.Scope.RootID
		f.Scope.PacketQuery, err = packetQueryProbeSelection().Window()
		if err != nil || !f.Scope.Valid() || !f.Source.Valid(f.Scope.Version) {
			t.Fatal("invalid query fixture", err)
		}
		comparisonProbeWrite(t, filepath.Join(folder, "fixture.json"), f)
		input.NativeSHA256, input.NativeBytes = comparisonProbeDigest(t, filepath.Join(folder, "native.pcapng"))
		input.Files = map[string]string{}
		for _, name := range []string{"native.pcapng", "data", "index", "manifest", "commit", "fixture.json"} {
			input.Files[name], _ = comparisonProbeDigest(t, filepath.Join(folder, name))
		}
		fixture.Inputs = append(fixture.Inputs, input)
		clear(native)
	}
	comparisonProbeWrite(t, filepath.Join(dir, "probe.json"), fixture)
}
func packetQueryProbeNative(t *testing.T, shape string, at time.Time) ([]byte, packetQueryProbeInput) {
	t.Helper()
	input := packetQueryProbeInput{Shape: shape}
	var out bytes.Buffer
	snap := 1500
	if shape == "tiny-prefix-wire-cache" {
		snap = 1
	} else if shape != "payload-output" {
		t.Fatal("unknown shape")
	}
	writer, err := pcapgo.NewNgWriterInterface(&out, pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: uint32(snap), TimestampResolution: 9}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.Flush(); err != nil {
		t.Fatal(err)
	}
	// Complete IPv6/TCP headers and maximum retained frame bytes, with long
	// canonical IPv6 cell values. Checksums are not an authority claim here.
	frame := make([]byte, 1500)
	copy(frame, []byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 0x86, 0xdd, 0x60, 0, 0, 0})
	binary.BigEndian.PutUint16(frame[18:], 1446)
	frame[20] = 6
	frame[21] = 64
	for i := 22; i < 54; i++ {
		frame[i] = 0xff
	}
	frame[53] = 0xfe
	binary.BigEndian.PutUint16(frame[54:], 65535)
	binary.BigEndian.PutUint16(frame[56:], 65535)
	binary.BigEndian.PutUint32(frame[58:], ^uint32(0))
	binary.BigEndian.PutUint32(frame[62:], ^uint32(0))
	frame[66] = 0x51
	frame[67] = 0xff
	binary.BigEndian.PutUint16(frame[68:], 65535)
	random := rand.New(rand.NewPCG(11, 17))
	recordBytes := 32 + (snap+3)/4*4
	// Reserve one finite ISB (52bytes) plus a valid padding ISB (>=40bytes),
	// then use the maximum whole-record count fitting this exact8MiB source.
	count := (int(artifact.RecordingNativeLimit) - out.Len() - 92) / recordBytes
	if count < 4100 {
		t.Fatal("not enough records to fill wire cache")
	}
	for n := 0; n < count; n++ {
		for i := 74; i < len(frame); i++ {
			frame[i] = byte(random.Uint32())
		}
		wire := 1500 + n
		if n >= count-100 {
			wire = int(^uint32(0))
		}
		data := frame
		if snap == 1 {
			data = frame[:1]
		}
		if err = writer.WritePacket(gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(n) * time.Nanosecond), CaptureLength: len(data), Length: wire}, data); err != nil {
			t.Fatal(err)
		}
		input.Packets++
		input.CapturedBytes += int64(len(data))
	}
	input.DistinctWireLengths = input.Packets - 99
	if err = writer.WriteInterfaceStats(0, pcapgo.NgInterfaceStatistics{LastUpdate: at.Add(time.Second), PacketsReceived: uint64(input.Packets), PacketsDropped: 0}); err != nil {
		t.Fatal(err)
	}
	if err = writer.Flush(); err != nil {
		t.Fatal(err)
	}
	for out.Len() < int(artifact.RecordingNativeLimit) {
		size := min(256<<10, int(artifact.RecordingNativeLimit)-out.Len())
		if size < 40 {
			t.Fatal("padding geometry", size)
		}
		body := make([]byte, 24)
		binary.LittleEndian.PutUint16(body[12:], 5)
		binary.LittleEndian.PutUint16(body[14:], 8)
		remaining := size - 40
		for remaining > 0 {
			n := min(65532, remaining-4)
			option := make([]byte, 4+n)
			binary.LittleEndian.PutUint16(option, 1)
			binary.LittleEndian.PutUint16(option[2:], uint16(n))
			body = append(body, option...)
			remaining -= 4 + n
		}
		body = append(body, 0, 0, 0, 0)
		block := make([]byte, len(body)+12)
		binary.LittleEndian.PutUint32(block, 5)
		binary.LittleEndian.PutUint32(block[4:], uint32(len(block)))
		copy(block[8:], body)
		binary.LittleEndian.PutUint32(block[len(block)-4:], uint32(len(block)))
		out.Write(block)
	}
	if out.Len() != int(artifact.RecordingNativeLimit) {
		t.Fatal("native maximum size")
	}
	checked, err := packets.CheckRaw(bytes.NewReader(out.Bytes()), packets.RawLimits{Snaplen: snap})
	if err != nil || int64(checked) != input.Packets {
		t.Fatal("canonical producer shape", err)
	}
	return out.Bytes(), input
}
