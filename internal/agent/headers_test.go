package agent

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

// Without payload tcpdump hands over the start of each packet only. That
// start holds the longest headers, so the capture is the same as of whole
// packets.
func TestSnappedPacketsKeepTheirHeaders(t *testing.T) {
	if args := strings.Join(tcpdumpArgs(7, "port 80", false, false), " "); !strings.Contains(args, "-t 7 -n tcpdump") || !strings.Contains(args, " -s 140 ") || !strings.Contains(args, "port 80") || strings.Contains(args, " -U ") {
		t.Fatal("without payload:", args)
	}
	// What is read while tcpdump runs gets every packet as it comes.
	if args := strings.Join(tcpdumpArgs(7, "", true, true), " "); strings.Contains(args, " -s ") || !strings.Contains(args, " -U ") {
		t.Fatal("with payload:", args)
	}
	le := binary.LittleEndian
	packet := binary.BigEndian.AppendUint16(nil, 0x0800) // Linux cooked v2
	packet = append(packet, make([]byte, 18)...)
	ip := make([]byte, 60) // IPv4 with all options
	ip[0], ip[9] = 0x4f, 6
	tcp := make([]byte, 60) // TCP with all options
	tcp[12], tcp[13] = 15<<4, 0x02
	packet = append(append(append(packet, ip...), tcp...), bytes.Repeat([]byte("payload "), 150)...)
	stream := func(captured int) []byte {
		file := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0}
		file = le.AppendUint32(file, 276)
		file = le.AppendUint32(le.AppendUint32(file, 1), 2)
		file = le.AppendUint32(le.AppendUint32(file, uint32(captured)), uint32(len(packet)))
		return append(file, packet[:captured]...)
	}
	whole, err := io.ReadAll(headersOnly(bytes.NewReader(stream(len(packet)))))
	if err != nil || len(whole) != 24+16+headerSnap {
		t.Fatal("whole packets", len(whole), err)
	}
	snapped, err := io.ReadAll(headersOnly(bytes.NewReader(stream(headerSnap))))
	if err != nil || !bytes.Equal(snapped, whole) {
		t.Fatal("snapped packets differ", len(snapped), err)
	}
}

func TestHeadersOnlyDropsPayload(t *testing.T) {
	le := binary.LittleEndian
	file := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0}
	file = le.AppendUint32(file, 276) // Linux cooked v2
	add := func(packet []byte) {
		file = le.AppendUint32(file, 1)
		file = le.AppendUint32(file, 2)
		file = le.AppendUint32(file, uint32(len(packet)))
		file = le.AppendUint32(file, uint32(len(packet)))
		file = append(file, packet...)
	}
	sll := func(proto uint16) []byte {
		return append(binary.BigEndian.AppendUint16(nil, proto), make([]byte, 18)...)
	}
	ipv4 := func(protocol byte) []byte {
		h := make([]byte, 24) // with one option word
		h[0], h[9] = 0x46, protocol
		return h
	}
	tcp := make([]byte, 32) // with options
	tcp[12] = 8 << 4
	secret := []byte("GET /?token=secret HTTP/1.1")
	add(append(append(append(sll(0x0800), ipv4(6)...), tcp...), secret...))
	add(append(append(append(sll(0x0800), ipv4(17)...), make([]byte, 8)...), secret...))
	ipv6 := make([]byte, 40)
	ipv6[0], ipv6[6] = 0x60, 6
	add(append(append(append(sll(0x86dd), ipv6...), tcp...), secret...))
	add(append(sll(0x1234), secret...)) // unknown protocol: link header only

	out, err := io.ReadAll(headersOnly(bytes.NewReader(file)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("secret")) {
		t.Fatal("payload kept")
	}
	want := []int{20 + 24 + 32, 20 + 24 + 8, 20 + 40 + 32, 20}
	rest := out[24:]
	for i, w := range want {
		if got, original := int(le.Uint32(rest[8:])), int(le.Uint32(rest[12:])); got != w || original <= got {
			t.Fatalf("packet %d: kept %d of %d bytes, want %d", i, got, original, w)
		}
		rest = rest[16+w:]
	}
	if len(rest) != 0 || !bytes.Equal(out[:24], file[:24]) {
		t.Fatal("stream framing changed")
	}
	// A stream cut within a record keeps the complete packets before it.
	out, err = io.ReadAll(headersOnly(bytes.NewReader(file[:len(file)-5])))
	if err != nil || len(out) != 24+3*16+want[0]+want[1]+want[2] {
		t.Fatal("interrupted stream", len(out), err)
	}
	if _, err := io.ReadAll(headersOnly(bytes.NewReader([]byte("this is not a pcap file.")))); err == nil {
		t.Fatal("accepted a non-pcap stream")
	}
}
