package agent

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

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
