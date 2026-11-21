package agent

import (
	"encoding/binary"
	"errors"
	"io"
)

// headersOnly rewrites a pcap stream so that every packet ends after its
// transport header. A fixed snap length cannot do that: header sizes vary, so
// it either cuts headers or keeps the first payload bytes.
func headersOnly(src io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(stripPayload(pw, src)) }()
	return pr
}

func stripPayload(dst io.Writer, src io.Reader) error {
	packets, err := newHeaderReader(src)
	if err != nil || packets == nil {
		return err
	}
	if _, err := dst.Write(packets.header); err != nil {
		return err
	}
	for {
		record, packet, err := packets.next()
		if err != nil || record == nil {
			return err
		}
		if _, err := dst.Write(record); err != nil {
			return err
		}
		if _, err := dst.Write(packet); err != nil {
			return err
		}
	}
}

// headerReader reads a pcap stream packet by packet, each cut after its
// transport header.
type headerReader struct {
	src      io.Reader
	header   []byte // the file header
	order    binary.ByteOrder
	linkType uint32
	record   []byte
	packet   []byte
}

// newHeaderReader returns nil for a stream that ends before its file header:
// the tool wrote nothing.
func newHeaderReader(src io.Reader) (*headerReader, error) {
	r := &headerReader{src: src, header: make([]byte, 24), record: make([]byte, 16)}
	if _, err := io.ReadFull(src, r.header); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	switch binary.LittleEndian.Uint32(r.header) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		r.order = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		r.order = binary.BigEndian
	default:
		return nil, errors.New("not a pcap stream")
	}
	r.linkType = r.order.Uint32(r.header[20:])
	return r, nil
}

// next returns the next packet's record header and its bytes up to the end
// of the transport header, both valid until the following call. It returns
// nil at the end of the stream, also when that interrupts a packet.
func (r *headerReader) next() (record, packet []byte, err error) {
	if _, err := io.ReadFull(r.src, r.record); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	n := r.order.Uint32(r.record[8:])
	if n > 1<<18 { // tcpdump's largest snap length
		return nil, nil, errors.New("corrupt pcap record")
	}
	if cap(r.packet) < int(n) {
		r.packet = make([]byte, n)
	}
	r.packet = r.packet[:n]
	if _, err := io.ReadFull(r.src, r.packet); err != nil {
		return nil, nil, nil
	}
	keep := min(headerLength(r.linkType, r.packet), len(r.packet))
	r.order.PutUint32(r.record[8:], uint32(keep))
	return r.record, r.packet[:keep], nil
}

// headerLength returns how many bytes of a packet are link, network and
// transport headers. A packet it cannot parse keeps its link header only.
func headerLength(linkType uint32, p []byte) int {
	var link int
	var proto uint16
	switch {
	case linkType == 276 && len(p) >= 20: // Linux cooked v2 (tcpdump -i any)
		link, proto = 20, binary.BigEndian.Uint16(p)
	case linkType == 113 && len(p) >= 16: // Linux cooked v1
		link, proto = 16, binary.BigEndian.Uint16(p[14:])
	case linkType == 1 && len(p) >= 14: // Ethernet
		link, proto = 14, binary.BigEndian.Uint16(p[12:])
	default:
		return 0
	}
	ip := p[link:]
	var network int
	var next byte
	switch {
	case proto == 0x0800 && len(ip) >= 20:
		network, next = int(ip[0]&0x0f)*4, ip[9]
		if binary.BigEndian.Uint16(ip[6:])&0x1fff != 0 {
			return link + network // a later fragment has no transport header
		}
	case proto == 0x86dd && len(ip) >= 40:
		network, next = 40, ip[6]
	case proto == 0x0806:
		return len(p) // ARP has no payload
	default:
		return link
	}
	transport := ip[min(network, len(ip)):]
	switch {
	case next == 6 && len(transport) >= 13: // TCP: data offset
		return link + network + int(transport[12]>>4)*4
	case next == 17 || next == 1 || next == 58: // UDP, ICMP, ICMPv6
		return link + network + 8
	}
	return link + network
}
