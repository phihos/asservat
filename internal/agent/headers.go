package agent

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strconv"
)

// headerSnap is the most that the headers of a packet take as dissect reads
// them: the link header of tcpdump's "any" interface (20 bytes), an IPv4
// header with all its options (60) and a TCP header with all of its (60).
const headerSnap = 20 + 60 + 60

// tcpdumpArgs are the arguments of nsenter for a tcpdump in the network
// namespace of a process that writes the packets of a filter to its
// standard output. Without payload it hands over the first headerSnap bytes
// of each packet only, so that the payload of the pod's traffic is not
// copied out of the kernel and through a pipe just to be dropped here.
func tcpdumpArgs(pid int, filter string, payload bool) []string {
	args := []string{"-t", strconv.Itoa(pid), "-n", "tcpdump", "-Z", "root", "-i", "any", "-U", "-w", "-"}
	if !payload {
		args = append(args, "-s", strconv.Itoa(headerSnap))
	}
	return append(args, withoutOwnTraffic(filter))
}

// headersOnly rewrites a pcap stream so that every packet ends after its
// transport header. A snap length alone cannot do that: header sizes vary, so
// it either cuts headers or keeps the first payload bytes.
func headersOnly(src io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(stripPayload(pw, src)) }()
	return pr
}

func stripPayload(dst io.Writer, src io.Reader) error {
	packets, err := newPacketReader(src)
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

// packetReader reads a pcap stream packet by packet, each cut after its
// transport header unless payload is set.
type packetReader struct {
	payload  bool
	src      io.Reader
	header   []byte // the file header
	order    binary.ByteOrder
	linkType uint32
	record   []byte
	packet   []byte
}

// newPacketReader returns nil for a stream that ends before its file header:
// the tool wrote nothing. The stream is read through a buffer, as much at a
// time as it has: a pipe would otherwise be read twice per packet.
func newPacketReader(src io.Reader) (*packetReader, error) {
	r := &packetReader{src: bufio.NewReaderSize(src, 64<<10), header: make([]byte, 24), record: make([]byte, 16)}
	if _, err := io.ReadFull(r.src, r.header); err != nil {
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

// next returns the next packet's record header and its kept bytes, both
// valid until the following call. It returns
// nil at the end of the stream, also when that interrupts a packet.
func (r *packetReader) next() (record, packet []byte, err error) {
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
	if r.payload {
		return r.record, r.packet, nil
	}
	keep := min(headerLength(r.linkType, r.packet), len(r.packet))
	r.order.PutUint32(r.record[8:], uint32(keep))
	return r.record, r.packet[:keep], nil
}

// headerLength returns how many bytes of a packet are link, network and
// transport headers. A packet it cannot parse keeps its link header only.
func headerLength(linkType uint32, p []byte) int { return dissect(linkType, p).headers }

// packetInfo is what the headers of a packet say.
type packetInfo struct {
	headers  int        // bytes of link, network and transport headers
	protocol string     // "tcp" or "udp"; empty for anything else
	src, dst netip.Addr // valid for IP packets
	srcPort  uint16
	dstPort  uint16
	// opens marks a TCP packet that opens a connection: its sender is the client.
	opens bool
}

func dissect(linkType uint32, p []byte) packetInfo {
	var info packetInfo
	var proto uint16
	switch {
	case linkType == 276 && len(p) >= 20: // Linux cooked v2 (tcpdump -i any)
		info.headers, proto = 20, binary.BigEndian.Uint16(p)
	case linkType == 113 && len(p) >= 16: // Linux cooked v1
		info.headers, proto = 16, binary.BigEndian.Uint16(p[14:])
	case linkType == 1 && len(p) >= 14: // Ethernet
		info.headers, proto = 14, binary.BigEndian.Uint16(p[12:])
	default:
		return info
	}
	ip := p[info.headers:]
	var network int
	var next byte
	switch {
	case proto == 0x0800 && len(ip) >= 20:
		network, next = int(ip[0]&0x0f)*4, ip[9]
		info.src, info.dst = netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
		if binary.BigEndian.Uint16(ip[6:])&0x1fff != 0 {
			info.headers += network // a later fragment has no transport header
			return info
		}
	case proto == 0x86dd && len(ip) >= 40:
		network, next = 40, ip[6]
		info.src, info.dst = netip.AddrFrom16([16]byte(ip[8:24])), netip.AddrFrom16([16]byte(ip[24:40]))
	case proto == 0x0806:
		info.headers = len(p) // ARP has no payload
		return info
	default:
		return info
	}
	transport := ip[min(network, len(ip)):]
	info.headers += network
	switch {
	case next == 6 && len(transport) >= 14: // TCP: data offset, flags
		info.headers += int(transport[12]>>4) * 4
		info.protocol, info.opens = "tcp", transport[13]&0x12 == 0x02 // SYN without ACK
	case next == 6 && len(transport) >= 13:
		info.headers += int(transport[12]>>4) * 4
	case next == 17 && len(transport) >= 8:
		info.headers += 8
		info.protocol = "udp"
	case next == 17 || next == 1 || next == 58: // UDP, ICMP, ICMPv6
		info.headers += 8
	}
	if info.protocol != "" {
		info.srcPort, info.dstPort = binary.BigEndian.Uint16(transport), binary.BigEndian.Uint16(transport[2:])
	}
	return info
}
