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
	header := make([]byte, 24)
	if _, err := io.ReadFull(src, header); err != nil {
		if err == io.EOF {
			return nil // the tool wrote nothing
		}
		return err
	}
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(header) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.BigEndian
	default:
		return errors.New("not a pcap stream")
	}
	linkType := order.Uint32(header[20:])
	if _, err := dst.Write(header); err != nil {
		return err
	}
	record := make([]byte, 16)
	var packet []byte
	for {
		if _, err := io.ReadFull(src, record); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil // interrupted between or within records
			}
			return err
		}
		n := order.Uint32(record[8:])
		if n > 1<<18 { // tcpdump's largest snap length
			return errors.New("corrupt pcap record")
		}
		if cap(packet) < int(n) {
			packet = make([]byte, n)
		}
		packet = packet[:n]
		if _, err := io.ReadFull(src, packet); err != nil {
			return nil
		}
		keep := min(headerLength(linkType, packet), len(packet))
		order.PutUint32(record[8:], uint32(keep))
		if _, err := dst.Write(record); err != nil {
			return err
		}
		if _, err := dst.Write(packet[:keep]); err != nil {
			return err
		}
	}
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
