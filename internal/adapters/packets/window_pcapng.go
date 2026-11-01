package packets

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// PacketIterator yields already sanitized source records, without borrowing ring
// memory. Encoding performs no new acquisition, observation debit or filtering.
type PacketIterator interface{ Next(*RingPacket) error }

type fixedPacketOutput struct {
	data []byte
	used int
}

func (b *fixedPacketOutput) Write(p []byte) (int, error) {
	if len(p) > len(b.data)-b.used {
		return 0, ErrInvalid
	}
	n := copy(b.data[b.used:], p)
	b.used += n
	return n, nil
}

// EncodeWindow owns exactly maxBytes of native output storage. The caller must
// reserve that storage separately from the iterator's frozen copy, and retain
// both charges until encoding/upload have joined and the storage is erased.
func EncodeWindow(ctx context.Context, records PacketIterator, maxBytes int, started, ended time.Time) (out []byte, counters Counters, err error) {
	if ctx == nil || ctx.Err() != nil || records == nil || maxBytes < 4096 || maxBytes > 8<<20 || started.IsZero() || ended.Before(started) {
		return nil, counters, ErrInvalid
	}
	b := &fixedPacketOutput{data: make([]byte, maxBytes)}
	defer func() {
		if err != nil {
			clear(b.data)
		}
	}()
	w, err := pcapgo.NewNgWriterInterface(b, pcapgo.NgInterface{Name: "pod", Description: "asservat saved networkHeaders source window", LinkType: layers.LinkTypeEthernet, SnapLength: Snaplen, TimestampResolution: 9}, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "asservat networkHeaders"}})
	if err != nil {
		return nil, counters, err
	}
	if err = w.Flush(); err != nil {
		return nil, counters, err
	}
	var p RingPacket
	for {
		if err = ctx.Err(); err != nil {
			return nil, counters, err
		}
		err = records.Next(&p)
		if errors.Is(err, io.EOF) {
			err = nil
			break
		}
		if err != nil {
			return nil, counters, err
		}
		if p.Length < 1 || p.Length > Snaplen || p.Wire < uint32(p.Length) || p.At.Before(started) || p.At.After(ended) {
			return nil, counters, ErrInvalid
		}
		counters.Seen++
		block := 32 + (p.Length+3)&^3
		if b.used+block+statsReserve > len(b.data) {
			counters.OutputFull++
			continue
		}
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: p.At, CaptureLength: p.Length, Length: int(p.Wire)}, p.Header[:p.Length]); err != nil {
			return nil, counters, err
		}
		if err = w.Flush(); err != nil {
			return nil, counters, err
		}
		counters.Retained++
		counters.WireBytes += uint64(p.Wire)
	}
	if err = w.WriteInterfaceStats(0, pcapgo.NgInterfaceStatistics{LastUpdate: ended, StartTime: started, EndTime: ended, PacketsReceived: counters.Seen, PacketsDropped: counters.OutputFull}); err != nil {
		return nil, counters, err
	}
	if err = w.Flush(); err != nil {
		return nil, counters, err
	}
	return b.data[:b.used], counters, nil
}
