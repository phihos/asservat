package integration

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/gopacket/gopacket/pcapgo"
)

func installedPacketQueryMatchesNative(page query.PacketQueryResult, native []byte, fields string) error {
	selection := installedPacketQuerySelection()
	if !page.Valid(selection, artifact.RawPCAPNGArtifact) {
		return errors.New("invalid raw page")
	}
	reader, err := pcapgo.NewNgReader(bytes.NewReader(native), pcapgo.NgReaderOptions{})
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(fields, "\n"), "\n")
	var expected [][]query.PacketQueryCell
	var scannedBytes int64
	var scannedPackets uint32
	stopped := false
	for i, line := range lines {
		f := strings.Split(line, "\t")
		if len(f) != 16 || f[0] != strconv.Itoa(i+1) {
			return errors.New("tshark original ordinal/field shape")
		}
		frame, ci, e := reader.ReadPacketData()
		if e != nil {
			return e
		}
		cap, e := strconv.ParseUint(f[2], 10, 32)
		wire, x := strconv.ParseUint(f[3], 10, 32)
		at, y := installedPacketEpoch(f[1])
		if e != nil || x != nil || y != nil || int(cap) != len(frame) || ci.CaptureLength != len(frame) || ci.Length != int(wire) || !at.Equal(ci.Timestamp) {
			return errors.New("native/tshark captured/wire length or timestamp differ")
		}
		if stopped {
			continue
		}
		scannedBytes += int64(len(frame))
		scannedPackets++
		srcPort, e1 := strconv.ParseUint(f[8], 10, 16)
		dstPort, e2 := strconv.ParseUint(f[9], 10, 16)
		if e1 != nil || e2 != nil || srcPort != 8080 && dstPort != 8080 {
			continue
		}
		number := func(n uint32) query.PacketQueryCell { return query.PacketQueryCell{Number: &n} }
		text := func(s string) query.PacketQueryCell { return query.PacketQueryCell{Text: &s} }
		row := make([]query.PacketQueryCell, 16)
		row[0] = number(uint32(i + 1))
		row[1] = text(at.UTC().Format(time.RFC3339Nano))
		row[2] = number(uint32(cap))
		row[3] = number(uint32(wire))
		row[15] = text(hex.EncodeToString(frame[:min(64, len(frame))]))
		source, dest, ipHeader := f[4], f[5], 40
		if source == "" {
			source, dest = f[6], f[7]
		} else {
			ipHeader, _ = strconv.Atoi(f[14])
		}
		tcpHeader, _ := strconv.Atoi(f[15])
		complete := ipHeader >= 20 && ipHeader <= 60 && tcpHeader >= 20 && tcpHeader <= 60 && len(frame) >= 14+ipHeader+tcpHeader
		if complete {
			a, e1 := netip.ParseAddr(source)
			b, e2 := netip.ParseAddr(dest)
			if e1 != nil || e2 != nil {
				return errors.New("complete TCP address missing")
			}
			row[4], row[5] = text(a.Unmap().String()), text(b.Unmap().String())
			row[6], row[7] = number(uint32(srcPort)), number(uint32(dstPort))
			row[8] = text("TCP")
			for j, column := range []int{10, 11, 12, 13} {
				base := 10
				if column == 10 {
					base = 0
				}
				n, e := strconv.ParseUint(f[column], base, 32)
				if e != nil {
					return fmt.Errorf("numeric tshark TCP column%d", column)
				}
				row[9+j] = number(uint32(n))
			}
		}
		expected = append(expected, row)
		if len(expected) == selection.MaxPackets {
			stopped = true
		}
	}
	if _, _, err = reader.ReadPacketData(); !errors.Is(err, io.EOF) {
		return errors.New("native EOF mismatch")
	}
	if !reflect.DeepEqual(page.Rows, expected) || page.ScannedBytes != scannedBytes || page.ScannedPackets != scannedPackets || page.RowLimitReached != (len(expected) == selection.MaxPackets) || page.ScanLimitReached || page.OutputLimitReached {
		return fmt.Errorf("page differs rows%d/%d scan%d/%d packets%d/%d limits%t/%t/%t", len(page.Rows), len(expected), page.ScannedBytes, scannedBytes, page.ScannedPackets, scannedPackets, page.RowLimitReached, page.ScanLimitReached, page.OutputLimitReached)
	}
	return nil
}
func installedPacketEpoch(s string) (time.Time, error) {
	seconds, fraction, _ := strings.Cut(s, ".")
	n, e := strconv.ParseInt(seconds, 10, 64)
	if e != nil || len(fraction) > 9 {
		return time.Time{}, errors.New("invalid tshark epoch")
	}
	fraction += strings.Repeat("0", 9-len(fraction))
	nano, e := strconv.ParseInt(fraction, 10, 64)
	if e != nil {
		return time.Time{}, e
	}
	return time.Unix(n, nano).UTC(), nil
}
