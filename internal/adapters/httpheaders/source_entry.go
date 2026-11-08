package httpheaders

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
)

// The existing ring stores only this closed approved metadata, never source
// payload frames. Entries retain the original kernel stamp. Timer-only closing
// counters use an explicitly missing stamp, not a fabricated kernel clock.
const MaxSourceEntryBytes = 4096
const sourceEntryHeader = 10 // kind, closed clock tag, original uint64 timestamp
const sourceCounterKind = 1
const sourceRecordKind = 2

type SourceAccounting struct {
	Projection                                              Counters
	FramesSeen, FramesFiltered, WireBytes, MatchedWireBytes uint64
}
type SourceEntry struct {
	Stamp      SourceStamp
	Accounting *SourceAccounting
	Record     *Record
}

var SourceCounterEntryBytes = sourceEntryHeader + binary.Size(SourceAccounting{})

func SourceAccountingDelta(previous, current SourceAccounting) (SourceAccounting, error) {
	return sourceAccountingArithmetic(previous, current, false)
}
func AddSourceAccounting(total, delta SourceAccounting) (SourceAccounting, error) {
	return sourceAccountingArithmetic(total, delta, true)
}
func sourceAccountingArithmetic(a, b SourceAccounting, add bool) (SourceAccounting, error) {
	var out SourceAccounting
	var left, right, result [512]byte
	n, err := binary.Encode(left[:], binary.LittleEndian, a)
	if err != nil || n > len(left) {
		return out, ErrInvalid
	}
	m, err := binary.Encode(right[:], binary.LittleEndian, b)
	if err != nil || m != n {
		return out, ErrInvalid
	}
	for i := 0; i < n; i += 8 {
		av, bv := binary.LittleEndian.Uint64(left[i:]), binary.LittleEndian.Uint64(right[i:])
		var v uint64
		if add {
			if bv > math.MaxUint64-av {
				return SourceAccounting{}, ErrInvalid
			}
			v = av + bv
		} else {
			if bv < av {
				return SourceAccounting{}, ErrInvalid
			}
			v = bv - av
		}
		binary.LittleEndian.PutUint64(result[i:], v)
	}
	if _, err = binary.Decode(result[:n], binary.LittleEndian, &out); err != nil {
		return SourceAccounting{}, ErrInvalid
	}
	return out, nil
}
func sourceHeader(kind byte, stamp SourceStamp) []byte {
	b := make([]byte, sourceEntryHeader)
	b[0] = kind
	if stamp.Clock == "monotonic" {
		b[1] = 1
	} else if stamp.Clock == "boottime" {
		b[1] = 2
	}
	binary.LittleEndian.PutUint64(b[2:], stamp.RawTimestamp)
	return b
}
func EncodeSourceAccounting(delta SourceAccounting, stamp SourceStamp) ([]byte, error) {
	if delta.FramesFiltered > delta.FramesSeen || delta.Projection.Frames != delta.FramesSeen-delta.FramesFiltered || delta.MatchedWireBytes > delta.WireBytes {
		return nil, ErrInvalid
	}
	b := sourceHeader(sourceCounterKind, stamp)
	b, err := binary.Append(b, binary.LittleEndian, delta)
	if err != nil || len(b) > MaxSourceEntryBytes {
		return nil, ErrInvalid
	}
	return b, nil
}
func EncodeSourceRecord(record ObservedRecord) ([]byte, error) {
	if !checkRecord(record.Record, record.Record.Timestamp, record.Record.Timestamp) {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(record.Record)
	if err != nil || len(raw)+sourceEntryHeader > MaxSourceEntryBytes {
		return nil, ErrInvalid
	}
	return append(sourceHeader(sourceRecordKind, record.Stamp), raw...), nil
}
func DecodeSourceEntry(data []byte) (SourceEntry, error) {
	var out SourceEntry
	if len(data) < sourceEntryHeader || len(data) > MaxSourceEntryBytes || data[1] > 2 {
		return out, ErrInvalid
	}
	out.Stamp.RawTimestamp = binary.LittleEndian.Uint64(data[2:])
	if data[1] == 1 {
		out.Stamp.Clock = "monotonic"
	} else if data[1] == 2 {
		out.Stamp.Clock = "boottime"
	}
	body := data[sourceEntryHeader:]
	switch data[0] {
	case sourceCounterKind:
		var a SourceAccounting
		if len(data) != SourceCounterEntryBytes {
			return SourceEntry{}, ErrInvalid
		}
		if _, err := binary.Decode(body, binary.LittleEndian, &a); err != nil || a.FramesFiltered > a.FramesSeen || a.Projection.Frames != a.FramesSeen-a.FramesFiltered || a.MatchedWireBytes > a.WireBytes {
			return SourceEntry{}, ErrInvalid
		}
		out.Accounting = &a
	case sourceRecordKind:
		var r Record
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || !checkRecord(r, r.Timestamp, r.Timestamp) {
			return SourceEntry{}, ErrInvalid
		}
		canonical, err := json.Marshal(r)
		if err != nil || !bytes.Equal(canonical, body) {
			return SourceEntry{}, ErrInvalid
		}
		out.Record = &r
	default:
		return SourceEntry{}, ErrInvalid
	}
	return out, nil
}
