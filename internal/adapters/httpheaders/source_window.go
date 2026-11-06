package httpheaders

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/artifact"
)

// EncodeSourceWindow consumes an already frozen approved-metadata ring. Counter
// deltas are selected by event completion time, rows by their original request
// time. It does not flush the source or claim a finite-parser terminal state.
func EncodeSourceWindow(ctx context.Context, entries packets.PacketIterator, limits Limits, maxBytes int64, from, until time.Time, historyComplete bool) ([]byte, packets.Counters, bool, error) {
	var frames packets.Counters
	if ctx == nil || entries == nil || limits.Validate() != nil || maxBytes < 1 || maxBytes > artifact.HTTPHeadersNativeLimit || from.IsZero() || until.Before(from) {
		return nil, frames, false, ErrInvalid
	}
	pr := Projection{Format: artifact.HTTPHeadersFormat, Protocol: "http1", StartedAt: from, EndedAt: until, Limits: LimitsRecord{limits.MaxFlows, limits.MaxHeaderBytes, limits.MaxFlowBytes, limits.MaxTotalBytes, int64(limits.IdleTimeout / time.Second), Snaplen}, Records: []Record{}, SourceWindow: &SourceWindowCoverage{CounterScope: "event-window", HistoryComplete: historyComplete}}
	var total SourceAccounting
	var packet packets.RingPacket
	used := int64(envelopeBytes)
	for {
		if err := ctx.Err(); err != nil {
			return nil, frames, false, err
		}
		err := entries.Next(&packet)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, frames, false, err
		}
		if packet.Length < 1 || packet.Length > MaxSourceEntryBytes || packet.At.Before(from) || packet.At.After(until) {
			return nil, frames, false, ErrInvalid
		}
		entry, err := DecodeSourceEntry(packet.Header[:packet.Length])
		if err != nil {
			return nil, frames, false, err
		}
		if entry.Accounting != nil {
			total, err = AddSourceAccounting(total, *entry.Accounting)
			if err != nil {
				return nil, frames, false, err
			}
			continue
		}
		r := *entry.Record
		if r.Timestamp.Before(from) || r.Timestamp.After(until) {
			pr.SourceWindow.WindowClippedRecords++
			continue
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			return nil, frames, false, err
		}
		if used+int64(len(encoded))+1 > maxBytes || len(pr.Records) >= maxRecords {
			pr.Counters.RecordsDropped++
			continue
		}
		used += int64(len(encoded)) + 1
		pr.Records = append(pr.Records, r)
	}
	if total.FramesFiltered > total.FramesSeen || total.MatchedWireBytes > total.WireBytes || total.Projection.Frames != total.FramesSeen-total.FramesFiltered {
		return nil, frames, false, ErrInvalid
	}
	pr.SourceWindow.FramesSeen = total.FramesSeen
	pr.SourceWindow.FramesFiltered = total.FramesFiltered
	pr.SourceWindow.ObservedWireBytes = total.WireBytes
	dropped := pr.Counters.RecordsDropped
	pr.Counters = total.Projection
	// Record counters describe actual retained rows, not whole-source totals or
	// event-window completions whose requests lie outside this window.
	pr.Counters.Records = uint64(len(pr.Records))
	pr.Counters.PartialRecords = 0
	pr.Counters.RecordsDropped += dropped
	pr.Counters.OpenAtCloseFlows = 0
	for _, r := range pr.Records {
		if r.Partial {
			pr.Counters.PartialRecords++
		}
	}
	sort.SliceStable(pr.Records, func(i, j int) bool { return pr.Records[i].Timestamp.Before(pr.Records[j].Timestamp) })
	frames = packets.Counters{Seen: total.FramesSeen, Filtered: total.FramesFiltered, Retained: total.FramesSeen - total.FramesFiltered, WireBytes: total.MatchedWireBytes}
	b, err := pr.Encode()
	if int64(len(b)) > maxBytes {
		return nil, frames, false, artifact.ErrLimit
	}
	return b, frames, historyComplete && pr.Counters.RecordsDropped == 0 && pr.SourceWindow.WindowClippedRecords == 0, err
}
