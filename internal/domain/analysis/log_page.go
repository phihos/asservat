package analysis

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// LogEntry carries exact saved bytes. Public presentation chooses UTF-8 text or
// canonical base64; neither alternative changes the underlying bytes.
type LogEntry struct {
	Origin       artifact.LogOrigin
	Fragment     uint64
	Line         uint64
	Offset       uint64
	LineOffset   uint64
	Continuation bool
	EndLine      bool
	SourceTime   *string
	Data         string
}

type LogPage struct {
	Version                                artifact.Digest
	PodUID                                 string
	WindowStart, WindowEnd                 time.Time
	StartFragment, NextFragment            uint64
	StartOffset, NextOffset                uint16
	HasNext                                bool
	Entries                                []LogEntry
	OriginCount                            uint16
	CompleteOrigins, PartialOrigins        uint16
	UnavailableOrigins                     uint16
	TotalFragments, SourceBytes            uint64
	UnknownTimestampOrigins, GappedOrigins uint16
}

func (p LogPage) ValidShape(s LogSelection, version artifact.Digest, pod string) bool {
	if !s.Matches(version) || p.Version != version || p.PodUID != pod || p.WindowStart.IsZero() || p.WindowEnd.Before(p.WindowStart) || p.StartFragment != s.Fragment || p.StartOffset != s.Offset || p.Entries == nil || len(p.Entries) > s.Limit || p.OriginCount == 0 || p.OriginCount > artifact.LogMaxOrigins || uint32(p.CompleteOrigins)+uint32(p.PartialOrigins)+uint32(p.UnavailableOrigins) != uint32(p.OriginCount) || p.GappedOrigins > p.OriginCount || p.UnknownTimestampOrigins > p.OriginCount || p.SourceBytes > uint64(artifact.LogNativeLimit) || p.TotalFragments > p.SourceBytes || p.StartFragment > p.TotalFragments || p.StartFragment == p.TotalFragments && p.StartOffset != 0 {
		return false
	}
	if len(p.Entries) == 0 && (p.TotalFragments != 0 || s.Fragment != 0 || s.Offset != 0) {
		return false
	}
	if p.HasNext {
		if len(p.Entries) == 0 || p.NextFragment >= p.TotalFragments || p.NextOffset >= artifact.LogMaxFragmentBytes || p.NextFragment < p.StartFragment || p.NextFragment == p.StartFragment && p.NextOffset <= p.StartOffset {
			return false
		}
	} else if p.NextFragment != 0 || p.NextOffset != 0 {
		return false
	}
	if (p.TotalFragments == 0) != (p.SourceBytes == 0) {
		return false
	}
	var previous LogEntry
	var previousBytes, nativeOffset uint64
	for i, e := range p.Entries {
		if !e.Origin.WellFormed() || e.Origin.OriginID >= p.OriginCount || e.Fragment < p.StartFragment || e.Fragment >= p.TotalFragments || e.Line == 0 || e.Line > p.SourceBytes || e.LineOffset > e.Offset || e.Offset > p.SourceBytes || e.Continuation != (e.LineOffset > 0) {
			return false
		}
		b, err := base64.StdEncoding.Strict().DecodeString(e.Data)
		valid := err == nil && len(b) > 0 && len(b) <= LogPageFragmentBytes && base64.StdEncoding.EncodeToString(b) == e.Data
		size := uint64(len(b))
		newline := bytes.IndexByte(b, '\n')
		if newline >= 0 && (newline != len(b)-1 || !e.EndLine) || e.EndLine && newline < 0 || size > p.SourceBytes-e.Offset {
			valid = false
		}
		clear(b)
		if !valid {
			return false
		}
		if e.SourceTime != nil {
			if len(*e.SourceTime) > 64 {
				return false
			}
			at, err := time.Parse(time.RFC3339Nano, *e.SourceTime)
			if err != nil || at.Before(p.WindowStart) || at.After(p.WindowEnd) {
				return false
			}
		}
		if i == 0 {
			if e.Fragment != p.StartFragment || e.Offset < uint64(p.StartOffset) || e.LineOffset < uint64(p.StartOffset) {
				return false
			}
			nativeOffset = uint64(p.StartOffset)
		} else {
			if e.Fragment == previous.Fragment {
				if !sameLogOrigin(e.Origin, previous.Origin) || previous.EndLine {
					return false
				}
			} else {
				if e.Fragment != previous.Fragment+1 {
					return false
				}
				nativeOffset = 0
			}
			if e.Origin.OriginID == previous.Origin.OriginID {
				if !sameLogOrigin(e.Origin, previous.Origin) || e.Offset != previous.Offset+previousBytes {
					return false
				}
				if previous.EndLine {
					if e.Line != previous.Line+1 || e.LineOffset != 0 {
						return false
					}
				} else if e.Line != previous.Line || e.LineOffset != previous.LineOffset+previousBytes || !sameLogTime(e.SourceTime, previous.SourceTime) {
					return false
				}
			} else if e.Fragment == previous.Fragment || e.Origin.OriginID <= previous.Origin.OriginID || e.Offset != 0 || e.Line != 1 || e.LineOffset != 0 {
				return false
			}
		}
		nativeOffset += size
		if nativeOffset > artifact.LogMaxFragmentBytes {
			return false
		}
		previous, previousBytes = e, size
	}
	if len(p.Entries) > 0 {
		if p.HasNext {
			sameFragment := p.NextFragment == previous.Fragment && uint64(p.NextOffset) == nativeOffset && p.NextOffset > 0 && p.NextOffset < artifact.LogMaxFragmentBytes && !previous.EndLine
			nextFragment := p.NextFragment == previous.Fragment+1 && p.NextOffset == 0
			if !sameFragment && !nextFragment {
				return false
			}
		} else if previous.Fragment+1 != p.TotalFragments || p.OriginCount == 1 && previous.Offset+previousBytes != p.SourceBytes {
			return false
		}
	}
	encoded, err := json.Marshal(p)
	defer clear(encoded)
	if err != nil {
		return false
	}
	cost := len(encoded)
	for _, e := range p.Entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return false
		}
		cost += e.EncodedUpperBound() - len(raw)
		clear(raw)
		if cost > LogQueryPageBytes {
			return false
		}
	}
	return cost <= LogQueryPageBytes
}

func (p LogPage) Next(s LogSelection, version artifact.Digest) string {
	if !p.HasNext || p.Version != version || p.StartFragment != s.Fragment || p.StartOffset != s.Offset {
		return ""
	}
	return s.Cursor(p.NextFragment, p.NextOffset, version)
}

func CloneLogPage(p LogPage) LogPage {
	if p.Entries != nil {
		p.Entries = append([]LogEntry{}, p.Entries...)
		for i := range p.Entries {
			e := &p.Entries[i]
			if e.SourceTime != nil {
				v := *e.SourceTime
				e.SourceTime = &v
			}
			if e.Origin.RuntimeID != nil {
				v := *e.Origin.RuntimeID
				e.Origin.RuntimeID = &v
			}
			if e.Origin.RestartCount != nil {
				v := *e.Origin.RestartCount
				e.Origin.RestartCount = &v
			}
		}
	}
	return p
}

func (p *LogPage) Clear() {
	clear(p.Entries)
	*p = LogPage{}
}

// EncodedUpperBound covers both the private base64 entry and public UTF-8 text.
// Go JSON can escape one source byte to six ASCII bytes. The additional128
// bytes cover closed public key/wrapper names; the page retains its separate
// 4KiB enclosing-envelope reserve. This is a bound, not measured wire cost.
func (e LogEntry) EncodedUpperBound() int {
	raw, err := base64.StdEncoding.Strict().DecodeString(e.Data)
	if err != nil || len(raw) < 1 || len(raw) > LogPageFragmentBytes || base64.StdEncoding.EncodeToString(raw) != e.Data {
		clear(raw)
		return ContextResultBytes + 1
	}
	size := len(raw)
	clear(raw)
	encoded, err := json.Marshal(e)
	if err != nil {
		return ContextResultBytes + 1
	}
	defer clear(encoded)
	return len(encoded) + 6*size + 128
}
func sameLogTime(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func sameLogOrigin(a, b artifact.LogOrigin) bool {
	return a.Record == b.Record && a.OriginID == b.OriginID && a.ContainerKind == b.ContainerKind && a.ContainerName == b.ContainerName && a.Source == b.Source && a.Stream == b.Stream && sameLogTime(a.RuntimeID, b.RuntimeID) && (a.RestartCount == nil && b.RestartCount == nil || a.RestartCount != nil && b.RestartCount != nil && *a.RestartCount == *b.RestartCount)
}
