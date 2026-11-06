package bootstrap

import (
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/httpheaders"
	"asservat.local/asservat/internal/domain/collector"
)

func (s *packetSource) sameHTTPConfig(h *collector.HTTPProjection) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpConfig == nil && h == nil || s.httpConfig != nil && h != nil && *s.httpConfig == *h
}
func (s *packetSource) observeHTTPRecordLocked(record httpheaders.ObservedRecord) {
	if s.httpFailure != nil {
		return
	}
	encoded, err := httpheaders.EncodeSourceRecord(record)
	if err == nil {
		err = s.ring.AddRecord(encoded, s.httpEntryAt, s.now())
	}
	clear(encoded)
	if err != nil {
		s.httpFailure = err
		_ = s.ring.Gap(s.now())
		return
	}
	if s.httpObserved != nil {
		s.httpObserved(record)
	}
}
func (s *packetSource) appendHTTPAccountingLocked(stamp httpheaders.SourceStamp) {
	current := s.httpAccounting
	current.Projection = s.httpProjector.SourceCounters()
	delta, err := httpheaders.SourceAccountingDelta(s.httpLastAccounting, current)
	if err != nil {
		s.httpFailure = err
		return
	}
	if delta == (httpheaders.SourceAccounting{}) {
		return
	}
	encoded, err := httpheaders.EncodeSourceAccounting(delta, stamp)
	if err == nil {
		err = s.ring.AddRecord(encoded, s.httpEntryAt, s.now())
	}
	clear(encoded)
	if err != nil {
		s.httpFailure = err
		_ = s.ring.Gap(s.now())
		return
	}
	s.httpAccounting, s.httpLastAccounting = current, current
	if s.httpGaps != nil {
		s.httpGaps(delta.Projection)
	}
}
func (s *packetSource) addHTTPFrameLocked(f gadget.Frame, now time.Time) {
	s.httpEntryAt = f.At
	s.httpAccounting.FramesSeen++
	s.httpAccounting.WireBytes += uint64(f.Wire)
	if s.ring.FilterMatch(f.Data, int(f.Wire)) {
		s.httpAccounting.MatchedWireBytes += uint64(f.Wire)
		s.httpProjector.AddObserved(f.Data, f.Wire, f.At, httpheaders.SourceStamp{RawTimestamp: f.RawTimestamp, Clock: f.Clock})
	} else {
		s.httpAccounting.FramesFiltered++
	}
	s.appendHTTPAccountingLocked(httpheaders.SourceStamp{RawTimestamp: f.RawTimestamp, Clock: f.Clock})
	if s.httpFailure != nil {
		s.stopLocked(s.httpFailure)
	}
}
func (s *packetSource) closeHTTPLocked(until time.Time) {
	if s.httpClosed {
		return
	}
	s.httpClosed = true
	s.httpEntryAt = until
	s.httpProjector.CloseSource(until, s.httpLost)
	s.appendHTTPAccountingLocked(httpheaders.SourceStamp{})
}
