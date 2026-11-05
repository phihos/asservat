// Package logs implements only the bounded saved raw-log format. These records
// and successful decoding confer no source, collection or disclosure authority.
package logs

import (
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"time"
)

type Visitor struct {
	Header   func(artifact.LogHeader) error
	Origin   func(artifact.LogOrigin) error
	Fragment func(artifact.LogFragment) error
	Coverage func(artifact.LogCoverage) error
}
type state struct {
	header                                                artifact.LogHeader
	origin                                                *artifact.LogOrigin
	finished                                              uint16
	footer                                                bool
	bytes, fragments, lines                               uint64
	sourceBytes, sourceFragments, sourceLines, lineOffset uint64
	line                                                  uint64
	sourceTime                                            *string
	unknownTime                                           bool
	origins                                               map[string]bool
	containers                                            map[string]bool
}

func sameTime(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func hasGap(c artifact.LogCoverage, g string) bool {
	for _, v := range c.Gaps {
		if v == g {
			return true
		}
	}
	return false
}
func (s *state) consume(v any) error {
	if s.footer {
		return artifact.ErrInvalid
	}
	switch r := v.(type) {
	case artifact.LogHeader:
		if s.header.Record != "" || !r.WellFormed() {
			return artifact.ErrInvalid
		}
		s.header = r
		s.origins = map[string]bool{}
		s.containers = map[string]bool{}
	case artifact.LogOrigin:
		if s.header.Record == "" || s.origin != nil || s.finished >= s.header.Origins || r.OriginID != s.finished || !r.WellFormed() {
			return artifact.ErrInvalid
		}
		k := r.ContainerKind + "/" + r.ContainerName
		if s.origins[k+"/"+r.Source] {
			return artifact.ErrInvalid
		}
		s.origins[k+"/"+r.Source] = true
		s.containers[k] = true
		if len(s.containers) > 64 {
			return artifact.ErrLimit
		}
		s.origin = &r
		s.sourceBytes = 0
		s.sourceFragments = 0
		s.sourceLines = 0
		s.lineOffset = 0
		s.line = 1
		s.sourceTime = nil
		s.unknownTime = false
	case artifact.LogFragment:
		if s.origin == nil || r.OriginID != s.origin.OriginID || r.Line != s.line || r.Offset != s.sourceBytes || r.LineOffset != s.lineOffset {
			return artifact.ErrInvalid
		}
		data, err := r.Bytes()
		if err != nil {
			return err
		}
		defer clear(data)
		if r.SourceTime != nil {
			at, _ := time.Parse(time.RFC3339Nano, *r.SourceTime)
			if at.Before(s.header.WindowStart) || at.After(s.header.WindowEnd) {
				return artifact.ErrInvalid
			}
			prefix := *r.SourceTime + " "
			if r.LineOffset < uint64(len(prefix)) {
				start := int(r.LineOffset)
				n := len(prefix) - start
				if n > len(data) {
					n = len(data)
				}
				if !bytes.Equal(data[:n], []byte(prefix[start:start+n])) {
					return artifact.ErrInvalid
				}
			}
			if r.EndLine && r.LineOffset+uint64(len(data)) < uint64(len(prefix)) {
				return artifact.ErrInvalid
			}
		}

		if s.lineOffset == 0 {
			s.sourceLines++
			if r.SourceTime == nil {
				s.sourceTime = nil
			} else {
				v := *r.SourceTime
				s.sourceTime = &v
			}
		} else if !sameTime(r.SourceTime, s.sourceTime) {
			return artifact.ErrInvalid
		}
		if r.SourceTime == nil {
			s.unknownTime = true
		}
		s.sourceBytes += uint64(len(data))
		s.sourceFragments++
		if s.sourceBytes > uint64(artifact.LogNativeLimit) {
			return artifact.ErrLimit
		}
		if r.EndLine {
			s.line++
			s.lineOffset = 0
			s.sourceTime = nil
		} else {
			s.lineOffset += uint64(len(data))
		}
	case artifact.LogCoverage:
		if s.origin == nil || !r.WellFormed() || r.OriginID != s.origin.OriginID || r.SourceBytes != s.sourceBytes || r.Fragments != s.sourceFragments || r.Lines != s.sourceLines || s.unknownTime && !hasGap(r, "timestampUnknown") || hasGap(r, "outputFull") && r.FetchOutcome != "partial" {
			return artifact.ErrInvalid
		}
		if s.lineOffset > 0 && s.sourceTime != nil && s.lineOffset < uint64(len(*s.sourceTime)+1) {
			return artifact.ErrInvalid
		}
		s.bytes += s.sourceBytes
		s.fragments += s.sourceFragments
		s.lines += s.sourceLines
		s.finished++
		s.origin = nil
	case artifact.LogFooter:
		if s.header.Record == "" || s.origin != nil || s.finished != s.header.Origins || !r.WellFormed() || r.Origins != s.finished || r.SourceBytes != s.bytes || r.Fragments != s.fragments || r.Lines != s.lines {
			return artifact.ErrInvalid
		}
		s.footer = true
	default:
		return artifact.ErrInvalid
	}
	return nil
}
