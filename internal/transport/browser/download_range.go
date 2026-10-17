// Package browser adapts browser/HTTP requests; it holds no collection authority.
package browser

import (
	"asservat.local/asservat/internal/domain/artifact"
	"errors"
	"strconv"
	"strings"
)

var (
	errPrecondition = errors.New("native version precondition failed")
	errRange        = errors.New("invalid or unsatisfiable native byte range")
	errConditional  = errors.New("invalid native conditional header")
	errNotModified  = errors.New("native representation not modified")
)

type nativeRange struct {
	Offset, Length int64
	Partial        bool
}

// The transport selects bytes before asking the application to reserve them.
// This parser never authorizes access. In particular an If-Range miss selects
// the FULL representation, which must then fit fresh full-response authority.
func selectNativeRange(size int64, etag, rangeHeader, ifMatch, ifRange string) (nativeRange, error) {
	full := nativeRange{Length: size}
	if size < 0 || size > artifact.MaxNativeBytes || !strongETag(etag) {
		return nativeRange{}, errConditional
	}
	if len(ifMatch) > 128 || len(ifRange) > 128 {
		return nativeRange{}, errConditional
	}
	if ifMatch != "" {
		matched, err := matchETags(ifMatch, etag)
		if err != nil {
			return nativeRange{}, err
		}
		if !matched {
			return nativeRange{}, errPrecondition
		}
	}
	if rangeHeader == "" {
		return full, nil
	}
	if ifRange != "" && strings.TrimSpace(ifRange) != etag {
		// A date cannot match: this endpoint does not supply a Last-Modified
		// validator. A weak tag never matches a strong If-Range comparison.
		return full, nil
	}
	if len(rangeHeader) > 128 {
		return nativeRange{}, errRange
	}
	unit, offsets, ok := strings.Cut(strings.TrimSpace(rangeHeader), "=")
	if !ok || !httpToken(unit) {
		return nativeRange{}, errRange
	}
	if !strings.EqualFold(unit, "bytes") {
		return full, nil
	}
	if strings.Contains(offsets, ",") || size == 0 {
		return nativeRange{}, errRange
	}
	first, last, ok := strings.Cut(offsets, "-")
	if !ok {
		return nativeRange{}, errRange
	}
	if first == "" {
		n, err := decimal(last)
		if err != nil || n == 0 {
			return nativeRange{}, errRange
		}
		if n > size {
			n = size
		}
		return nativeRange{Offset: size - n, Length: n, Partial: true}, nil
	}
	start, err := decimal(first)
	if err != nil || start >= size {
		return nativeRange{}, errRange
	}
	end := size - 1
	if last != "" {
		n, err := decimal(last)
		if err != nil || n < start {
			return nativeRange{}, errRange
		}
		if n < end {
			end = n
		}
	}
	return nativeRange{Offset: start, Length: end - start + 1, Partial: true}, nil
}

func decimal(s string) (int64, error) {
	if s == "" {
		return 0, errRange
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errRange
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, errRange
	}
	return n, nil
}

// Product ETags deliberately use a narrow opaque ASCII alphabet. Client
// If-Match lists still accept the RFC entity-tag grammar (including commas
// inside quotes); a syntactically valid but different value simply fails.
func strongETag(s string) bool {
	if len(s) < 3 || len(s) > 122 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	for _, c := range s[1 : len(s)-1] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func matchETags(header, current string) (bool, error) {
	return matchETagList(header, current, false)
}
func matchETagList(header, current string, allowWeak bool) (bool, error) {
	if len(header) > 128 {
		return false, errConditional
	}
	s := strings.Trim(header, " \t")
	if s == "*" {
		return true, nil
	}
	matched, empty := false, 0
	for s != "" {
		// RFC list recipients tolerate a bounded number of empty elements.
		if s[0] == ',' {
			empty++
			if empty > 8 {
				return false, errConditional
			}
			s = strings.Trim(s[1:], " \t")
			continue
		}
		weak := strings.HasPrefix(s, "W/")
		if weak {
			s = s[2:]
		}
		if len(s) < 2 || s[0] != '"' {
			return false, errConditional
		}
		end := 1
		for end < len(s) && s[end] != '"' {
			if s[end] < 0x21 || s[end] == 0x7f {
				return false, errConditional
			}
			end++
		}
		if end == len(s) {
			return false, errConditional
		}
		if (!weak || allowWeak) && s[:end+1] == current {
			matched = true
		}
		s = strings.Trim(s[end+1:], " \t")
		if s == "" {
			break
		}
		if s[0] != ',' {
			return false, errConditional
		}
		s = strings.Trim(s[1:], " \t")
	}
	return matched, nil
}

func httpToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}
