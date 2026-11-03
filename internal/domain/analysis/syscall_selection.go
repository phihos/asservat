package analysis

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

type SyscallView string

const (
	SyscallSummaryView SyscallView = "summary"
	SyscallEventsView  SyscallView = "events"
	SyscallPageRecords             = 100
	SyscallMaxRecords              = 1_000_000 // portable recorder ceiling (REQ-SYS-002)
)

const (
	SyscallSummaryDisplayVersion = "approved-syscall-summary/v1"
	SyscallEventsDisplayVersion  = "approved-syscall-events/v1"
)

func (v SyscallView) DisplayVersion() string {
	switch v {
	case SyscallSummaryView:
		return SyscallSummaryDisplayVersion
	case SyscallEventsView:
		return SyscallEventsDisplayVersion
	}
	return ""
}

// SyscallSelection describes display only. It cannot change acquisition or
// select argument fields. A cursor is a version/filter binding, not authority.
type SyscallSelection struct {
	CaseID, ArtifactID string
	View               SyscallView
	Start, Limit       int
	Binding            string
	Names              []string
	ErrorsOnly         bool
}

func (s SyscallSelection) Valid() bool {
	return authorization.UUID(s.CaseID) && authorization.UUID(s.ArtifactID) && s.selectionValid()
}

func (s SyscallSelection) selectionValid() bool {
	if s.Limit < 1 || s.Limit > SyscallPageRecords || s.Start < 0 || s.Start >= SyscallMaxRecords || len(s.Names) > 64 {
		return false
	}
	if s.Start == 0 && s.Binding != "" || s.Start > 0 && !lowerHex(s.Binding, 32) {
		return false
	}
	if s.View != SyscallSummaryView && s.View != SyscallEventsView || s.View == SyscallSummaryView && (len(s.Names) > 0 || s.ErrorsOnly) {
		return false
	}
	for i, n := range s.Names {
		if !utf8.ValidString(n) || utf8.RuneCountInString(n) < 1 || utf8.RuneCountInString(n) > 64 || i > 0 && s.Names[i-1] >= n {
			return false
		}
	}
	return true
}

func NormalizeSyscallSelection(caseID, artifactID string, view SyscallView, cursor string, limit int, names []string, errorsOnly bool) (SyscallSelection, error) {
	if limit == 0 {
		limit = SyscallPageRecords
	}
	s := SyscallSelection{CaseID: caseID, ArtifactID: artifactID, View: view, Limit: limit, Names: append([]string(nil), names...), ErrorsOnly: errorsOnly}
	sort.Strings(s.Names)
	if cursor != "" {
		index, binding, ok := strings.Cut(cursor, ":")
		n, err := strconv.Atoi(index)
		if !ok || err != nil || index != strconv.Itoa(n) || n < 1 || n >= SyscallMaxRecords || !lowerHex(binding, 32) {
			return SyscallSelection{}, ErrInvalidCursor
		}
		s.Start, s.Binding = n, binding
	}
	if !s.Valid() {
		return SyscallSelection{}, ErrInvalid
	}
	return s, nil
}

func (s SyscallSelection) Matches(version artifact.Digest) bool {
	return s.Valid() && version != (artifact.Digest{}) && (s.Start == 0 || s.Binding == s.cursorBinding(version))
}

// Cursor resumes in sorted aggregate order or matching native event order.
// Page size may change; artifact, view and normalized filter remain bound.
func (s SyscallSelection) Cursor(next int, version artifact.Digest) string {
	if !s.Valid() || next < 1 || next >= SyscallMaxRecords || version == (artifact.Digest{}) {
		return ""
	}
	return strconv.Itoa(next) + ":" + s.cursorBinding(version)
}

func (s SyscallSelection) cursorBinding(version artifact.Digest) string {
	h := sha256.New()
	h.Write([]byte(s.View.DisplayVersion() + "\x00"))
	h.Write(version[:])
	// UUIDs have fixed width. Every variable string is length-prefixed.
	h.Write([]byte(s.CaseID))
	h.Write([]byte(s.ArtifactID))
	write := func(v string) { h.Write([]byte{byte(len(v) >> 8), byte(len(v))}); h.Write([]byte(v)) }
	write(string(s.View))
	if s.ErrorsOnly {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	for _, name := range s.Names {
		write(name)
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}

// SyscallWindow is the comparable, closed selection carried by an admitted
// scope. Fixed storage preserves exact scope equality without borrowed slices.
type SyscallWindow struct {
	View         SyscallView
	Start, Limit int
	Binding      string
	Names        [64]string
	NameCount    int
	ErrorsOnly   bool
}

func (s SyscallSelection) Window() SyscallWindow {
	w := SyscallWindow{View: s.View, Start: s.Start, Limit: s.Limit, Binding: s.Binding, NameCount: len(s.Names), ErrorsOnly: s.ErrorsOnly}
	copy(w.Names[:], s.Names)
	return w
}
func (w SyscallWindow) Valid() bool { return w.Selection("", "").selectionValid() }
func (w SyscallWindow) Selection(caseID, artifactID string) SyscallSelection {
	if w.NameCount < 0 || w.NameCount > len(w.Names) {
		return SyscallSelection{}
	}
	for _, name := range w.Names[w.NameCount:] {
		if name != "" {
			return SyscallSelection{}
		}
	}
	s := SyscallSelection{CaseID: caseID, ArtifactID: artifactID, View: w.View, Start: w.Start, Limit: w.Limit, Binding: w.Binding, ErrorsOnly: w.ErrorsOnly}
	if w.NameCount >= 0 && w.NameCount <= len(w.Names) {
		s.Names = append([]string(nil), w.Names[:w.NameCount]...)
	}
	if !s.selectionValid() {
		return SyscallSelection{}
	}
	return s
}
