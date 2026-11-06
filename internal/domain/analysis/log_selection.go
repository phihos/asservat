package analysis

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

const (
	LogQueryDisplayVersion = "approved-logs/v1"
	LogQueryPageBytes      = ContextResultBytes - 4096
	LogQueryReadBatches    = 2
	LogQueryUnits          = 20 // Configured full-source work allowance; not measured overhead.
	LogQueryWorkerBytes    = 256 << 20
	LogPageRecords         = 100
	LogPageFragmentBytes   = 1024
)

// LogWindow is display position only, never collection scope or authority.
// Offset permits bounded pages to split a recorded fragment without losing bytes.
type LogWindow struct {
	Fragment uint64
	Offset   uint16
	Limit    int
	Binding  string
}

func (w LogWindow) Valid() bool {
	if w.Fragment >= uint64(artifact.LogNativeLimit) || w.Offset >= artifact.LogMaxFragmentBytes || w.Limit < 1 || w.Limit > LogPageRecords {
		return false
	}
	if w.Fragment == 0 && w.Offset == 0 {
		return w.Binding == ""
	}
	return lowerHex(w.Binding, 32)
}

type LogSelection struct {
	CaseID, ArtifactID string
	LogWindow
}

func (s LogSelection) Valid() bool {
	return authorization.UUID(s.CaseID) && authorization.UUID(s.ArtifactID) && s.LogWindow.Valid()
}

func NormalizeLogSelection(caseID, artifactID, cursor string, limit int) (LogSelection, error) {
	if limit == 0 {
		limit = LogPageRecords
	}
	s := LogSelection{CaseID: caseID, ArtifactID: artifactID, LogWindow: LogWindow{Limit: limit}}
	if cursor != "" {
		parts := strings.Split(cursor, ":")
		if len(parts) != 3 {
			return LogSelection{}, ErrInvalidCursor
		}
		fragment, fe := strconv.ParseUint(parts[0], 10, 64)
		offset, oe := strconv.ParseUint(parts[1], 10, 16)
		if fe != nil || oe != nil || parts[0] != strconv.FormatUint(fragment, 10) || parts[1] != strconv.FormatUint(offset, 10) || fragment == 0 && offset == 0 {
			return LogSelection{}, ErrInvalidCursor
		}
		s.Fragment, s.Offset, s.Binding = fragment, uint16(offset), parts[2]
		if !s.LogWindow.Valid() {
			return LogSelection{}, ErrInvalidCursor
		}
	}
	if !s.Valid() {
		return LogSelection{}, ErrInvalid
	}
	return s, nil
}

func (s LogSelection) Matches(version artifact.Digest) bool {
	return s.Valid() && version != (artifact.Digest{}) && (s.Binding == "" || s.Binding == s.cursorBinding(version))
}

// Cursor binds the exact saved source and display version; page size may change.
// A cursor cannot authorize a read or bypass complete-source verification.
func (s LogSelection) Cursor(fragment uint64, offset uint16, version artifact.Digest) string {
	if !s.Matches(version) || fragment >= uint64(artifact.LogNativeLimit) || offset >= artifact.LogMaxFragmentBytes || fragment == 0 && offset == 0 {
		return ""
	}
	return strconv.FormatUint(fragment, 10) + ":" + strconv.FormatUint(uint64(offset), 10) + ":" + s.cursorBinding(version)
}

func (s LogSelection) cursorBinding(version artifact.Digest) string {
	h := sha256.New()
	h.Write([]byte(LogQueryDisplayVersion + "\x00"))
	h.Write(version[:])
	h.Write([]byte(s.CaseID))
	h.Write([]byte(s.ArtifactID))
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}

func (w LogWindow) Selection(caseID, artifactID string) LogSelection {
	return LogSelection{CaseID: caseID, ArtifactID: artifactID, LogWindow: w}
}

type RawLogQueryRequest struct {
	CaseID, ArtifactID, GrantID, IdempotencyKey string
	Selection                                   LogWindow
}

func (r RawLogQueryRequest) Valid() bool {
	return authorization.UUID(r.CaseID) && authorization.UUID(r.ArtifactID) && (r.GrantID == "" || authorization.UUID(r.GrantID)) && len(r.IdempotencyKey) >= 1 && len(r.IdempotencyKey) <= 128 && r.Selection.Valid()
}
