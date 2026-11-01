package capture

import (
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const MaxRecordingSelections = 100

// RecordingReference is passive control metadata. It conveys no acquisition,
// disclosure, source lease or promise that history remains in the ring.
type RecordingReference struct {
	SourceID, Fence, PolicyUID, PodUID, ActionID string
	BindingDigest, ExecutionDigest               artifact.Digest
}

func (r RecordingReference) Valid() bool {
	return authorization.UUID(r.SourceID) && authorization.UUID(r.Fence) && identity.Text(r.PolicyUID, 64) && identity.Text(r.PodUID, 64) && identity.Text(r.ActionID, 63) && r.BindingDigest != (artifact.Digest{}) && r.ExecutionDigest != (artifact.Digest{})
}

// RecordingSelectionSet is one principal/client-bound inventory page set.
// Paging and lookup retain the original expiry, never a rolling lease.
type RecordingSelectionSet struct {
	ID, RootID               string
	PolicyUID, AfterSourceID string
	More                     bool
	Actor                    identity.Principal
	Target                   authorization.WorkloadTarget
	References               []RecordingReference
	CreatedAt, ExpiresAt     time.Time
}

func (s RecordingSelectionSet) Valid() bool {
	if !authorization.UUID(s.ID) || !authorization.UUID(s.RootID) || !s.Actor.Valid() || !s.Target.Valid() || !previewTime(s.CreatedAt) || !previewTime(s.ExpiresAt) || !s.ExpiresAt.After(s.CreatedAt) || s.ExpiresAt.After(s.CreatedAt.Add(time.Minute)) || len(s.References) > MaxRecordingSelections || s.PolicyUID != "" && !identity.Text(s.PolicyUID, 64) || s.AfterSourceID != "" && !authorization.UUID(s.AfterSourceID) || s.More && s.AfterSourceID == "" {
		return false
	}
	seen := make(map[string]bool, len(s.References))
	for _, r := range s.References {
		if !r.Valid() || seen[r.SourceID] {
			return false
		}
		seen[r.SourceID] = true
	}
	return true
}

func (s RecordingSelectionSet) Clone() RecordingSelectionSet {
	s.References = append(s.References[:0:0], s.References...)
	return s
}

// Handles contain an unpredictable set ID and a slot, with no reusable source
// identity. The authenticated service must still read and authorize the set.
func (s RecordingSelectionSet) Handle(slot int) string {
	if slot < 0 || slot >= len(s.References) {
		return ""
	}
	return s.ID + ":" + strconv.Itoa(slot)
}

func ParseRecordingHandle(handle string) (string, int, bool) {
	id, raw, ok := strings.Cut(handle, ":")
	slot, err := strconv.Atoi(raw)
	return id, slot, ok && authorization.UUID(id) && err == nil && slot >= 0 && slot < MaxRecordingSelections && strconv.Itoa(slot) == raw
}

func (s RecordingSelectionSet) Select(actor identity.Principal, handles []string, now time.Time) ([]RecordingReference, error) {
	if !s.Valid() || actor != s.Actor || now.Before(s.CreatedAt) || !now.Before(s.ExpiresAt) {
		return nil, ErrDenied
	}
	if len(handles) < 1 || len(handles) > 16 {
		return nil, ErrInvalid
	}
	out := make([]RecordingReference, 0, len(handles))
	seen := map[int]bool{}
	for _, handle := range handles {
		id, slot, ok := ParseRecordingHandle(handle)
		if !ok || id != s.ID || slot >= len(s.References) || seen[slot] {
			return nil, ErrInvalid
		}
		seen[slot] = true
		out = append(out, s.References[slot])
	}
	return out, nil
}

// A batch cursor is not a selectable source handle. Its state stays protected
// in the original principal-bound selection row, including the original expiry.
func (s RecordingSelectionSet) BatchCursor() string {
	if !s.More {
		return ""
	}
	return s.ID + ":100"
}
func ParseRecordingCursor(cursor string) (string, int, bool) {
	id, raw, ok := strings.Cut(cursor, ":")
	if ok && authorization.UUID(id) && raw == "100" {
		return id, 100, true
	}
	return ParseRecordingHandle(cursor)
}
