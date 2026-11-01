package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// RecordingSaveSettings are encrypted repeat preferences, not an old source
// selection or capability. No handles, session/fence/snapshot IDs or clocks.
type RecordingSaveSettings struct {
	PolicyUID             string
	PolicyExecutionDigest artifact.Digest
	Windows               []RecordingSavePreference
}
type RecordingSavePreference struct {
	ActionID string
	Before   time.Duration
}

func (s *RecordingSaveSettings) Valid() bool {
	if s == nil || !identity.Text(s.PolicyUID, 64) || s.PolicyExecutionDigest == (artifact.Digest{}) || len(s.Windows) < 1 || len(s.Windows) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, w := range s.Windows {
		if !identity.Text(w.ActionID, 63) || seen[w.ActionID] || w.Before <= 0 || w.Before > artifact.MaxLifecycleWindow || w.Before%time.Millisecond != 0 {
			return false
		}
		seen[w.ActionID] = true
	}
	return true
}
func (s *RecordingSaveSettings) Clone() *RecordingSaveSettings {
	if s == nil {
		return nil
	}
	out := *s
	out.Windows = append(s.Windows[:0:0], s.Windows...)
	return &out
}
