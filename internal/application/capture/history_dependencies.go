package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"bytes"
	"encoding/hex"
	"encoding/json"
)

// Current preview observations already provide these pins. Comparison performs
// no extra capability/API read and cannot silently upgrade a stored dependency.
func historyDependenciesMatch(s value.CaptureSettings, collector, projection artifact.Digest, profiles []planning.ResolvedProfile) bool {
	if s.SettingsKey == (artifact.Digest{}) {
		return true
	} // legacy pod-status projection (ADR-236)
	var pins []struct{ Role, Digest string }
	if json.Unmarshal(s.DependencyJSON, &pins) != nil || len(pins) == 0 || len(pins) > 64 {
		return false
	}
	for _, pin := range pins {
		switch pin.Role {
		case "collector":
			if pin.Digest != hex.EncodeToString(collector[:]) {
				return false
			}
		case "projection":
			if pin.Digest != hex.EncodeToString(projection[:]) {
				return false
			}
		case "captureProfile":
			matched := false
			for _, p := range profiles {
				if pin.Digest == hex.EncodeToString(p.DefinitionDigest[:]) {
					matched = true
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

func historyFiltersMatch(saved []byte, currentScope []byte, edited bool) bool {
	if len(saved) == 0 {
		return true
	}
	var old []json.RawMessage
	var scope struct {
		Filters []json.RawMessage `json:"filters"`
	}
	if json.Unmarshal(saved, &old) != nil || json.Unmarshal(currentScope, &scope) != nil {
		return false
	}
	oldByID := map[string]json.RawMessage{}
	for _, record := range old {
		var key struct{ ActionID, Expression string }
		if json.Unmarshal(record, &key) != nil {
			return false
		}
		oldByID[key.ActionID] = record
	}
	for _, record := range scope.Filters {
		var key struct{ ActionID, Expression string }
		if json.Unmarshal(record, &key) != nil {
			return false
		}
		before, ok := oldByID[key.ActionID]
		if !ok {
			if edited {
				continue
			}
			return false
		}
		var prior struct{ Expression string }
		if json.Unmarshal(before, &prior) != nil {
			return false
		}
		if edited && prior.Expression != key.Expression {
			continue
		}
		var a, b any
		if json.Unmarshal(before, &a) != nil || json.Unmarshal(record, &b) != nil {
			return false
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		if !bytes.Equal(x, y) {
			return false
		}
	}
	return edited || len(old) == len(scope.Filters)
}
