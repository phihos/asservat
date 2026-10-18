package objectstore

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// The pinned Go producer emits RFC3339 timestamps with at most nanosecond
// precision. Reject syntax accepted leniently by time.Parse (comma fractions,
// one-digit hours and out-of-range offsets) rather than silently normalizing it.
var contextTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// ParseContextProjection only validates the fixed native shape and its inner
// Pod/namespace bindings. The acquisition adapter must first verify the exact
// committed source/version, envelope and manifest independently. This pure
// parser cannot turn arbitrary caller bytes or an asserted scope into evidence.
func ParseContextProjection(native []byte, scope analysis.ContextProjectionScope) (analysis.PodStatusProjection, error) {
	var zero analysis.PodStatusProjection
	if !scope.Valid() || len(native) == 0 || len(native) > artifact.MaxContextBytes || !utf8.Valid(native) {
		return zero, analysis.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(native))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return zero, analysis.ErrInvalid
	}
	p := analysis.PodStatusProjection{}
	seen := make(map[string]bool, 14)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return zero, analysis.ErrInvalid
		}
		seen[name] = true
		var destination any
		var observed string
		switch name {
		case "format":
			destination = &p.Format
		case "namespaceUID":
			destination = &p.NamespaceUID
		case "podUID":
			destination = &p.PodUID
		case "resourceVersion":
			destination = &p.ResourceVersion
		case "observedAt":
			destination = &observed
		case "phase":
			destination = &p.Phase
		case "ready":
			destination = &p.Ready
		case "initialized":
			destination = &p.Initialized
		case "scheduled":
			destination = &p.Scheduled
		case "runtimeInstances":
			destination = &p.RuntimeInstances
		case "running":
			destination = &p.Running
		case "waiting":
			destination = &p.Waiting
		case "terminated":
			destination = &p.Terminated
		case "restarts":
			destination = &p.Restarts
		default:
			return zero, analysis.ErrInvalid
		}
		var raw json.RawMessage
		invalid := decoder.Decode(&raw) != nil || bytes.Equal(raw, []byte("null")) || !validSurrogates(raw) || json.Unmarshal(raw, destination) != nil
		clear(raw)
		if invalid {
			return zero, analysis.ErrInvalid
		}
		if name == "observedAt" {
			if !contextTimestamp.MatchString(observed) {
				return zero, analysis.ErrInvalid
			}
			p.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
			if err != nil {
				return zero, analysis.ErrInvalid
			}
			p.ObservedAt = p.ObservedAt.UTC()
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || len(seen) != 14 {
		return zero, analysis.ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF || !p.Valid() || p.PodUID != scope.PodUID || p.NamespaceUID != scope.NamespaceUID {
		return zero, analysis.ErrInvalid
	}
	return p, nil
}

// encoding/json replaces unpaired UTF-16 surrogates with U+FFFD. Reject those
// malformed strings before decoding so formatting never silently changes them.
func validSurrogates(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		v, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
