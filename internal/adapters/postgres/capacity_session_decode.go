package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"io"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

const capacitySessionDigestDomain = "asservat-capacity-session/jsonb-v1\x00"

// SQL owns snapshot creation and emits its exact jsonb text. The versioned
// digest covers those UTF-8 bytes, including all nested original policy facts;
// Go does not recreate a different serialization for verification. An authority
// caller never supplies a snapshot or digest to the session INSERT.
func decodeCapacitySessionBacking(raw, hash []byte, managed bool, session artifact.DownloadSession) (*value.CapacitySessionBacking, error) {
	if !managed && len(raw) == 0 && len(hash) == 0 {
		return nil, nil
	}
	if !managed || len(raw) == 0 || len(raw) > value.CapacitySessionBackingBytes || len(hash) != sha256.Size {
		return nil, artifact.ErrIntegrity
	}
	var zero artifact.Digest
	if bytes.Equal(hash, zero[:]) {
		return nil, artifact.ErrIntegrity
	}
	h := sha256.New()
	_, _ = h.Write([]byte(capacitySessionDigestDomain))
	_, _ = h.Write(raw)
	if !bytes.Equal(hash, h.Sum(nil)) {
		return nil, artifact.ErrIntegrity
	}
	// Canonicalize validates duplicate keys and JSON syntax/depth before the
	// ordinary decoder's case-insensitive struct matching can hide an alias.
	canonical := jsontext.Value(bytes.Clone(raw))
	if canonical.Canonicalize() != nil {
		return nil, artifact.ErrIntegrity
	}
	var out value.CapacitySessionBacking
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || !out.Matches(session) {
		return nil, artifact.ErrIntegrity
	}
	written, err := json.Marshal(out)
	if err != nil || !capacitySameJSONFields(raw, written) {
		return nil, artifact.ErrIntegrity
	}
	return &out, nil
}

// Require the complete exact-case closed field tree while allowing PostgreSQL
// and Go's equivalent timezone renderings. The typed decoder and Valid methods
// check every scalar; this helper cannot supply defaults for missing fields.
func capacitySameJSONFields(a, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	var same func(any, any) bool
	same = func(a, b any) bool {
		switch expected := b.(type) {
		case map[string]any:
			actual, ok := a.(map[string]any)
			if !ok || len(actual) != len(expected) {
				return false
			}
			for k, v := range expected {
				got, ok := actual[k]
				if !ok || !same(got, v) {
					return false
				}
			}
			return true
		case []any:
			actual, ok := a.([]any)
			if !ok || len(actual) != len(expected) {
				return false
			}
			for i, v := range expected {
				if !same(actual[i], v) {
					return false
				}
			}
			return true
		case string:
			_, ok := a.(string)
			return ok
		case float64:
			_, ok := a.(float64)
			return ok
		case bool:
			_, ok := a.(bool)
			return ok
		case nil:
			return a == nil
		default:
			return false
		}
	}
	return same(left, right)
}
