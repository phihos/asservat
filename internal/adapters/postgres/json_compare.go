package postgres

import (
	"bytes"
	"encoding/json"
)

// sameAuditJSON compares two values by their JSON encoding.
func sameAuditJSON(a, b any) bool {
	x, e := json.Marshal(a)
	if e != nil {
		return false
	}
	y, e := json.Marshal(b)
	return e == nil && bytes.Equal(x, y)
}

func strictJSON(s string, v any) error {
	d := json.NewDecoder(bytes.NewReader([]byte(s)))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
