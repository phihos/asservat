// Package jose signs and verifies detached Ed25519 lifecycle records.
package jose

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"strconv"
)

func strictJSON(b []byte, maximum, tokens int) bool {
	if len(b) == 0 || len(b) > maximum {
		return false
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	for i := 0; ; i++ {
		token, err := d.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil || i >= tokens || d.StackDepth() > 32 {
			return false
		}
		if token.Kind() == '0' {
			n, err := strconv.ParseInt(token.String(), 10, 64)
			if err != nil || n > 9007199254740991 || n < -9007199254740991 {
				return false
			}
		}
	}
	return json.Valid(b)
}
func rawURL(s string, max int) ([]byte, bool) {
	if len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) <= max && base64.RawURLEncoding.EncodeToString(b) == s
}
