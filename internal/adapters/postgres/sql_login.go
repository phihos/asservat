package postgres

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/xdg-go/scram"
)

// SQLLogin is one runtime role's name and password. It is secret material.
type SQLLogin struct{ Username, Password string }

// sqlPasswordVerifier derives a salted SCRAM-SHA-256 verifier with the
// maintained SCRAM implementation. Only the verifier reaches role DDL; the
// plaintext password is never part of an SQL statement or bind parameter.
func sqlPasswordVerifier(l SQLLogin) (string, error) {
	if len(l.Password) < 32 || len(l.Password) > 1024 || strings.IndexFunc(l.Password, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", value.ErrInvalid
	}
	c, err := scram.SHA256.NewClient(l.Username, l.Password, "")
	if err != nil {
		return "", value.ErrInvalid
	}
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return "", value.ErrUnavailable
	}
	defer clear(salt)
	stored, err := c.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt), Iters: 4096})
	if err != nil {
		return "", value.ErrUnavailable
	}
	defer clear(stored.StoredKey)
	defer clear(stored.ServerKey)
	b64 := base64.StdEncoding.EncodeToString
	return "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(stored.StoredKey) + ":" + b64(stored.ServerKey), nil
}
