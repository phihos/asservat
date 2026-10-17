package postgres

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io/fs"
	"strconv"
	"strings"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/migrations"
)

// InitialSchemaBundle is public build identity, not a caller-selectable source.
// The installation root binds this exact identity before first SQL mutation.
type InitialSchemaBundle struct {
	Digest string
	Head   int64
}

func EmbeddedInitialSchema() (InitialSchemaBundle, error) {
	return initialSchemaBundle(migrations.Files(), currentSchemaVersion)
}
func initialSchemaBundle(source fs.FS, head int64) (InitialSchemaBundle, error) {
	var zero InitialSchemaBundle
	entries, e := fs.ReadDir(source, ".")
	if e != nil || len(entries) == 0 || len(entries) > 128 || int64(len(entries)) != head {
		return zero, cfg.ErrInvalid
	}
	sum := sha256.New()
	total := 0
	for i, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) < 11 || len(name) > 128 || name[5] != '_' || !strings.HasSuffix(name, ".sql") {
			return zero, cfg.ErrInvalid
		}
		n, e := strconv.ParseInt(name[:5], 10, 64)
		if e != nil || n != int64(i+1) {
			return zero, cfg.ErrInvalid
		}
		b, e := fs.ReadFile(source, name)
		if e != nil || len(b) == 0 || len(b) > 512<<10 {
			return zero, cfg.ErrInvalid
		}
		total += len(b)
		if total > 8<<20 {
			return zero, cfg.ErrInvalid
		}
		// Goose remains the SQL parser. Restrict its control annotations to the
		// qualified transactional, upward-only subset before any database access.
		up, down, depth := 0, 0, 0
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "--") || !strings.Contains(line, "+goose") {
				continue
			}
			switch line {
			case "-- +goose Up":
				up++
				if up != 1 || depth != 0 {
					return zero, cfg.ErrInvalid
				}
			case "-- +goose Down":
				if up != 1 || down != 0 || depth != 0 {
					return zero, cfg.ErrInvalid
				}
				down++
			case "-- +goose StatementBegin":
				if up != 1 || depth != 0 {
					return zero, cfg.ErrInvalid
				}
				depth++
			case "-- +goose StatementEnd":
				if depth != 1 {
					return zero, cfg.ErrInvalid
				}
				depth--
			default:
				return zero, cfg.ErrInvalid
			}
		}
		if up != 1 || depth != 0 {
			return zero, cfg.ErrInvalid
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(name)))
		sum.Write(size[:])
		sum.Write([]byte(name))
		binary.BigEndian.PutUint64(size[:], uint64(len(b)))
		sum.Write(size[:])
		sum.Write(b)
	}
	return InitialSchemaBundle{Digest: hex.EncodeToString(sum.Sum(nil)), Head: head}, nil
}
