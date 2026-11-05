package postgres

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"asservat.local/asservat/migrations"
)

// Compare effective definitions, not a parallel whitelist: every replaced
// function must restore the exact preceding implementation on rollback.
func TestProcessesMigrationRestoresExact141(t *testing.T) {
	files, err := fs.Glob(migrations.Files(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	body, err := fs.ReadFile(migrations.Files(), "00142_pod_process_discovery.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(body), "-- +goose Down")
	if !ok {
		t.Fatal("missing Down")
	}
	definitions := regexp.MustCompile(`(?s)CREATE (?:OR REPLACE )?FUNCTION (\w+)\(.*?\$\$;`)
	old := map[string]string{}
	for _, file := range files {
		if file >= "00142" {
			continue
		}
		b, err := fs.ReadFile(migrations.Files(), file)
		if err != nil {
			t.Fatal(err)
		}
		section, _, _ := strings.Cut(string(b), "-- +goose Down")
		for _, m := range definitions.FindAllStringSubmatch(section, -1) {
			old[m[1]] = strings.Replace(m[0], "CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", 1)
		}
	}
	replaced := definitions.FindAllStringSubmatch(up, -1)
	if len(replaced) == 0 {
		t.Fatal("missing functions")
	}
	restored := definitions.FindAllStringSubmatch(down, -1)
	if len(restored) != len(replaced) {
		t.Fatal("rollback definition inventory", len(replaced), len(restored))
	}
	for _, m := range replaced {
		if old[m[1]] == "" || !strings.Contains(down, old[m[1]]) {
			t.Fatal("Down changed effective141 function", m[1])
		}
	}
	if strings.Contains(up, "CREATE TABLE") || strings.Contains(up, "GRANT ") || strings.Contains(up, "ADD COLUMN") {
		t.Fatal("extension added state or privileges")
	}
}
