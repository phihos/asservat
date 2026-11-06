package postgres

import (
	"asservat.local/asservat/migrations"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestFiniteLogsMigrationRestoresExact140(t *testing.T) {
	files, err := fs.Glob(migrations.Files(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	body, err := fs.ReadFile(migrations.Files(), "00141_finite_saved_logs.sql")
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
		if file >= "00141" {
			continue
		}
		b, err := fs.ReadFile(migrations.Files(), file)
		if err != nil {
			t.Fatal(err)
		}
		section, _, _ := strings.Cut(string(b), "-- +goose Down")
		for _, match := range definitions.FindAllStringSubmatch(section, -1) {
			old[match[1]] = strings.Replace(match[0], "CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", 1)
		}
	}
	for _, match := range definitions.FindAllStringSubmatch(up, -1) {
		if old[match[1]] == "" || !strings.Contains(down, old[match[1]]) {
			t.Fatal("Down changed effective140 function", match[1])
		}
	}
	constraints := regexp.MustCompile(`(?s)ALTER TABLE (?:access_grant|access_grant_use) ADD CONSTRAINT \w+ .*?;`)
	prior, err := fs.ReadFile(migrations.Files(), "00140_saved_syscall_query.sql")
	if err != nil {
		t.Fatal(err)
	}
	priorUp, _, _ := strings.Cut(string(prior), "-- +goose Down")
	for _, constraint := range constraints.FindAllString(priorUp, -1) {
		if !strings.Contains(down, constraint) {
			t.Fatal("Down changed effective140 grant constraint")
		}
	}
	if strings.Contains(up, "CREATE TABLE") || strings.Contains(up, "GRANT ") || strings.Contains(up, "ADD COLUMN") {
		t.Fatal("extension added state or privileges")
	}
}
