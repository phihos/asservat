package postgres

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"asservat.local/asservat/migrations"
)

// Compare complete effective definitions rather than allowlisting words. The
// process migration is integrated by the schema owner before qualification.
func TestLiveWatchMigrationRestoresEffective142(t *testing.T) {
	files, err := fs.Glob(migrations.Files(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fs.Stat(migrations.Files(), "00142_pod_process_discovery.sql"); err != nil {
		t.Skip("provisional143 awaits final142 integration; restoration is not qualified")
	}
	body, err := fs.ReadFile(migrations.Files(), "00143_finite_live_watch.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(body), "-- +goose Down")
	if !ok {
		t.Fatal("missing Down")
	}
	definitions := regexp.MustCompile(`(?s)CREATE (?:OR REPLACE )?FUNCTION (\w+)\(.*?\$\$;`)
	prior := map[string]string{}
	for _, file := range files {
		if file >= "00143" {
			continue
		}
		raw, err := fs.ReadFile(migrations.Files(), file)
		if err != nil {
			t.Fatal(err)
		}
		before, _, _ := strings.Cut(string(raw), "-- +goose Down")
		for _, match := range definitions.FindAllStringSubmatch(before, -1) {
			prior[match[1]] = strings.Replace(match[0], "CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", 1)
		}
	}
	replaced := 0
	for _, match := range definitions.FindAllStringSubmatch(up, -1) {
		if old := prior[match[1]]; old != "" {
			replaced++
			if !strings.Contains(down, old) {
				t.Fatal("Down changed effective142 definition", match[1])
			}
		}
	}
	if replaced != 3 {
		t.Fatal("unexpected existing function replacement count", replaced)
	}
}
