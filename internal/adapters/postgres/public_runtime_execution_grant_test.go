package postgres

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The installed api-execution login must hold INSERT on every column
// InsertAPIExecution writes. SQL39 added writer_protocol to the statement and
// the component fixture role, but not to the product grant plan, so every
// installed context start was denied at its first execution row.
func TestAPIExecutionPrepareInsertsEveryWrittenColumn(t *testing.T) {
	q, err := os.ReadFile("../../../migrations/queries/context_execution.sql")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`INSERT INTO context_execution\(([^)]*)\)`).FindSubmatch(q)
	if m == nil {
		t.Fatal("InsertAPIExecution statement not found")
	}
	grants, _ := publicRuntimeDutyGrants("api-execution")
	for _, column := range strings.Split(string(m[1]), ",") {
		if !slices.Contains(grants, publicRuntimeGrant{"table", "context_execution", strings.TrimSpace(column), "INSERT"}) {
			t.Errorf("api-execution cannot insert context_execution.%s", column)
		}
	}
}
