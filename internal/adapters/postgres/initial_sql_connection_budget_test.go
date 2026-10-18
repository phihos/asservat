package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

type connectionCapacityRead struct {
	publicRoleQuery
	server contracts.SQLServerCapacity
	err    error
	after  func()
	query  string
}

func (s *connectionCapacityRead) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	s.query = query
	return functionIdentityRow(func(dst ...any) error {
		if s.after != nil {
			s.after()
		}
		*dst[0].(*int), *dst[1].(*int), *dst[2].(*int) = s.server.MaxConnections, s.server.SuperuserReserved, s.server.Reserved
		return s.err
	})
}

func TestInstalledSQLBudgetReadsActualReservedCapacity(t *testing.T) {
	plan, _ := contracts.InstalledSQLConnectionPlan(1)
	for _, tc := range []struct {
		name       string
		server     contracts.SQLServerCapacity
		allocation int
		want       bool
	}{
		{"component fixture", contracts.SQLServerCapacity{MaxConnections: 48, SuperuserReserved: 3}, 0, false},
		{"old installed allowance", contracts.SQLServerCapacity{MaxConnections: 110, SuperuserReserved: 3}, 0, false},
		{"minimum installed", contracts.SQLServerCapacity{MaxConnections: 115, SuperuserReserved: 3}, 0, true},
		{"additional reserved", contracts.SQLServerCapacity{MaxConnections: 115, SuperuserReserved: 3, Reserved: 1}, 0, false},
		{"below declared allocation", contracts.SQLServerCapacity{MaxConnections: 115, SuperuserReserved: 3}, 111, false},
		{"allocation exceeds server", contracts.SQLServerCapacity{MaxConnections: 115, SuperuserReserved: 3}, 113, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &connectionCapacityRead{server: tc.server}
			got, err := readSQLConnectionBudget(context.Background(), q, plan, tc.allocation)
			if (err == nil) != tc.want || got.Required != 112 || got.Available != tc.server.Ordinary() {
				t.Fatal(got, err)
			}
			if err != nil && !errors.Is(err, contracts.ErrSQLConnectionBudget) {
				t.Fatal(err)
			}
			if !strings.Contains(q.query, "current_setting('reserved_connections',true)") {
				t.Fatal("reserved slots omitted")
			}
		})
	}
}

func TestInstalledSQLBudgetReadCannotOutliveCaller(t *testing.T) {
	plan, _ := contracts.InstalledSQLConnectionPlan(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := &connectionCapacityRead{server: contracts.SQLServerCapacity{MaxConnections: 115, SuperuserReserved: 3}, after: cancel}
	if _, err := readSQLConnectionBudget(ctx, q, plan, 0); !errors.Is(err, cfg.ErrUnavailable) {
		t.Fatal(err)
	}
	q = &connectionCapacityRead{err: errors.New("secret SQL detail")}
	if _, err := readSQLConnectionBudget(context.Background(), q, plan, 0); err != cfg.ErrUnavailable {
		t.Fatal(err)
	}
}
