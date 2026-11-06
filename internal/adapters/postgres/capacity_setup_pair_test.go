package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This isolates the pair decision and immutable INSERT inputs. It supplies no
// SQL, role, current-authority or provider qualification; the service regression
// exercises those through InitializeCapacity and the actual protected guards.
type capacityPairTestTx struct {
	pgx.Tx
	source, capture, exact bool
	reads                  int
	writes                 [][]any
}

type capacityPairTestRow []bool

func (r capacityPairTestRow) Scan(out ...any) error {
	for i, value := range r {
		*out[i].(*bool) = value
	}
	return nil
}

func (t *capacityPairTestTx) QueryRow(context.Context, string, ...any) pgx.Row {
	t.reads++
	if t.reads == 1 {
		return capacityPairTestRow{t.source, t.capture}
	}
	return capacityPairTestRow{t.exact}
}

func (t *capacityPairTestTx) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	t.writes = append(t.writes, append([]any(nil), args...))
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestCapacitySetupPairOnlyFinishesUnacknowledgedAbsentPair(t *testing.T) {
	roles := make([]capacitySetupRole, len(contracts.CapacitySetupRolePurposes()))
	for i, purpose := range contracts.CapacitySetupRolePurposes() {
		roles[i].Purpose = purpose
		roles[i].Receipt.RoleOID = uint32(i + 100)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	old := contracts.CapacityRootSetupReceipt{ClaimedAt: now.Add(-time.Minute), Until: now.Add(-time.Minute + time.Second)}
	in := capacitySetupInput{}
	in.bytes = []byte(`{}`)
	for _, test := range []struct {
		name                                   string
		source, capture, exact, fresh, pending bool
		cancelled, wantOK                      bool
		writes                                 int
	}{
		{name: "original-expired-claim-new-current-invocation", exact: true, pending: true, wantOK: true, writes: 2},
		{name: "fresh-invocation-still-uses-original-end", exact: true, fresh: true, pending: true},
		{name: "current-invocation-cancelled", exact: true, pending: true, cancelled: true},
		{name: "acknowledged-missing-pair", exact: true},
		{name: "source-half", source: true, exact: true, pending: true},
		{name: "capture-half", capture: true, exact: true, pending: true},
		{name: "committed-pending-receipt-lookup", source: true, capture: true, exact: true, pending: true, wantOK: true},
		{name: "committed-acknowledged-lookup", source: true, capture: true, exact: true, wantOK: true},
		{name: "foreign-committed-pair", source: true, capture: true, pending: true},
		{name: "fresh-claim-cannot-adopt-existing-pair", source: true, capture: true, exact: true, fresh: true, pending: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if test.cancelled {
				cancel()
			}
			tx := &capacityPairTestTx{source: test.source, capture: test.capture, exact: test.exact}
			err := (&PublicRuntimeSQLRoles{}).capacitySetupPair(ctx, tx, in, old, roles, test.fresh, test.pending)
			if (err == nil) != test.wantOK || len(tx.writes) != test.writes {
				t.Fatal("pair completion/lookup decision", err, len(tx.writes))
			}
			if test.writes > 0 {
				var inserted contracts.CapacityRootSetupReceipt
				if json.Unmarshal(tx.writes[1][12].([]byte), &inserted) != nil || !reflect.DeepEqual(inserted, old) {
					t.Fatal("new authority rewrote original claim receipt")
				}
			}
		})
	}
}
