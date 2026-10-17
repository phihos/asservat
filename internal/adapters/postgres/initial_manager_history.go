package postgres

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

type initialHistoryOrigin struct {
	grant          initialRoleGrant
	owner, grantor uint32
}

// The owner is measured independently for each object; public schema ownership
// can be pg_database_owner and is never assumed to be bootstrap superuser 10.
func readInitialHistoryOrigins(ctx context.Context, q initialManagerQuery, state contracts.InitialBootstrapState) ([]initialHistoryOrigin, error) {
	name := initialRoleName(state.InstallationID, "history")
	rows, e := q.Query(ctx, `SELECT 'schema',n.nspname,'',a.privilege_type,n.nspowner,a.grantor,a.is_grantable FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE a.grantee=(SELECT oid FROM pg_roles WHERE rolname=$1)
 UNION ALL SELECT 'table',c.relname,'',a.privilege_type,c.relowner,a.grantor,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname='public' AND a.grantee=(SELECT oid FROM pg_roles WHERE rolname=$1)`, name)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	defer rows.Close()
	out := []initialHistoryOrigin{}
	for rows.Next() {
		var v initialHistoryOrigin
		var grantable bool
		if rows.Scan(&v.grant.kind, &v.grant.object, &v.grant.column, &v.grant.privilege, &v.owner, &v.grantor, &grantable) != nil || grantable || v.owner == 0 || v.owner == state.Manager.Receipt.OID {
			return nil, cfg.ErrChanged
		}
		out = append(out, v)
		if len(out) > 6 {
			return nil, cfg.ErrChanged
		}
	}
	if rows.Err() != nil || ctx.Err() != nil {
		return nil, cfg.ErrUnavailable
	}
	return out, nil
}
func initialHistoryOriginSet(rows []initialHistoryOrigin, manager uint32, owners bool) bool {
	if len(rows) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range rows {
		found := false
		for _, g := range initialHistoryGrants() {
			if g.key() == v.grant.key() {
				found = true
				break
			}
		}
		if !found || seen[v.grant.key()] || v.owner == 0 || v.owner == manager {
			return false
		}
		seen[v.grant.key()] = true
		want := manager
		if owners {
			want = v.owner
		}
		if v.grantor != want {
			return false
		}
	}
	return true
}
func verifyTransferredHistory(ctx context.Context, q initialManagerQuery, state contracts.InitialBootstrapState) error {
	if e := verifyInitialHistoryRole(ctx, q, initialRoleName(state.InstallationID, "history"), *state.Manager.Receipt); e != nil {
		return cfg.ErrChanged
	}
	rows, e := readInitialHistoryOrigins(ctx, q, state)
	if e != nil {
		return e
	}
	if !initialHistoryOriginSet(rows, state.Manager.Receipt.OID, true) {
		return cfg.ErrChanged
	}
	return nil
}

// This is a fixed three-grant authority-preserving transfer. PostgreSQL's
// RESTRICT revocation otherwise refuses a manager's grant option while its
// passive history grant chain remains. CASCADE would remove passive access.
// The same transaction gives each exact non-grantable privilege from its real
// owner, removes only the original manager-origin copy, restores administrator
// identity, and verifies unchanged effective rights and exact final origins.
func transferInitialHistoryGrants(ctx context.Context, tx pgx.Tx, state contracts.InitialBootstrapState) error {
	pin := *state.Manager.Receipt
	name := initialRoleName(state.InstallationID, "history")
	if e := verifyInitialHistoryRole(ctx, tx, name, pin); e != nil {
		return cfg.ErrChanged
	}
	rows, e := readInitialHistoryOrigins(ctx, tx, state)
	if e != nil {
		return e
	}
	if initialHistoryOriginSet(rows, pin.OID, true) {
		return nil
	}
	if !initialHistoryOriginSet(rows, pin.OID, false) {
		return cfg.ErrChanged
	}
	for _, g := range initialHistoryGrants() {
		if _, e = tx.Exec(ctx, g.sql("GRANT", name)); e != nil {
			return cfg.ErrUnavailable
		}
	}
	transferred, e := readInitialHistoryOrigins(ctx, tx, state)
	if e != nil {
		return e
	}
	if len(transferred) != 6 {
		return cfg.ErrChanged
	}
	for _, original := range rows {
		old, new := 0, 0
		for _, v := range transferred {
			if v.grant.key() == original.grant.key() {
				if v.owner != original.owner {
					return cfg.ErrChanged
				}
				switch v.grantor {
				case pin.OID:
					old++
				case original.owner:
					new++
				default:
					return cfg.ErrChanged
				}
			}
		}
		if old != 1 || new != 1 {
			return cfg.ErrChanged
		}
	}
	// Only the independently pinned manager is selected, not a caller-chosen
	// role. Its LOGIN flag is irrelevant to this trusted SQL-administrator SET.
	var originalAdmin uint32
	if e = tx.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=current_user`).Scan(&originalAdmin); e != nil {
		return cfg.ErrUnavailable
	}
	if _, e = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{pin.Name}.Sanitize()); e != nil {
		return cfg.ErrUnavailable
	}
	var current uint32
	if e = tx.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=current_user`).Scan(&current); e != nil || current != pin.OID {
		return cfg.ErrChanged
	}
	for _, g := range initialHistoryGrants() {
		if _, e = tx.Exec(ctx, g.sql("REVOKE", name)+" RESTRICT"); e != nil {
			return cfg.ErrUnavailable
		}
	}
	if _, e = tx.Exec(ctx, "RESET ROLE"); e != nil {
		return cfg.ErrUnavailable
	}
	if e = tx.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=current_user`).Scan(&current); e != nil || current != originalAdmin {
		return cfg.ErrChanged
	}
	return verifyTransferredHistory(ctx, tx, state)
}
