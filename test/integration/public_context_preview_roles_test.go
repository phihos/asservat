package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The caller authenticated using the actual provisioned role/password. These
// raw synthetic rows isolate SQL grants and trigger enforcement; existing
// qualifyContextPreviews/qualifyContextRequestResolution test application
// validation, current authority, caps and expiry after blocking reads.
func qualifyPublicContextDraftRole(t *testing.T, ctx context.Context, admin *pgxpool.Pool, conn *pgx.Conn, purpose, installation string) {
	if purpose != "capture-preview" && purpose != "capture-resolution" {
		return
	}
	t.Run(purpose+"-generated-role-effects", func(t *testing.T) {
		root, preview := custodyID(), custodyID()
		digest := make([]byte, 32)
		digest[0] = 1
		if _, e := admin.Exec(ctx, `INSERT INTO public.permission_stream(id,epoch,trust_digest,lease_until) VALUES($1,$2,$3,clock_timestamp()+interval '1 hour')`, root, custodyID(), digest); e != nil {
			t.Fatal(e)
		}
		// An already expired synthetic row can be removed in positive fixture cleanup
		// without rewriting its dates, disabling guards or waiting out a live draft.
		if _, e := admin.Exec(ctx, `INSERT INTO public.context_preview(id,root_id,capture_id,attempt_id,actor_key,principal_key,blueprint_json,blueprint_sha256,created_at,deadline)
   VALUES($1,$2,$3,$4,$5,$5,$6,$5,clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute')`, preview, root, custodyID(), custodyID(), digest, []byte(`{"fixture":"ACL-only"}`)); e != nil {
			t.Fatal(e)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, e := admin.Exec(cleanup, `DELETE FROM public.context_preview WHERE root_id=$1`, root); e != nil {
				t.Error("expired fixture preview cleanup", e)
			}
			if _, e := admin.Exec(cleanup, `DELETE FROM public.permission_stream WHERE id=$1`, root); e != nil {
				t.Error("fixture permission root cleanup", e)
			}
		}()
		tx, e := conn.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if e := tx.Rollback(cleanup); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
				t.Error("draft role rollback", e)
			}
		}()
		must := func(q string, args ...any) {
			t.Helper()
			if _, e := tx.Exec(ctx, q, args...); e != nil {
				t.Fatal("expected narrow role operation", e)
			}
		}
		deny := func(code, q string, args ...any) {
			t.Helper()
			must("SAVEPOINT draft_negative")
			_, e := tx.Exec(ctx, q, args...)
			var pg *pgconn.PgError
			if !errors.As(e, &pg) || pg.Code != code {
				t.Fatal("wrong denial", q, e)
			}
			must("ROLLBACK TO SAVEPOINT draft_negative")
			must("RELEASE SAVEPOINT draft_negative")
		}
		if purpose == "capture-resolution" {
			must(`SELECT * FROM public.fleet_current_trust WHERE installation_id=$1 FOR SHARE`, installation)
		}
		must(`SELECT id FROM public.permission_stream WHERE id=$1 FOR UPDATE`, root)
		must(`SELECT * FROM public.context_preview WHERE root_id=$1`, root)
		must(`SELECT * FROM public.context_preview_fence WHERE root_id=$1`, root)
		// Separate statements prevent one missing column from masking a broad grant
		// on another column. Catalog inspection covers every future column as well.
		allowed := map[string]map[string]bool{"permission_stream": {"id": true}}
		if purpose == "capture-resolution" {
			allowed["fleet_current_trust"] = map[string]bool{"installation_id": true}
			allowed["context_preview"] = map[string]bool{"closed_at": true, "closed_request_key": true, "closed_submission_digest": true}
		}
		for _, table := range []string{"permission_stream", "fleet_current_trust", "context_preview", "context_preview_fence", "context_capture", "custody_attempt", "operation_audit", "authority_audit"} {
			rows, e := conn.Query(ctx, `SELECT a.attname,has_column_privilege(current_user,c.oid,a.attnum,'UPDATE') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`, table)
			if e != nil {
				t.Fatal(e)
			}
			columns := []string{}
			for rows.Next() {
				var column string
				var granted bool
				if e = rows.Scan(&column, &granted); e != nil {
					rows.Close()
					t.Fatal(e)
				}
				if granted != allowed[table][column] {
					rows.Close()
					t.Fatal("unexpected column privilege", table, column, granted)
				}
				if !granted {
					columns = append(columns, column)
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil || len(columns) == 0 {
				t.Fatal("missing column privilege inventory", table, e)
			}
			if table == "fleet_current_trust" {
				continue
			} // computed view columns are checked by catalog privileges above
			for _, column := range columns {
				name := pgx.Identifier{column}.Sanitize()
				deny("42501", "UPDATE "+pgx.Identifier{"public", table}.Sanitize()+" SET "+name+"="+name+" WHERE false")
			}
		}
		for _, table := range []string{"context_capture", "custody_attempt", "operation_audit", "authority_audit"} {
			deny("42501", "INSERT INTO "+pgx.Identifier{"public", table}.Sanitize()+" DEFAULT VALUES")
			deny("42501", "DELETE FROM "+pgx.Identifier{"public", table}.Sanitize()+" WHERE false")
		}
		if purpose == "capture-preview" {
			live := custodyID()
			must(`WITH original AS MATERIALIZED (SELECT clock_timestamp() AS created_at) INSERT INTO public.context_preview(id,root_id,capture_id,attempt_id,actor_key,principal_key,blueprint_json,blueprint_sha256,created_at,deadline) SELECT $1,$2,$3,$4,$5,$5,$6,$5,created_at,created_at+interval '5 minutes' FROM original`, live, root, custodyID(), custodyID(), digest, []byte(`{"fixture":"ACL-only"}`))
			deny("23514", `DELETE FROM public.context_preview WHERE id=$1`, live)
			deny("42501", `INSERT INTO public.context_preview_fence DEFAULT VALUES`)
			// The SQL guard rejects a created-closed blueprint even though this role
			// has INSERT authority, independently of Go field validation.
			deny("23514", `INSERT INTO public.context_preview(id,root_id,capture_id,attempt_id,actor_key,principal_key,blueprint_json,blueprint_sha256,created_at,deadline,closed_at,closed_request_key,closed_submission_digest) VALUES($1,$2,$3,$4,$5,$5,$6,$5,clock_timestamp(),clock_timestamp()+interval '1 minute',clock_timestamp(),$5,$5)`, custodyID(), root, custodyID(), custodyID(), digest, []byte(`{}`))
		} else {
			for _, table := range []string{"permission_basis", "permission_assignment", "authority_audit", "context_capture"} {
				must("SELECT * FROM " + pgx.Identifier{"public", table}.Sanitize() + " WHERE false")
			}
			must(`UPDATE public.context_preview SET closed_at=clock_timestamp(),closed_request_key=$2,closed_submission_digest=$2 WHERE id=$1`, preview, digest)
			deny("23514", `UPDATE public.context_preview SET closed_at=NULL,closed_request_key=NULL,closed_submission_digest=NULL WHERE id=$1`, preview)
			for _, column := range []string{"closed_request_key", "closed_submission_digest"} {
				deny("23514", "UPDATE public.context_preview SET "+pgx.Identifier{column}.Sanitize()+"=$2 WHERE id=$1", preview, make([]byte, 32))
			}
			deny("23514", `UPDATE public.context_preview SET closed_at=closed_at+interval '1 second' WHERE id=$1`, preview)
			deny("42501", `INSERT INTO public.context_preview DEFAULT VALUES`)
			fence := custodyID()
			must(`INSERT INTO public.context_preview_fence(root_id,preview_id,actor_key,principal_key,request_key,submission_digest,created_at,expires_at) VALUES($1,$2,$3,$3,$3,$3,clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute')`, root, fence, digest)
			var current bool
			if e := tx.QueryRow(ctx, `SELECT expires_at>clock_timestamp() AND expires_at=created_at+interval '5 minutes' FROM public.context_preview_fence WHERE root_id=$1 AND preview_id=$2`, root, fence).Scan(&current); e != nil || !current {
				t.Fatal("fence expiry was not assigned independently", e)
			}
			deny("23514", `DELETE FROM public.context_preview_fence WHERE root_id=$1 AND preview_id=$2`, root, fence)
		}
		must(`DELETE FROM public.context_preview WHERE id=$1`, preview)
		var left int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM public.context_preview WHERE id=$1`, preview).Scan(&left); e != nil || left != 0 {
			t.Fatal("expired preview was not removed", e, left)
		}
	})
}
