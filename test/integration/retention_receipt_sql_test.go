package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pure predicate and actual planner qualification only. This test grants no
// source observation, recovery authority or encrypted-audit acknowledgement.
func TestRetentionReceiptPredicatesWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("owned custody PostgreSQL fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	if err != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, end := context.WithTimeout(context.Background(), 90*time.Second)
	defer end()
	config, err := pgxpool.ParseConfig(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 2
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	root, event := custodyID(), custodyID()
	for _, purpose := range []struct {
		name, key, sql string
		max            int64
		valid          func(audit.Receipt) bool
	}{
		{"checkpoint", audit.RetentionAcceptanceKey(root, event), "SELECT public.retention_checkpoint_receipt_current($1,$2,$3)", 512 << 10, func(r audit.Receipt) bool { return r.ValidRetentionAcceptance(root, event) }},
		{"lifecycle", audit.LifecycleKey(root, event), "SELECT public.retention_lifecycle_receipt_current($1,$2,$3)", 128 << 10, func(r audit.Receipt) bool { return r.ValidLifecycle(root, event) }},
	} {
		t.Run(purpose.name, func(t *testing.T) {
			valid := audit.Receipt{Key: purpose.key, Version: "original", ETag: "original", Bytes: purpose.max, SHA256: artifact.Digest{1}}
			for _, tc := range []struct {
				name  string
				alter func(*audit.Receipt)
			}{
				{"original", func(*audit.Receipt) {}}, {"empty", func(r *audit.Receipt) { r.Version = "" }},
				{"null", func(r *audit.Receipt) { r.Version = "null" }}, {"maximum-version", func(r *audit.Receipt) { r.Version = strings.Repeat("v", 1024) }},
				{"long-version", func(r *audit.Receipt) { r.Version = strings.Repeat("v", 1025) }},
				{"utf8-byte-bound", func(r *audit.Receipt) { r.Version = strings.Repeat("é", 513) }},
				{"unicode-control", func(r *audit.Receipt) { r.Version = "original\u0085" }},
				{"ascii-control", func(r *audit.Receipt) { r.ETag = "original\u007f" }},
				{"printable-unicode", func(r *audit.Receipt) { r.Version = "version\u00a0" }},
				{"maximum-etag", func(r *audit.Receipt) { r.ETag = strings.Repeat("e", 256) }},
				{"long-etag", func(r *audit.Receipt) { r.ETag = strings.Repeat("e", 257) }},
				{"empty-etag", func(r *audit.Receipt) { r.ETag = "" }},
				{"oversize", func(r *audit.Receipt) { r.Bytes++ }}, {"zero-size", func(r *audit.Receipt) { r.Bytes = 0 }},
				{"negative-size", func(r *audit.Receipt) { r.Bytes = -1 }},
				{"zero-digest", func(r *audit.Receipt) { r.SHA256 = artifact.Digest{} }},
				{"wrong-key", func(r *audit.Receipt) { r.Key += "/replacement" }},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := valid
					tc.alter(&r)
					data, err := json.Marshal(r)
					if err != nil {
						t.Fatal(err)
					}
					var got bool
					if err = admin.QueryRow(ctx, purpose.sql, root, event, data).Scan(&got); err != nil {
						t.Fatal("canonical SQL receipt", err)
					}
					if got != purpose.valid(r) {
						t.Fatal("canonical Go/SQL predicate mismatch", got, purpose.valid(r))
					}
				})
			}
			original, err := json.Marshal(valid)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(original, &fields) != nil {
				t.Fatal("canonical fixture")
			}
			for _, tc := range []struct {
				name  string
				alter func(map[string]json.RawMessage)
			}{
				{"unknown-field", func(m map[string]json.RawMessage) { m["Unexpected"] = json.RawMessage(`true`) }},
				{"missing-field", func(m map[string]json.RawMessage) { delete(m, "Version") }},
				{"casefold-field", func(m map[string]json.RawMessage) { m["version"] = m["Version"]; delete(m, "Version") }},
				{"json-null-version", func(m map[string]json.RawMessage) { m["Version"] = json.RawMessage(`null`) }},
				{"fractional-bytes", func(m map[string]json.RawMessage) { m["Bytes"] = json.RawMessage(`1.5`) }},
				{"enormous-bytes", func(m map[string]json.RawMessage) { m["Bytes"] = json.RawMessage(`99999999999999999999999999999999`) }},
				{"short-digest", func(m map[string]json.RawMessage) { m["SHA256"] = json.RawMessage(`[1]`) }},
				{"null-digest", func(m map[string]json.RawMessage) { m["SHA256"] = json.RawMessage(`null`) }},
				{"long-digest", func(m map[string]json.RawMessage) {
					m["SHA256"] = append(append([]byte{}, m["SHA256"][:len(m["SHA256"])-1]...), []byte(",0]")...)
				}},
				{"null-octet", func(m map[string]json.RawMessage) {
					m["SHA256"] = bytes.Replace(m["SHA256"], []byte("[1,"), []byte("[null,"), 1)
				}},
				{"fractional-octet", func(m map[string]json.RawMessage) {
					m["SHA256"] = bytes.Replace(m["SHA256"], []byte("[1,"), []byte("[0.5,"), 1)
				}},
				{"text-octet", func(m map[string]json.RawMessage) {
					m["SHA256"] = bytes.Replace(m["SHA256"], []byte("[1,"), []byte(`["1",`), 1)
				}},
				{"numeric-version", func(m map[string]json.RawMessage) { m["Version"] = json.RawMessage(`123`) }},
				{"null-etag", func(m map[string]json.RawMessage) { m["ETag"] = json.RawMessage(`null`) }},
				{"text-bytes", func(m map[string]json.RawMessage) { m["Bytes"] = json.RawMessage(`"64"`) }},
				{"overflow-octet", func(m map[string]json.RawMessage) {
					m["SHA256"] = bytes.Replace(m["SHA256"], []byte("[1,"), []byte("[256,"), 1)
				}},
				{"negative-octet", func(m map[string]json.RawMessage) {
					m["SHA256"] = bytes.Replace(m["SHA256"], []byte("[1,"), []byte("[-1,"), 1)
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					m := make(map[string]json.RawMessage, len(fields))
					for k, v := range fields {
						m[k] = bytes.Clone(v)
					}
					tc.alter(m)
					data, err := json.Marshal(m)
					if err != nil {
						t.Fatal(err)
					}
					var got bool
					if err = admin.QueryRow(ctx, purpose.sql, root, event, data).Scan(&got); err != nil || got {
						t.Fatal("closed SQL receipt accepted", got, err)
					}
				})
			}
			for _, tc := range []struct {
				name string
				data []byte
			}{
				{"sql-null", nil}, {"json-null", []byte(`null`)}, {"array", []byte(`[]`)},
				{"oversize-json", []byte(`{"padding":"` + strings.Repeat("x", 4097) + `"}`)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var got bool
					if err := admin.QueryRow(ctx, purpose.sql, root, event, tc.data).Scan(&got); err != nil || got {
						t.Fatal("invalid receipt accepted", got, err)
					}
				})
			}
			for _, scope := range []struct {
				name        string
				root, event any
			}{
				{"missing-root", nil, event}, {"zero-root", "00000000-0000-0000-0000-000000000000", event},
				{"foreign-root", custodyID(), event}, {"foreign-event", root, custodyID()},
			} {
				t.Run(scope.name, func(t *testing.T) {
					var got bool
					if err := admin.QueryRow(ctx, purpose.sql, scope.root, scope.event, original).Scan(&got); err != nil || got {
						t.Fatal("wrong original scope accepted", got, err)
					}
				})
			}
			// bytea preserves spelling. JSONB has already discarded duplicate keys and
			// exponent spelling, so no full noncanonical Go/SQL parser equivalence claim.
			if purpose.name == "lifecycle" {
				for _, tc := range []struct {
					name string
					data []byte
				}{
					{"invalid-utf8", []byte{0xff}}, {"truncated-json", []byte(`{"Version":`)}, {"zero-byte", []byte{0}},
					{"duplicate", append([]byte(`{"Version":"original",`), original[1:]...)},
					{"exponent", bytes.Replace(original, []byte(`"Bytes":131072`), []byte(`"Bytes":1e1`), 1)},
					{"integer-fraction", bytes.Replace(original, []byte(`"Bytes":131072`), []byte(`"Bytes":1.0`), 1)},
					{"digest-exponent", bytes.Replace(original, []byte(`[1,`), []byte(`[1e0,`), 1)},
					{"overflow-json-number", []byte(`{"Bytes":1e999999999}`)},
				} {
					t.Run(tc.name, func(t *testing.T) {
						var got bool
						if err := admin.QueryRow(ctx, purpose.sql, root, event, tc.data).Scan(&got); err != nil || got {
							t.Fatal("malformed bytea receipt accepted", got, err)
						}
					})
				}
			}
			t.Run("cancel-propagates", func(t *testing.T) {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				var got bool
				if err := admin.QueryRow(cancelled, purpose.sql, root, event, original).Scan(&got); !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled read returned a value", err)
				}
			})
		})
	}
	t.Run("pure-invoker-public-capability", func(t *testing.T) {
		for _, signature := range []string{"public.retention_checkpoint_receipt_current(uuid,uuid,jsonb)", "public.retention_lifecycle_receipt_current(uuid,uuid,bytea)"} {
			var immutable, invoker, publicExecute bool
			var config []string
			err := admin.QueryRow(ctx, `SELECT p.provolatile='i',NOT p.prosecdef,p.proconfig,EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc p WHERE p.oid=$1::regprocedure`, signature).Scan(&immutable, &invoker, &config, &publicExecute)
			if err != nil || !immutable || !invoker || !publicExecute || len(config) != 1 || strings.ReplaceAll(config[0], " ", "") != "search_path=pg_catalog,pg_temp" {
				t.Fatal("unexpected pure predicate ACL/definition", err, immutable, invoker, publicExecute, config)
			}
		}
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SET LOCAL ROLE retention_source_read_runtime"); err != nil {
			t.Fatal(err)
		}
		var first, second bool
		if err = tx.QueryRow(ctx, "SELECT public.retention_checkpoint_receipt_current($1,$2,NULL),public.retention_lifecycle_receipt_current($1,$2,NULL)", root, event).Scan(&first, &second); err != nil || first || second {
			t.Fatal("pure read role cannot evaluate receipt", err)
		}
		if _, err = tx.Exec(ctx, "UPDATE retention_checkpoint SET audit_acknowledged_at=clock_timestamp()"); err == nil {
			t.Fatal("reader acquired acknowledgement rights")
		} else {
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
				t.Fatal("wrong denial", err)
			}
		}
	})
	qualifyRetentionReceiptPlans(t, ctx, admin)
}
