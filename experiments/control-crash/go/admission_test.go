package experiment

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

//go:embed schema.sql
var schema string
var ctx = context.Background()

func setup(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("ASSERVAT_TEST_PG")
	if url == "" {
		t.Fatal("explicit isolated PostgreSQL fixture required")
	}
	admin, e := pgx.Connect(ctx, url)
	must(t, e)
	defer admin.Close(ctx)
	name := "lab_" + strings.ToLower(strings.TrimPrefix(t.Name(), "Test"))
	name = strings.ReplaceAll(name, "/", "_")
	_, e = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{name}.Sanitize()+" CASCADE; CREATE SCHEMA "+pgx.Identifier{name}.Sanitize())
	must(t, e)
	cfg, e := pgxpool.ParseConfig(url)
	must(t, e)
	cfg.MaxConns = 32
	cfg.ConnConfig.RuntimeParams["search_path"] = name
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "1000"
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	must(t, e)
	t.Cleanup(p.Close)
	_, e = p.Exec(ctx, schema)
	must(t, e)
	_, e = p.Exec(ctx, "INSERT INTO grants(id,expires,max_starts) VALUES('g',clock_timestamp()+interval '5 minutes',1000); INSERT INTO workload(id) VALUES('a'),('b'),('c'),('d')")
	must(t, e)
	return p
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func scalar(t *testing.T, p *pgxpool.Pool, q string) int64 {
	t.Helper()
	var n int64
	must(t, p.QueryRow(ctx, q).Scan(&n))
	return n
}
func race(n int, fn func(int) error) []error {
	var wg sync.WaitGroup
	wg.Add(n)
	start := make(chan struct{})
	out := make([]error, n)
	for i := range n {
		go func(i int) { defer wg.Done(); <-start; out[i] = fn(i) }(i)
	}
	close(start)
	wg.Wait()
	return out
}
func expectErrors(t *testing.T, es []error, allowed error) int {
	t.Helper()
	ok := 0
	for _, e := range es {
		if e == nil {
			ok++
		} else if !errors.Is(e, allowed) {
			t.Fatal(e)
		}
	}
	return ok
}

func TestNaiveCrossRowQuotaFails(t *testing.T) {
	p := setup(t)
	_, e := p.Exec(ctx, "CREATE TABLE naive(n bigint)")
	must(t, e)
	ready := make(chan struct{}, 2)
	start := make(chan struct{})
	out := make(chan error, 2)
	for range 2 {
		go func() {
			tx, e := p.Begin(ctx)
			if e != nil {
				out <- e
				return
			}
			defer tx.Rollback(ctx)
			var n int64
			e = tx.QueryRow(ctx, "SELECT coalesce(sum(n),0) FROM naive").Scan(&n)
			ready <- struct{}{}
			<-start
			if e == nil && n+8 <= 8 {
				_, e = tx.Exec(ctx, "INSERT INTO naive VALUES(8)")
			}
			if e == nil {
				e = tx.Commit(ctx)
			}
			out <- e
		}()
	}
	<-ready
	<-ready
	close(start)
	must(t, <-out)
	must(t, <-out)
	if scalar(t, p, "SELECT sum(n) FROM naive") != 16 {
		t.Fatal("did not reproduce unlocked aggregate race")
	}
	t.Log("unsafe Read Committed read-sum-then-insert admitted 16 units against an 8-unit budget")
}
func TestLastGrantAndLastCapacity(t *testing.T) {
	p := setup(t)
	_, e := p.Exec(ctx, "UPDATE grants SET max_starts=1")
	must(t, e)
	ok := expectErrors(t, race(64, func(i int) error { _, e := Admit(ctx, p, request(fmt.Sprint(i), 8), nil); return e }), Denied)
	if ok != 1 || scalar(t, p, "SELECT starts FROM grants WHERE id='g'") != 1 || scalar(t, p, "SELECT count(*) FROM operation") != 1 {
		t.Fatal("grant overdraw")
	}
	_, e = p.Exec(ctx, "UPDATE grants SET max_starts=1000; UPDATE workload SET protected_b=9,hard_b=9 WHERE id='b'")
	must(t, e)
	ok = expectErrors(t, race(64, func(i int) error {
		r := request(fmt.Sprint("b", i), 8)
		r.Workload = "b"
		_, e := Admit(ctx, p, r, nil)
		return e
	}), Denied)
	if ok != 1 || scalar(t, p, "SELECT starts FROM grants WHERE id='g'") != 2 {
		t.Fatal("capacity race or rollback leak")
	}
	t.Log("64 contenders: one last grant, one 8-unit non-context reservation; losers leak no starts")
}
func TestProtectedCapacityAndObjects(t *testing.T) {
	p := setup(t)
	for _, w := range []string{"a", "c", "d"} {
		r := request(w, 31)
		r.Workload = w
		_, e := Admit(ctx, p, r, nil)
		if w == "d" {
			if !errors.Is(e, Denied) {
				t.Fatal(e)
			}
		} else {
			must(t, e)
		}
	}
	r := request("b-protected", 15)
	r.Workload = "b"
	_, e := Admit(ctx, p, r, nil)
	must(t, e)
	r = request("a-context", 1)
	r.Context = true
	_, e = Admit(ctx, p, r, nil)
	must(t, e)
	r = request("a-too-much", 1)
	_, e = Admit(ctx, p, r, nil)
	if !errors.Is(e, Denied) {
		t.Fatal(e)
	}
	r = request("d-many-objects", 1)
	r.Workload = "d"
	r.Objects = 32
	_, e = Admit(ctx, p, r, nil)
	if !errors.Is(e, Denied) {
		t.Fatal("object quota not independent", e)
	}
	if scalar(t, p, "SELECT used_b FROM pool") != 32 || scalar(t, p, "SELECT non_b+ctx_b FROM workload WHERE id='a'") != 32 {
		t.Fatal("allocation mismatch")
	}
	t.Log("A/C used their burst; B retained protected capacity; A retained context at hard ceiling; object ceiling independent")
}
func TestDuplicateOperationAndDigest(t *testing.T) {
	p := setup(t)
	var created atomic.Int64
	es := race(32, func(i int) error {
		yes, e := Admit(ctx, p, request("same", 8), nil)
		if yes && e == nil {
			created.Add(1)
		}
		return e
	})
	expectErrors(t, es, nil)
	if created.Load() != 1 || scalar(t, p, "SELECT starts FROM grants WHERE id='g'") != 1 {
		t.Fatal("duplicate spend")
	}
	r := request("same", 8)
	r.Digest = "different"
	_, e := Admit(ctx, p, r, nil)
	if !errors.Is(e, Conflict) {
		t.Fatal(e)
	}
}
func TestExpiredWhileWaitingAndTransactionClockTrap(t *testing.T) {
	p := setup(t)
	_, e := p.Exec(ctx, "UPDATE grants SET expires=clock_timestamp()+interval '350 milliseconds'")
	must(t, e)
	hold, e := p.Begin(ctx)
	must(t, e)
	defer hold.Rollback(ctx)
	_, e = hold.Exec(ctx, "SELECT id FROM grants WHERE id='g' FOR UPDATE")
	must(t, e)
	tx, e := p.Begin(ctx)
	must(t, e)
	defer tx.Rollback(ctx)
	// Freeze now() before waiting on a contended row.
	_, e = tx.Exec(ctx, "SELECT now()")
	must(t, e)
	done := make(chan error, 1)
	go func() { _, e := tx.Exec(ctx, "SELECT id FROM grants WHERE id='g' FOR UPDATE"); done <- e }()
	time.Sleep(500 * time.Millisecond)
	must(t, hold.Commit(ctx))
	must(t, <-done)
	var stale, current bool
	must(t, tx.QueryRow(ctx, "SELECT expires>now(),expires>clock_timestamp() FROM grants WHERE id='g'").Scan(&stale, &current))
	if !stale || current {
		t.Fatalf("clock trap not reproduced: stale=%v current=%v", stale, current)
	}
	must(t, tx.Rollback(ctx))
	_, e = p.Exec(ctx, "UPDATE grants SET expires=clock_timestamp()+interval '350 milliseconds'")
	must(t, e)
	hold, e = p.Begin(ctx)
	must(t, e)
	_, e = hold.Exec(ctx, "SELECT id FROM pool FOR UPDATE")
	must(t, e)
	go func() { _, e := Admit(ctx, p, request("wait", 8), nil); done <- e }()
	time.Sleep(500 * time.Millisecond)
	must(t, hold.Commit(ctx))
	if e = <-done; !errors.Is(e, Denied) {
		t.Fatal("expired admission", e)
	}
	if scalar(t, p, "SELECT starts FROM grants WHERE id='g'") != 0 {
		t.Fatal("expiry spent")
	}
	t.Log("now() remained valid after real expiry; post-lock clock_timestamp check rejected without spend")
}
func TestRevocationWinsWaitingAdmission(t *testing.T) {
	p := setup(t)
	tx, e := p.Begin(ctx)
	must(t, e)
	_, e = tx.Exec(ctx, "UPDATE grants SET revoked=true WHERE id='g'")
	must(t, e)
	out := make(chan error, 1)
	go func() { _, e := Admit(ctx, p, request("late", 8), nil); out <- e }()
	time.Sleep(50 * time.Millisecond)
	must(t, tx.Commit(ctx))
	if e = <-out; !errors.Is(e, Denied) {
		t.Fatal(e)
	}
	if scalar(t, p, "SELECT count(*) FROM work") != 0 {
		t.Fatal("revoked work exists")
	}
}

func TestPublicationExpiryAfterArtifactLockWait(t *testing.T) {
	p := setup(t)
	_, e := p.Exec(ctx, "UPDATE grants SET expires=clock_timestamp()+interval '350 milliseconds'; INSERT INTO artifact VALUES('blocked','capture',true)")
	must(t, e)
	hold, e := p.Begin(ctx)
	must(t, e)
	defer hold.Rollback(ctx)
	_, e = hold.Exec(ctx, "SELECT id FROM artifact WHERE id='blocked' FOR UPDATE")
	must(t, e)
	out := make(chan error, 1)
	go func() { out <- Publish(ctx, p, "g", "blocked", "web", "capture") }()
	time.Sleep(500 * time.Millisecond)
	must(t, hold.Commit(ctx))
	if e = <-out; !errors.Is(e, Denied) {
		t.Fatal("expired grant published a child after waiting for artifact lock", e)
	}
	if scalar(t, p, "SELECT count(*) FROM child") != 0 {
		t.Fatal("expired child persisted")
	}
}
func TestResultChildrenShareOneDisclosurePool(t *testing.T) {
	p := setup(t)
	_, e := p.Exec(ctx, "UPDATE grants SET starts=max_starts; INSERT INTO artifact VALUES('one','capture',false),('two','capture',true),('three','capture',true)")
	must(t, e)
	if e = Publish(ctx, p, "g", "one", "web", "capture"); !errors.Is(e, Denied) {
		t.Fatal("uncommitted result", e)
	}
	_, e = p.Exec(ctx, "UPDATE artifact SET committed=true WHERE id='one'")
	must(t, e)
	es := race(32, func(i int) error {
		return Publish(ctx, p, "g", []string{"one", "two"}[i%2], []string{"web", "mcp"}[(i/2)%2], "capture")
	})
	expectErrors(t, es, nil)
	if scalar(t, p, "SELECT count(*) FROM result_artifact") != 2 || scalar(t, p, "SELECT count(*) FROM child") != 4 {
		t.Fatal("duplicate output/client accounting")
	}
	for _, args := range [][3]string{{"three", "web", "capture"}, {"one", "other", "capture"}, {"one", "web", "forged"}} {
		if e = Publish(ctx, p, "g", args[0], args[1], args[2]); !errors.Is(e, Denied) {
			t.Fatal(e)
		}
	}
	n := expectErrors(t, race(64, func(i int) error {
		return Spend(ctx, p, "g", []string{"one", "two"}[i%2], []string{"web", "mcp"}[(i/2)%2], 8)
	}), Denied)
	if n != 8 || scalar(t, p, "SELECT result_spent FROM grants") != 64 {
		t.Fatal("copied result allowance", n)
	}
	_, e = p.Exec(ctx, "UPDATE grants SET revoked=true")
	must(t, e)
	if e = Spend(ctx, p, "g", "one", "web", 1); !errors.Is(e, Denied) {
		t.Fatal(e)
	}
	t.Log("collection starts exhausted, 4 children usable under one 64-unit parent pool; only 8 of 64 eight-unit spends admitted")
}
func TestUncertainChargeAndVerifiedDeletion(t *testing.T) {
	p := setup(t)
	_, e := Admit(ctx, p, request("uncertain", 31), nil)
	must(t, e)
	_, e = p.Exec(ctx, "UPDATE operation SET state='indeterminate'")
	must(t, e)
	if e = Release(ctx, p, "uncertain", false); !errors.Is(e, Denied) {
		t.Fatal(e)
	}
	if scalar(t, p, "SELECT non_b FROM workload WHERE id='a'") != 31 {
		t.Fatal("uncertainty refunded")
	}
	expectErrors(t, race(32, func(int) error { return Release(ctx, p, "uncertain", true) }), nil)
	if scalar(t, p, "SELECT non_b FROM workload WHERE id='a'") != 0 || scalar(t, p, "SELECT used_b FROM pool") != 0 || scalar(t, p, "SELECT starts FROM grants") != 1 {
		t.Fatal("release duplicated or action count refunded")
	}
}

type dropCommitReply struct {
	net.Conn
	armed    atomic.Bool
	observed atomic.Bool
}

func (c *dropCommitReply) Read(p []byte) (int, error) {
	if !c.armed.Load() {
		return c.Conn.Read(p)
	}
	var data []byte
	b := make([]byte, 4096)
	for len(data) < 65536 {
		n, e := c.Conn.Read(b)
		data = append(data, b[:n]...)
		if bytes.Contains(data, []byte("COMMIT\x00")) {
			c.observed.Store(true)
			c.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		if e != nil {
			return 0, e
		}
	}
	return 0, errors.New("fault proxy bound")
}
func TestCommitAcknowledgementLost(t *testing.T) {
	p := setup(t)
	cfg := p.Config().ConnConfig.Copy()
	var first atomic.Pointer[dropCommitReply]
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, network, address)
		if e != nil {
			return nil, e
		}
		candidate := &dropCommitReply{Conn: c}
		if first.CompareAndSwap(nil, candidate) {
			return candidate, nil
		}
		return c, nil
	}
	c, e := pgx.ConnectConfig(ctx, cfg)
	must(t, e)
	defer c.Close(ctx)
	wire := first.Load()
	_, e = Admit(ctx, c, request("lost-ack", 8), func(pgx.Tx) error { wire.armed.Store(true); return nil })
	if e == nil || !wire.observed.Load() {
		t.Fatal("did not drop a real committed acknowledgement", e)
	}
	created, e := Admit(ctx, p, request("lost-ack", 8), nil)
	must(t, e)
	if created || scalar(t, p, "SELECT starts FROM grants") != 1 || scalar(t, p, "SELECT count(*) FROM work") != 1 {
		t.Fatal("unknown commit duplicated")
	}
	t.Log("discarded real server COMMIT acknowledgement; original key resolved to exactly one spent reservation/work item")
}
func TestBackendTerminationRollsBackAdmission(t *testing.T) {
	p := setup(t)
	_, e := Admit(ctx, p, request("killed", 8), func(tx pgx.Tx) error {
		var ok bool
		return p.QueryRow(ctx, "SELECT pg_terminate_backend($1)", tx.Conn().PgConn().PID()).Scan(&ok)
	})
	if e == nil {
		t.Fatal("backend termination did not fail commit")
	}
	if scalar(t, p, "SELECT starts FROM grants") != 0 || scalar(t, p, "SELECT count(*) FROM work") != 0 || scalar(t, p, "SELECT non_b FROM workload WHERE id='a'") != 0 {
		t.Fatal("partial reservation survived aborted transaction")
	}
}
func TestSerializableUnprotectedPredicate(t *testing.T) {
	p := setup(t)
	_, e := p.Exec(ctx, "CREATE TABLE predicate(id int PRIMARY KEY,n int); INSERT INTO predicate VALUES(1,0),(2,0)")
	must(t, e)
	tx1, e := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	must(t, e)
	defer tx1.Rollback(ctx)
	tx2, e := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	must(t, e)
	defer tx2.Rollback(ctx)
	var n int
	must(t, tx1.QueryRow(ctx, "SELECT sum(n) FROM predicate").Scan(&n))
	must(t, tx2.QueryRow(ctx, "SELECT sum(n) FROM predicate").Scan(&n))
	_, e = tx1.Exec(ctx, "UPDATE predicate SET n=8 WHERE id=1")
	must(t, e)
	_, e = tx2.Exec(ctx, "UPDATE predicate SET n=8 WHERE id=2")
	must(t, e)
	e1, e2 := tx1.Commit(ctx), tx2.Commit(ctx)
	var pe *pgconn.PgError
	if e1 != nil || !errors.As(e2, &pe) || pe.Code != "40001" {
		t.Fatalf("SSI: %v / %v", e1, e2)
	}
	// A fresh complete retry sees the already spent capacity and does not write.
	retry, e := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	must(t, e)
	must(t, retry.QueryRow(ctx, "SELECT sum(n) FROM predicate").Scan(&n))
	if n != 8 {
		t.Fatal(n)
	}
	must(t, retry.Commit(ctx))
	t.Log("unlocked predicate conflict aborted with 40001; fresh complete retry observed exhausted capacity")
}
func TestAuditedWorkClaimsAndFences(t *testing.T) {
	p := setup(t)
	for i := range 12 {
		_, e := Admit(ctx, p, request(fmt.Sprintf("job-%02d", i), 1), nil)
		must(t, e)
	}
	tx, e := p.Begin(ctx)
	must(t, e)
	_, _, e = Claim(ctx, tx)
	if !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("unaudited dispatch", e)
	}
	must(t, tx.Rollback(ctx))
	_, e = p.Exec(ctx, "UPDATE work SET audited=true")
	must(t, e)
	var mu sync.Mutex
	claimed := map[string]int64{}
	expectErrors(t, race(24, func(int) error {
		tx, e := p.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(ctx)
		id, f, e := Claim(ctx, tx)
		if e != nil {
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := claimed[id]; exists {
			return errors.New("duplicate claim")
		}
		claimed[id] = f
		return nil
	}), pgx.ErrNoRows)
	if len(claimed) != 12 {
		t.Fatal(len(claimed))
	}
	_, e = p.Exec(ctx, "UPDATE work SET lease_until=clock_timestamp()-interval '1 second' WHERE id='job-00'")
	must(t, e)
	tx, e = p.Begin(ctx)
	must(t, e)
	id, f, e := Claim(ctx, tx)
	must(t, e)
	must(t, tx.Commit(ctx))
	if id != "job-00" || f != 2 {
		t.Fatal(id, f)
	}
	tag, e := p.Exec(ctx, "UPDATE work SET done=true WHERE id=$1 AND fence=$2", id, 1)
	must(t, e)
	if tag.RowsAffected() != 0 {
		t.Fatal("stale completion")
	}
	t.Log("audit gate; 24 workers claimed 12 distinct items; reclaimed lease rejected fence-1 completion. No remote effect executed")
}
func TestPrepareDurabilityMarker(t *testing.T) {
	p := setup(t)
	_, e := p.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS asservat_durable; CREATE TABLE IF NOT EXISTS asservat_durable.marker(id int PRIMARY KEY,revoked bool,charge bigint); INSERT INTO asservat_durable.marker VALUES(1,true,8) ON CONFLICT(id) DO UPDATE SET revoked=true,charge=8")
	must(t, e)
	var fsync, commit string
	must(t, p.QueryRow(ctx, "SHOW fsync").Scan(&fsync))
	must(t, p.QueryRow(ctx, "SHOW synchronous_commit").Scan(&commit))
	if fsync != "on" || commit != "on" {
		t.Fatal(fsync, commit)
	}
}
func TestAfterRestartDurability(t *testing.T) {
	if os.Getenv("ASSERVAT_AFTER_RESTART") != "1" {
		t.Skip("separate post-restart invocation")
	}
	c, e := pgx.Connect(ctx, os.Getenv("ASSERVAT_TEST_PG"))
	must(t, e)
	defer c.Close(ctx)
	var revoked bool
	var charge int64
	must(t, c.QueryRow(ctx, "SELECT revoked,charge FROM asservat_durable.marker WHERE id=1").Scan(&revoked, &charge))
	if !revoked || charge != 8 {
		t.Fatal("acknowledged marker lost")
	}
	t.Log("single-primary abrupt restart preserved acknowledged denial and uncertain charge; not HA/failover/PITR proof")
}
