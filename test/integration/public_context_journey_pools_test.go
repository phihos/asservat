package integration

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The journey has one credential owner. Only two explicitly identical reader
// purposes are shared. Other roles and all existing pool limits stay separate.
// No Reset, idle eviction, role switching, or reconnect policy is introduced.
type publicJourneyPool struct {
	role, password string
	pool           *pgxpool.Pool
}
type publicJourneyPools struct {
	t       *testing.T
	open    func(string, string) *pgxpool.Pool
	mu      sync.Mutex
	owned   []publicJourneyPool
	shared  map[string]publicJourneyPool
	retired map[string]bool
}

// Retire closes a purpose's pool after the journey's last call that uses it and
// refuses to reopen it. Native25/26/28/34 hit SQLSTATE 53300 opening the
// publication facets with 44 of the unchanged 45 ordinary slots already held.
// This is a finite fixture lifetime, not idle eviction, a pool reset or a limit change.
func (p *publicJourneyPools) Retire(role string) {
	p.t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	closed := 0
	for _, v := range p.owned {
		if v.role == role {
			v.pool.Close()
			closed++
		}
	}
	if closed == 0 || p.retired[role] {
		p.t.Fatal("journey pool retirement inventory changed")
	}
	if p.retired == nil {
		p.retired = map[string]bool{}
	}
	p.retired[role] = true
}

func newPublicJourneyPools(t *testing.T, open func(string, string) *pgxpool.Pool) *publicJourneyPools {
	return &publicJourneyPools{t: t, open: open, shared: make(map[string]publicJourneyPool)}
}
func (p *publicJourneyPools) Open(role, password string) *pgxpool.Pool {
	p.t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	share := role == "context_catalog_read_runtime" || role == "api_execution_read_runtime"
	if p.retired[role] {
		p.t.Fatal("journey reopened a retired pool purpose")
	}
	if existing, ok := p.shared[role]; ok {
		if !share || existing.password != password {
			p.t.Fatal("journey reader credential mismatch")
		}
		return existing.pool
	}
	if len(p.owned) >= 64 || !publicJourneyRoleName(role) {
		p.t.Fatal("journey pool inventory exceeded")
	}
	v := publicJourneyPool{role, password, p.open(role, password)}
	p.owned = append(p.owned, v)
	if share {
		p.shared[role] = v
	}
	return v.pool
}
func publicJourneyRoleName(v string) bool {
	if len(v) == 0 || len(v) > 63 {
		return false
	}
	for _, c := range v {
		if c != '_' && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// Diagnostic snapshots are bounded reads using the existing fixture admin.
// They include all actual database clients, including pre-journey pools and the
// independent owner reader. No query text, IDs, DSNs, or credentials are logged.
// Counts are snapshots, never a claimed continuous high-water mark.
func (p *publicJourneyPools) Snapshot(parent context.Context, admin *pgxpool.Pool, phase string) {
	p.t.Helper()
	switch phase {
	case "regional-ready", "native-ready", "before-audit", "assembly-ready", "before-publication", "published", "exit":
	default:
		p.t.Fatal("unknown journey connection diagnostic phase")
	}
	p.mu.Lock()
	type counts struct {
		pools, total, acquired, idle, acquires, waits, canceled int64
		waited                                                  time.Duration
	}
	byRole := make(map[string]counts)
	for _, v := range p.owned {
		s := v.pool.Stat()
		c := byRole[v.role]
		c.pools++
		c.total += int64(s.TotalConns())
		c.acquired += int64(s.AcquiredConns())
		c.idle += int64(s.IdleConns())
		// Cumulative pgx counters: acquisitions that found no idle connection,
		// their total wait and canceled acquisitions. Counts/durations only.
		c.acquires += s.AcquireCount()
		c.waits += s.EmptyAcquireCount()
		c.canceled += s.CanceledAcquireCount()
		c.waited += s.EmptyAcquireWaitTime()
		byRole[v.role] = c
	}
	p.mu.Unlock()
	roles := make([]string, 0, len(byRole))
	for role := range byRole {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		c := byRole[role]
		p.t.Logf("journey SQL phase=%s role=%s owned-pools=%d total=%d acquired=%d idle=%d acquires=%d empty-acquires=%d canceled-acquires=%d empty-wait=%s", phase, role, c.pools, c.total, c.acquired, c.idle, c.acquires, c.waits, c.canceled, c.waited)
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	c, err := admin.Acquire(ctx)
	if err != nil {
		p.t.Logf("journey SQL phase=%s diagnostic=admin-acquire-unavailable", phase)
		return
	}
	defer c.Release()
	var maximum, reserved, superuser int
	if err = c.QueryRow(ctx, `SELECT current_setting('max_connections')::int,current_setting('reserved_connections')::int,current_setting('superuser_reserved_connections')::int`).Scan(&maximum, &reserved, &superuser); err != nil {
		p.t.Logf("journey SQL phase=%s diagnostic=settings-unavailable", phase)
		return
	}
	rows, err := c.Query(ctx, `SELECT coalesce(usename,''),coalesce(state,''),count(*) FROM pg_stat_activity WHERE datname=current_database() AND backend_type='client backend' GROUP BY usename,state ORDER BY usename,state LIMIT 65`)
	if err != nil {
		p.t.Logf("journey SQL phase=%s diagnostic=activity-unavailable", phase)
		return
	}
	defer rows.Close()
	n, total := 0, int64(0)
	for rows.Next() {
		n++
		var role, state string
		var count int64
		if n > 64 || rows.Scan(&role, &state, &count) != nil || !publicJourneyRoleName(role) || count < 1 || count > int64(maximum) {
			p.t.Logf("journey SQL phase=%s diagnostic=activity-invalid", phase)
			return
		}
		switch state {
		case "active", "idle", "idle in transaction", "idle in transaction (aborted)", "disabled":
		default:
			state = "unclassified"
		}
		total += count
		p.t.Logf("journey SQL phase=%s database-role=%s state=%s connections=%d", phase, role, state, count)
	}
	if rows.Err() != nil {
		p.t.Logf("journey SQL phase=%s diagnostic=activity-incomplete", phase)
		return
	}
	p.t.Logf("journey SQL phase=%s database-connections=%d maximum=%d reserved=%d superuser-reserved=%d", phase, total, maximum, reserved, superuser)
}

func TestPublicJourneyPoolRetirementIsFinal(t *testing.T) {
	open := func(role, password string) *pgxpool.Pool {
		// MinConns=0 pools never dial here; this checks only registry ownership.
		c, err := pgxpool.ParseConfig("postgres://" + role + ":" + password + "@127.0.0.1:1/none?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		p, err := pgxpool.NewWithConfig(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	pools := newPublicJourneyPools(t, open)
	retired := pools.Open("context_preview_runtime", "synthetic-context-preview")
	kept := pools.Open("context_progress_read_runtime", "synthetic-context-progress")
	pools.Retire("context_preview_runtime")
	if _, err := retired.Acquire(context.Background()); err == nil {
		t.Fatal("retired pool still usable")
	}
	if kept.Stat().MaxConns() < 1 || !pools.retired["context_preview_runtime"] || pools.retired["context_progress_read_runtime"] {
		t.Fatal("retirement affected another purpose")
	}
}
