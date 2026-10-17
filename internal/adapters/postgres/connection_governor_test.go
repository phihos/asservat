package postgres

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func governedTestConfig(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) *pgxpool.Config {
	t.Helper()
	c, err := pgxpool.ParseConfig("host=localhost port=1 user=unused password=unused dbname=unused sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	c.MaxConns, c.MinConns = 1, 0
	c.ConnConfig.DialFunc = dial
	return c
}

func TestSQLConnectionGovernorBoundsSocketsNotLogins(t *testing.T) {
	var server []net.Conn
	pipe := func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		server = append(server, b)
		return a, nil
	}
	short := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 50*time.Millisecond)
	}
	g, err := NewSQLConnectionGovernor(3, 1)
	if err != nil {
		t.Fatal(err)
	}
	hot, coldA, coldB, coldC := governedTestConfig(t, pipe), governedTestConfig(t, pipe), governedTestConfig(t, pipe), governedTestConfig(t, pipe)
	for _, c := range []*pgxpool.Config{coldA, coldB, coldC} {
		if err = g.Govern(c, false); err != nil {
			t.Fatal(err)
		}
		if c.AfterRelease == nil || c.AfterRelease(nil) {
			t.Fatal("cold purpose keeps idle connections")
		}
	}
	if err = g.Govern(hot, true); err != nil || hot.AfterRelease != nil {
		t.Fatal("hot purpose", err)
	}
	if g.Govern(governedTestConfig(t, pipe), true) == nil {
		t.Fatal("more hot purposes than reserved")
	}
	ctx := context.Background()
	// Two shared slots: a third cold socket waits until one closes.
	a, err := coldA.ConnConfig.DialFunc(ctx, "tcp", "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coldB.ConnConfig.DialFunc(ctx, "tcp", "x"); err != nil {
		t.Fatal(err)
	}
	call, stop := short()
	if _, err = coldC.ConnConfig.DialFunc(call, "tcp", "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shared limit exceeded", err)
	}
	stop()
	// The hot purpose has its own slot and is never starved by cold ones.
	h, err := hot.ConnConfig.DialFunc(ctx, "tcp", "x")
	if err != nil {
		t.Fatal("hot purpose starved", err)
	}
	call, stop = short()
	if _, err = hot.ConnConfig.DialFunc(call, "tcp", "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("hot purpose opened a second socket while the first is open", err)
	}
	stop()
	_ = h.Close()
	_ = a.Close()
	_ = a.Close() // a repeated close returns its slot only once
	if _, err = coldC.ConnConfig.DialFunc(ctx, "tcp", "x"); err != nil {
		t.Fatal("closed socket did not return its slot", err)
	}
	call, stop = short()
	if _, err = coldA.ConnConfig.DialFunc(call, "tcp", "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("double close released two slots", err)
	}
	stop()
	// A failed dial never keeps a slot.
	g2, _ := NewSQLConnectionGovernor(1, 0)
	failing := governedTestConfig(t, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") })
	if err = g2.Govern(failing, false); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err = failing.ConnConfig.DialFunc(ctx, "tcp", "x"); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("failed dial leaked its slot", err)
		}
	}
	for _, s := range server {
		_ = s.Close()
	}
}

func TestSQLConnectionGovernorRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := NewSQLConnectionGovernor(0, 0); err == nil {
		t.Fatal("empty governor")
	}
	if _, err := NewSQLConnectionGovernor(2, 3); err == nil {
		t.Fatal("more hot than limit")
	}
	allHot, _ := NewSQLConnectionGovernor(1, 1)
	if allHot.Govern(governedTestConfig(t, nil), false) == nil {
		t.Fatal("cold purpose without a shared slot")
	}
	g, _ := NewSQLConnectionGovernor(4, 2)
	wide := governedTestConfig(t, nil)
	wide.MaxConns = 3
	if g.Govern(wide, true) == nil {
		t.Fatal("hot pool wider than its reserved slots")
	}
	idle := governedTestConfig(t, nil)
	idle.MinConns = 1
	if g.Govern(idle, false) == nil {
		t.Fatal("cold pool holding idle connections")
	}
}
