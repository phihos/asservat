package postgres

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrConnectionGovernor = errors.New("SQL connection governor configuration rejected")

// SQLConnectionGovernor bounds the physical PostgreSQL connections of one
// process (ADR-177). Every governed pool keeps its own login. A connection
// holds one slot for exactly the lifetime of its socket: the slot is taken
// before dialing and returned when the socket closes, so a failed
// TLS/authentication handshake cannot leak it. Hot purposes own MaxConns
// dedicated slots and keep their connections; cold purposes share the
// remaining slots and close their connection when it is released. Waiting
// for a slot is bounded by the caller's own context; there is no background
// reconnect.
type SQLConnectionGovernor struct {
	mu         sync.Mutex
	limit, hot int
	assigned   int
	shared     chan struct{}
}

// NewSQLConnectionGovernor reserves hot dedicated slots out of limit for the
// hot pools' MaxConns. The rest are shared by cold purposes, so at least one
// must remain when any cold purpose is governed.
func NewSQLConnectionGovernor(limit, hot int) (*SQLConnectionGovernor, error) {
	if limit < 1 || limit > 64 || hot < 0 || hot > limit {
		return nil, ErrConnectionGovernor
	}
	return &SQLConnectionGovernor{limit: limit, hot: hot, shared: make(chan struct{}, limit-hot)}, nil
}

// Govern configures one purpose's pool. It must be called before the pool is
// created; a config can be governed only once.
func (g *SQLConnectionGovernor) Govern(c *pgxpool.Config, hot bool) error {
	if g == nil || c == nil || c.ConnConfig == nil || c.MaxConns < 1 || c.MinConns != 0 {
		return ErrConnectionGovernor
	}
	slots := g.shared
	if hot {
		n := int(c.MaxConns)
		g.mu.Lock()
		if g.assigned+n > g.hot {
			g.mu.Unlock()
			return ErrConnectionGovernor
		}
		g.assigned += n
		g.mu.Unlock()
		slots = make(chan struct{}, n)
	} else if cap(g.shared) == 0 {
		return ErrConnectionGovernor
	}
	dial := c.ConnConfig.DialFunc
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 5 * time.Minute}).DialContext
	}
	c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		conn, err := dial(ctx, network, address)
		if err != nil {
			<-slots
			return nil, err
		}
		return &governedConn{Conn: conn, release: sync.OnceFunc(func() { <-slots })}, nil
	}
	if !hot {
		// A cold purpose never keeps an idle connection between transactions.
		c.AfterRelease = func(*pgx.Conn) bool { return false }
	}
	return nil
}

type governedConn struct {
	net.Conn
	release func()
}

func (c *governedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}
