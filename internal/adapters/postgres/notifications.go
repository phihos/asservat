package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Notification channels of the joined clusters' stored deliveries
// (migration 00163 triggers, ADR-329/330).
const (
	RemoteBindingsChannel = "asservat_remote_bindings"
	RemoteCapacityChannel = "asservat_remote_capacity"
)

// listenReconnect spaces reconnects of a failed notification connection.
const listenReconnect = 5 * time.Second

// Listen signals on the returned channel for each notification on channel
// and once whenever its own connection (with the pool's login, outside the
// pool) is (re)established, so a reader rereads whatever it may have missed.
// Signals coalesce; the goroutine ends with ctx.
func Listen(ctx context.Context, pool *pgxpool.Pool, channel string) <-chan struct{} {
	out := make(chan struct{}, 1)
	signal := func() {
		select {
		case out <- struct{}{}:
		default:
		}
	}
	go func() {
		for ctx.Err() == nil {
			listen(ctx, pool, channel, signal)
			t := time.NewTimer(listenReconnect)
			select {
			case <-ctx.Done():
				t.Stop()
			case <-t.C:
			}
		}
	}()
	return out
}

func listen(ctx context.Context, pool *pgxpool.Pool, channel string, signal func()) {
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return
	}
	defer func() {
		closing, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = conn.Close(closing)
	}()
	if _, err = conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return
	}
	signal()
	for {
		if _, err = conn.WaitForNotification(ctx); err != nil {
			return
		}
		signal()
	}
}
