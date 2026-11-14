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
	// CaptureProgressChannel carries the capture ID of each committed
	// progress revision (migration 00165).
	CaptureProgressChannel = "asservat_capture_progress"
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
			listen(ctx, pool, channel, func(string) { signal() })
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

func listen(ctx context.Context, pool *pgxpool.Pool, channel string, signal func(string)) {
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
	signal("")
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return
		}
		signal(n.Payload)
	}
}

// ListenPayloads calls publish with each notification payload on channel,
// and with "" whenever its connection is (re)established. It ends with ctx.
func ListenPayloads(ctx context.Context, pool *pgxpool.Pool, channel string, publish func(string)) {
	go func() {
		for ctx.Err() == nil {
			listen(ctx, pool, channel, publish)
			t := time.NewTimer(listenReconnect)
			select {
			case <-ctx.Done():
				t.Stop()
			case <-t.C:
			}
		}
	}()
}
