package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	subscribeBackoffStart = 1 * time.Second
	subscribeBackoffMax   = 30 * time.Second
)

// Subscribe holds a pool connection open with LISTEN <channel> and
// pumps wakeups (non-blocking) into out on every notification. It
// reconnects with backoff on errors and returns when ctx is cancelled.
//
// out is best-effort: if a wakeup is pending the next one is dropped.
// That's fine because consumers do FetchTasks/FetchPending in a loop —
// they'll see whatever is in the table regardless of how many notifies
// arrived.
func Subscribe(ctx context.Context, pool *pgxpool.Pool, channel string, out chan<- struct{}, log *slog.Logger) {
	backoff := subscribeBackoffStart
	for {
		if ctx.Err() != nil {
			return
		}
		err := subscribeOnce(ctx, pool, channel, out)
		if ctx.Err() != nil {
			return
		}
		log.Warn("LISTEN connection lost, reconnecting",
			"channel", channel, "err", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, subscribeBackoffMax)
	}
}

func subscribeOnce(ctx context.Context, pool *pgxpool.Pool, channel string, out chan<- struct{}) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}

	for {
		_, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		select {
		case out <- struct{}{}:
		default:
		}
	}
}
