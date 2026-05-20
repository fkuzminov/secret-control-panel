// Package daemon implements the dispatch side of the panel: it picks
// tasks queued by scp-listener, fans them out into per-cluster events
// against the policy, then POSTs each pending event to the matching
// cluster agent. Retries with exponential backoff are owned here.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"secret-control-panel/internal/shared/wire"
)

// PostgreSQL LISTEN/NOTIFY channel names.
const (
	TasksChannel  = "tasks_new"
	EventsChannel = "events_new"
)

// Store is the daemon's view of the database.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps an existing pgx pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Task is one inbox row queued by the listener.
type Task struct {
	ID    int64
	Event wire.SecretEvent
}

// FetchTasks returns up to limit tasks ordered by id (oldest first).
func (s *Store) FetchTasks(ctx context.Context, limit int) ([]Task, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, request_id, operation, mount, path, version, created_at
		FROM tasks
		ORDER BY id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("select tasks: %w", err)
	}
	defer rows.Close()

	var out []Task
	for rows.Next() {
		var t Task
		var op string
		if err := rows.Scan(
			&t.ID, &t.Event.RequestID, &op,
			&t.Event.Mount, &t.Event.Path, &t.Event.Version, &t.Event.Time,
		); err != nil {
			return nil, fmt.Errorf("scan task: %w", err)
		}
		t.Event.Operation = wire.Operation(op)
		out = append(out, t)
	}
	return out, rows.Err()
}

// FanoutTask atomically inserts one event per cluster (idempotent on
// (request_id, cluster)) and deletes the task. If clusters is empty,
// only the task is deleted (no policy match). NOTIFY events_new fires
// only when at least one event row was actually inserted.
func (s *Store) FanoutTask(ctx context.Context, taskID int64, ev wire.SecretEvent, clusters []string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var inserted int64
	for _, cluster := range clusters {
		tag, err := tx.Exec(ctx, `
			INSERT INTO events (request_id, cluster, operation, mount, path, version, status)
			VALUES ($1, $2, $3, $4, $5, $6, 'pending')
			ON CONFLICT (request_id, cluster) DO NOTHING
		`, ev.RequestID, cluster, string(ev.Operation), ev.Mount, ev.Path, ev.Version)
		if err != nil {
			return fmt.Errorf("insert event for cluster %q: %w", cluster, err)
		}
		inserted += tag.RowsAffected()
	}

	if _, err := tx.Exec(ctx, `DELETE FROM tasks WHERE id = $1`, taskID); err != nil {
		return fmt.Errorf("delete task: %w", err)
	}

	if inserted > 0 {
		if _, err := tx.Exec(ctx, `NOTIFY `+EventsChannel); err != nil {
			return fmt.Errorf("notify: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// PendingEvent is an event row that needs to be (re-)dispatched.
type PendingEvent struct {
	ID       int64
	Cluster  string
	Attempts int
	Event    wire.SecretEvent
}

// FetchPending returns events ready for dispatch: status='pending' or
// status='failed' whose retry deadline has passed.
func (s *Store) FetchPending(ctx context.Context, limit int) ([]PendingEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, cluster, attempts, request_id, operation, mount, path, version
		FROM events
		WHERE status = 'pending'
		   OR (status = 'failed' AND (next_retry_at IS NULL OR next_retry_at < now()))
		ORDER BY id
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("select pending: %w", err)
	}
	defer rows.Close()

	var out []PendingEvent
	for rows.Next() {
		var e PendingEvent
		var op string
		if err := rows.Scan(
			&e.ID, &e.Cluster, &e.Attempts,
			&e.Event.RequestID, &op,
			&e.Event.Mount, &e.Event.Path, &e.Event.Version,
		); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		e.Event.Operation = wire.Operation(op)
		out = append(out, e)
	}
	return out, rows.Err()
}

// AgentEndpoint returns the URL and bearer token for a cluster's agent,
// or ok=false if no agent is registered.
func (s *Store) AgentEndpoint(ctx context.Context, cluster string) (url, token string, ok bool, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT url, token FROM agents WHERE cluster = $1
	`, cluster).Scan(&url, &token)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("select agent: %w", err)
	}
	return url, token, true, nil
}

// MarkDispatched flips an event to dispatched.
func (s *Store) MarkDispatched(ctx context.Context, eventID int64) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE events
		SET status = 'dispatched', dispatched_at = now()
		WHERE id = $1
	`, eventID); err != nil {
		return fmt.Errorf("mark dispatched: %w", err)
	}
	return nil
}

// MarkFailed records a failed dispatch attempt: bumps attempts, sets
// next_retry_at, and switches to 'dead' once attempts hits the cap.
func (s *Store) MarkFailed(ctx context.Context, eventID int64, attempts int, dead bool, nextRetryAt time.Time) error {
	status := "failed"
	if dead {
		status = "dead"
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE events
		SET status = $2, attempts = $3, next_retry_at = $4
		WHERE id = $1
	`, eventID, status, attempts, nextRetryAt); err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}
