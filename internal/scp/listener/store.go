// Package listener implements the audit-ingestion side of the panel:
// reads parsed Vault audit events, deduplicates them by KV version, and
// inserts them into the tasks table for the daemon to fan out.
package listener

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"secret-control-panel/internal/shared/wire"
)

// notifyChannel is the postgres LISTEN/NOTIFY channel name the daemon
// subscribes to.
const notifyChannel = "tasks_new"

// Store is the listener's view of the database: versions (for dedup)
// and tasks (the daemon's inbox).
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps an existing pgx pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Result describes what Ingest did with an event.
type Result int

const (
	// Inserted means the event was new and a task row was created.
	Inserted Result = iota
	// DroppedOldVersion means a higher version was already seen for this
	// path — replay or out-of-order.
	DroppedOldVersion
	// DroppedDuplicateRequest means a task with this request_id already
	// existed (typically a duplicate audit line).
	DroppedDuplicateRequest
)

// Ingest atomically advances the version watermark for ev's path and,
// if ev wins, inserts a task row and notifies the daemon. The whole
// operation is one transaction so listener restarts can't leak partial
// state.
func (s *Store) Ingest(ctx context.Context, ev wire.SecretEvent) (Result, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Take a row-level lock on the (mount, path) version row so two
	// concurrent ingests of the same path serialize cleanly.
	var stored int
	err = tx.QueryRow(ctx, `
		SELECT version FROM versions
		WHERE mount = $1 AND path = $2
		FOR UPDATE
	`, ev.Mount, ev.Path).Scan(&stored)

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// First time we see this path — fall through to insert.
	case err != nil:
		return 0, fmt.Errorf("select version: %w", err)
	default:
		if ev.Version <= stored {
			return DroppedOldVersion, tx.Commit(ctx)
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO versions (mount, path, version)
		VALUES ($1, $2, $3)
		ON CONFLICT (mount, path) DO UPDATE
		SET version = EXCLUDED.version
	`, ev.Mount, ev.Path, ev.Version); err != nil {
		return 0, fmt.Errorf("upsert version: %w", err)
	}

	var taskID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO tasks (request_id, operation, mount, path, version)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (request_id) DO NOTHING
		RETURNING id
	`, ev.RequestID, string(ev.Operation), ev.Mount, ev.Path, ev.Version).Scan(&taskID)

	if errors.Is(err, pgx.ErrNoRows) {
		// request_id collision — another path raced us, or the same
		// audit line was re-delivered. Either way, no task to notify.
		return DroppedDuplicateRequest, tx.Commit(ctx)
	}
	if err != nil {
		return 0, fmt.Errorf("insert task: %w", err)
	}

	if _, err := tx.Exec(ctx, `NOTIFY `+notifyChannel); err != nil {
		return 0, fmt.Errorf("notify: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return Inserted, nil
}
