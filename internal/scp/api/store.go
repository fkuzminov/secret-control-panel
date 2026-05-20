package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"secret-control-panel/internal/shared/wire"
)

// Store is the api server's view of the database: agents (registration)
// and events (callback updates).
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps an existing pgx pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ValidateToken reports whether the given bearer token (UUID string)
// matches an active row in api_tokens. Malformed tokens (not a UUID)
// return false without error.
func (s *Store) ValidateToken(ctx context.Context, token string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM api_tokens
			WHERE token = $1::uuid AND active
		)
	`, token).Scan(&ok)
	if err != nil {
		// Malformed UUID surfaces as PG SQLSTATE 22P02 — treat as
		// "not authorized" rather than 500.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "22P02" {
			return false, nil
		}
		return false, fmt.Errorf("validate token: %w", err)
	}
	return ok, nil
}

// UpsertAgent inserts a new agent or refreshes an existing one. The
// last_seen_at column is bumped on every call so it doubles as a
// liveness signal.
func (s *Store) UpsertAgent(ctx context.Context, reg wire.Registration) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (cluster, url, token, registered_at, last_seen_at)
		VALUES ($1, $2, $3, now(), now())
		ON CONFLICT (cluster) DO UPDATE
		SET url = EXCLUDED.url,
		    token = EXCLUDED.token,
		    last_seen_at = now()
	`, reg.Cluster, reg.URL, reg.Token)
	if err != nil {
		return fmt.Errorf("upsert agent: %w", err)
	}
	return nil
}

// ApplyCallback updates the events row matching (request_id, cluster)
// with the agent's sync result. Returns the number of rows updated;
// zero means there was no matching dispatched event (stale callback or
// missed dispatch).
func (s *Store) ApplyCallback(ctx context.Context, cb wire.Callback) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE events
		SET synced     = $3,
		    matched    = $4,
		    patched    = $5,
		    elapsed_ms = $6,
		    synced_at  = now()
		WHERE request_id = $1 AND cluster = $2
	`, cb.RequestID, cb.Cluster, cb.Synced, cb.Matched, cb.Patched, cb.ElapsedMS)
	if err != nil {
		return 0, fmt.Errorf("update event: %w", err)
	}
	return tag.RowsAffected(), nil
}
