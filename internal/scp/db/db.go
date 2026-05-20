// Package db manages the panel's PostgreSQL connection and schema.
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a pgx connection pool and runs schema migrations.
// The caller is responsible for calling pool.Close().
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS agents (
    cluster       TEXT        PRIMARY KEY,
    url           TEXT        NOT NULL,
    token         TEXT        NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- versions: dedup state for the listener (max KV version seen per path).
CREATE TABLE IF NOT EXISTS versions (
    mount   TEXT NOT NULL,
    path    TEXT NOT NULL,
    version INT  NOT NULL,
    PRIMARY KEY (mount, path)
);

-- tasks: inbox from the listener; deleted by the daemon after fanout.
CREATE TABLE IF NOT EXISTS tasks (
    id         BIGSERIAL   PRIMARY KEY,
    request_id TEXT        NOT NULL UNIQUE,
    operation  TEXT        NOT NULL,
    mount      TEXT        NOT NULL,
    path       TEXT        NOT NULL,
    version    INT         NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- events: per-cluster fanout produced by the daemon; lives forever.
CREATE TABLE IF NOT EXISTS events (
    id             BIGSERIAL   PRIMARY KEY,
    request_id     TEXT        NOT NULL,
    cluster        TEXT        NOT NULL,
    operation      TEXT        NOT NULL,
    mount          TEXT        NOT NULL,
    path           TEXT        NOT NULL,
    version        INT         NOT NULL,
    status         TEXT        NOT NULL,
    attempts       INT         NOT NULL DEFAULT 0,
    next_retry_at  TIMESTAMPTZ,
    synced         BOOLEAN,
    matched        INT,
    patched        INT,
    elapsed_ms     BIGINT,
    synced_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dispatched_at  TIMESTAMPTZ,
    UNIQUE (request_id, cluster)
);

CREATE INDEX IF NOT EXISTS events_status_retry_idx ON events (status, next_retry_at);
CREATE INDEX IF NOT EXISTS events_cluster_status_idx ON events (cluster, status);

-- api_tokens: bearer tokens accepted on /api/v1/* endpoints. One row
-- per issued token; deactivate (active=false) to revoke without losing
-- audit history.
CREATE TABLE IF NOT EXISTS api_tokens (
    id         BIGSERIAL   PRIMARY KEY,
    token      UUID        NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    active     BOOLEAN     NOT NULL DEFAULT true
);
`

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("schema migration: %w", err)
	}
	return nil
}
