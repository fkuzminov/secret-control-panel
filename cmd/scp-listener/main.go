// scp-listener consumes Vault audit events from a TCP socket device,
// deduplicates them by KV version, and writes them to the tasks table
// for the daemon to fan out across clusters.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"secret-control-panel/internal/scp/audit"
	"secret-control-panel/internal/scp/db"
	"secret-control-panel/internal/scp/listener"
	"secret-control-panel/internal/shared/logger"
	"secret-control-panel/internal/shared/wire"
)

const eventsChannelBuf = 16

type config struct {
	auditAddr string
	dbURL     string
	logLevel  string
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.auditAddr, "audit-addr", ":9090", "TCP address for Vault audit socket")
	flag.StringVar(&c.dbURL, "db-url", os.Getenv("SCP_DB_URL"), "PostgreSQL DSN (or env SCP_DB_URL)")
	flag.StringVar(&c.logLevel, "log-level", "info", "log level: debug | info | warn | error")
	flag.Parse()
	return c
}

func main() {
	cfg := parseFlags()
	log := logger.New(cfg.logLevel)

	if err := run(cfg, log); err != nil {
		log.Error("listener exited with error", "err", err)
		os.Exit(1)
	}
}

func run(cfg config, log *slog.Logger) error {
	if cfg.dbURL == "" {
		return fmt.Errorf("db-url is required (use --db-url or SCP_DB_URL)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pool, err := db.Open(ctx, cfg.dbURL)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer pool.Close()

	store := listener.NewStore(pool)

	events := make(chan wire.SecretEvent, eventsChannelBuf)
	socket := audit.NewSocket(cfg.auditAddr, log, events)

	log.Info("listener started", "audit_addr", cfg.auditAddr)

	socketErr := make(chan error, 1)
	go func() {
		socketErr <- socket.Run(ctx)
	}()

	pumpErr := pump(ctx, events, store, log)
	cancel()
	sErr := <-socketErr

	switch {
	case pumpErr != nil && !errors.Is(pumpErr, context.Canceled):
		return pumpErr
	case sErr != nil && !errors.Is(sErr, context.Canceled):
		return sErr
	}
	return nil
}

// pump reads parsed events off the socket and ingests them through the
// store. Returns ctx.Err() on shutdown.
func pump(ctx context.Context, in <-chan wire.SecretEvent, store *listener.Store, log *slog.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-in:
			res, err := store.Ingest(ctx, ev)
			if err != nil {
				log.Error("ingest failed",
					"request_id", ev.RequestID,
					"mount", ev.Mount,
					"path", ev.Path,
					"version", ev.Version,
					"err", err)
				continue
			}
			switch res {
			case listener.Inserted:
				log.Info("task created",
					"request_id", ev.RequestID,
					"mount", ev.Mount,
					"path", ev.Path,
					"version", ev.Version)
			case listener.DroppedOldVersion:
				log.Info("event dropped: stale version",
					"request_id", ev.RequestID,
					"mount", ev.Mount,
					"path", ev.Path,
					"version", ev.Version)
			case listener.DroppedDuplicateRequest:
				log.Info("event dropped: duplicate request_id",
					"request_id", ev.RequestID,
					"mount", ev.Mount,
					"path", ev.Path)
			}
		}
	}
}
