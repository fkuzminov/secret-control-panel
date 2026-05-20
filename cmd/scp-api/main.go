// scp-api is the panel's inbound HTTP service: it accepts agent
// registrations and sync callbacks, persisting both into postgres.
// Audit ingestion and event dispatch live in scp-listener and
// scp-daemon respectively.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secret-control-panel/internal/scp/api"
	"secret-control-panel/internal/scp/db"
	"secret-control-panel/internal/shared/logger"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	shutdownTimeout       = 5 * time.Second
)

type config struct {
	listen   string
	dbURL    string
	logLevel string
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.listen, "listen", ":8080", "HTTP bind address")
	flag.StringVar(&c.dbURL, "db-url", os.Getenv("SCP_DB_URL"), "PostgreSQL DSN (or env SCP_DB_URL)")
	flag.StringVar(&c.logLevel, "log-level", "info", "log level: debug | info | warn | error")
	flag.Parse()
	return c
}

func main() {
	cfg := parseFlags()
	log := logger.New(cfg.logLevel)

	if err := run(cfg, log); err != nil {
		log.Error("api exited with error", "err", err)
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

	store := api.NewStore(pool)
	server := api.New(store, log)

	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           server.Routes(),
		ReadHeaderTimeout: httpReadHeaderTimeout,
	}

	go func() {
		<-ctx.Done()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	log.Info("api started", "listen", cfg.listen)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}
