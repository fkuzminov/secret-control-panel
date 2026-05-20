// scp-daemon owns the panel's worker side: it processes tasks queued
// by scp-listener (fanout into per-cluster events) and dispatches
// pending events to cluster agents with retries.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"secret-control-panel/internal/scp/daemon"
	"secret-control-panel/internal/scp/db"
	"secret-control-panel/internal/scp/policy"
	"secret-control-panel/internal/shared/logger"
)

const pollInterval = 10 * time.Second

type config struct {
	dbURL        string
	policiesPath string
	logLevel     string
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.dbURL, "db-url", os.Getenv("SCP_DB_URL"), "PostgreSQL DSN (or env SCP_DB_URL)")
	flag.StringVar(&c.policiesPath, "policies", "/etc/scp/policies.yaml", "path to policies YAML")
	flag.StringVar(&c.logLevel, "log-level", "info", "log level: debug | info | warn | error")
	flag.Parse()
	return c
}

func main() {
	cfg := parseFlags()
	log := logger.New(cfg.logLevel)
	if err := run(cfg, log); err != nil {
		log.Error("daemon exited with error", "err", err)
		os.Exit(1)
	}
}

func run(cfg config, log *slog.Logger) error {
	if cfg.dbURL == "" {
		return fmt.Errorf("db-url is required (use --db-url or SCP_DB_URL)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	policyStore, err := loadPolicies(cfg.policiesPath, log)
	if err != nil {
		return err
	}

	pool, err := db.Open(ctx, cfg.dbURL)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer pool.Close()

	store := daemon.NewStore(pool)

	tasksWake := make(chan struct{}, 1)
	eventsWake := make(chan struct{}, 1)

	var listenWG sync.WaitGroup
	listenWG.Add(2)
	go func() {
		defer listenWG.Done()
		daemon.Subscribe(ctx, pool, daemon.TasksChannel, tasksWake,
			log.With("listen", daemon.TasksChannel))
	}()
	go func() {
		defer listenWG.Done()
		daemon.Subscribe(ctx, pool, daemon.EventsChannel, eventsWake,
			log.With("listen", daemon.EventsChannel))
	}()

	procErr := make(chan error, 1)
	dispErr := make(chan error, 1)
	go func() {
		procErr <- daemon.RunProcessor(ctx, store, policyStore, tasksWake, pollInterval,
			log.With("worker", "processor"))
	}()
	go func() {
		dispErr <- daemon.RunDispatcher(ctx, store, eventsWake, pollInterval,
			log.With("worker", "dispatcher"))
	}()

	log.Info("daemon started",
		"poll_interval", pollInterval,
		"policies", policyStore.Size())

	pErr := <-procErr
	cancel()
	dErr := <-dispErr
	listenWG.Wait()

	switch {
	case pErr != nil && !errors.Is(pErr, context.Canceled):
		return pErr
	case dErr != nil && !errors.Is(dErr, context.Canceled):
		return dErr
	}
	return nil
}

func loadPolicies(path string, log *slog.Logger) (*policy.Store, error) {
	pols, err := policy.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load policies %q: %w", path, err)
	}
	store := policy.NewStore()
	if err := store.Load(pols); err != nil {
		return nil, fmt.Errorf("policy store: %w", err)
	}
	log.Info("policies loaded", "count", store.Size(), "path", path)
	for _, p := range store.List() {
		log.Info("policy",
			"mount", p.Mount,
			"path", p.Path,
			"clusters", p.ClusterCount,
			"wildcard", p.Wildcard)
	}
	return store, nil
}
