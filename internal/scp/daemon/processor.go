package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// batchSize is the upper bound on rows fetched per loop iteration.
// Drains the table in chunks to avoid huge transactions.
const batchSize = 100

// Resolver maps (mount, path) to the clusters subscribed to that path.
type Resolver interface {
	Resolve(mount, path string) []string
}

// RunProcessor turns tasks into per-cluster events. Wakes on the
// tasks_new channel and also polls every interval as a safety net for
// missed notifications. Returns ctx.Err() on shutdown.
func RunProcessor(
	ctx context.Context,
	store *Store,
	resolver Resolver,
	wakeup <-chan struct{},
	interval time.Duration,
	log *slog.Logger,
) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wakeup:
		case <-ticker.C:
		}

		if err := drainTasks(ctx, store, resolver, log); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("processor batch failed", "err", err)
		}
	}
}

func drainTasks(ctx context.Context, store *Store, resolver Resolver, log *slog.Logger) error {
	for {
		tasks, err := store.FetchTasks(ctx, batchSize)
		if err != nil {
			return err
		}
		if len(tasks) == 0 {
			return nil
		}
		for _, t := range tasks {
			clusters := resolver.Resolve(t.Event.Mount, t.Event.Path)
			if err := store.FanoutTask(ctx, t.ID, t.Event, clusters); err != nil {
				log.Error("fanout task",
					"task_id", t.ID,
					"request_id", t.Event.RequestID,
					"err", err)
				continue
			}
			if len(clusters) == 0 {
				log.Warn("task dropped: no policy",
					"task_id", t.ID,
					"request_id", t.Event.RequestID,
					"mount", t.Event.Mount,
					"path", t.Event.Path)
			} else {
				log.Info("task fanned out",
					"task_id", t.ID,
					"request_id", t.Event.RequestID,
					"clusters", clusters)
			}
		}
	}
}
