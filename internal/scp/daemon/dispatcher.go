package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"secret-control-panel/internal/shared/wire"
)

const (
	// maxAttempts is the cap before an event is moved to status='dead'.
	maxAttempts = 5

	// httpTimeout caps a single POST to a cluster agent.
	httpTimeout = 5 * time.Second

	// maxErrorBodyBytes caps how much of a non-2xx response body we
	// read for logging.
	maxErrorBodyBytes = 512

	// maxBackoff caps the exponential backoff between retry attempts.
	maxBackoff = 5 * time.Minute
)

// RunDispatcher delivers pending events to agents. Wakes on events_new
// and also polls every interval — polling is required to pick up
// retries whose next_retry_at has passed.
func RunDispatcher(
	ctx context.Context,
	store *Store,
	wakeup <-chan struct{},
	interval time.Duration,
	log *slog.Logger,
) error {
	client := &http.Client{Timeout: httpTimeout}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wakeup:
		case <-ticker.C:
		}

		if err := drainPending(ctx, store, client, log); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("dispatcher batch failed", "err", err)
		}
	}
}

func drainPending(ctx context.Context, store *Store, client *http.Client, log *slog.Logger) error {
	for {
		pending, err := store.FetchPending(ctx, batchSize)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			return nil
		}
		for _, ev := range pending {
			dispatchOne(ctx, store, client, ev, log)
		}
	}
}

func dispatchOne(ctx context.Context, store *Store, client *http.Client, ev PendingEvent, log *slog.Logger) {
	url, token, ok, err := store.AgentEndpoint(ctx, ev.Cluster)
	if err != nil {
		log.Error("agent lookup failed", "event_id", ev.ID, "err", err)
		return
	}
	if !ok {
		recordFailure(ctx, store, ev,
			fmt.Errorf("no agent registered for cluster %q", ev.Cluster), log)
		return
	}

	if err := postEvent(ctx, client, url, token, ev.Event); err != nil {
		recordFailure(ctx, store, ev, err, log)
		return
	}

	if err := store.MarkDispatched(ctx, ev.ID); err != nil {
		log.Error("mark dispatched", "event_id", ev.ID, "err", err)
		return
	}
	log.Info("event dispatched",
		"event_id", ev.ID,
		"request_id", ev.Event.RequestID,
		"cluster", ev.Cluster,
		"version", ev.Event.Version)
}

func recordFailure(ctx context.Context, store *Store, ev PendingEvent, cause error, log *slog.Logger) {
	attempts := ev.Attempts + 1
	dead := attempts >= maxAttempts
	next := time.Now().Add(backoff(attempts))

	if err := store.MarkFailed(ctx, ev.ID, attempts, dead, next); err != nil {
		log.Error("mark failed", "event_id", ev.ID, "err", err)
		return
	}
	if dead {
		log.Error("event marked dead",
			"event_id", ev.ID,
			"request_id", ev.Event.RequestID,
			"cluster", ev.Cluster,
			"attempts", attempts,
			"cause", cause)
		return
	}
	log.Warn("event dispatch failed",
		"event_id", ev.ID,
		"request_id", ev.Event.RequestID,
		"cluster", ev.Cluster,
		"attempt", attempts,
		"next_retry_at", next,
		"cause", cause)
}

// backoff returns min(2^attempts, maxBackoff) seconds.
func backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 30 {
		// guard against overflow on the shift
		return maxBackoff
	}
	d := time.Duration(1<<uint(attempts)) * time.Second
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

func postEvent(ctx context.Context, client *http.Client, url, token string, ev wire.SecretEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	cleanURL := strings.TrimRight(url, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cleanURL+wire.EventsPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.AuthHeader, wire.AuthScheme+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return fmt.Errorf("agent returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(b)))
	}
	// Drain success body so the connection can be reused (keep-alive).
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
