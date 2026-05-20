// Package syncer confirms ESO reconcile after a patch: it polls
// ExternalSecret status.refreshTime until it advances past the patch
// timestamp, then sends a Callback to the panel.
package syncer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"

	"secret-control-panel/internal/agent/patcher"
	"secret-control-panel/internal/shared/vaultpath"
	"secret-control-panel/internal/shared/wire"
)

const (
	pollInterval    = 2 * time.Second
	pollTimeout     = 30 * time.Second
	callbackTimeout = 5 * time.Second
)

// Watcher polls ExternalSecret status after a patch and sends a
// Callback to the panel when ESO confirms reconcile (or on timeout).
type Watcher struct {
	k8s      dynamic.Interface
	cluster  string
	panelURL string
	token    string
	client   *http.Client
	log      *slog.Logger
	wg       sync.WaitGroup
}

// New creates a Watcher. If panelURL is empty, callbacks are not sent.
func New(k8s dynamic.Interface, cluster, panelURL, token string, log *slog.Logger) *Watcher {
	return &Watcher{
		k8s:      k8s,
		cluster:  cluster,
		panelURL: panelURL,
		token:    token,
		client: &http.Client{
			Timeout:   callbackTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
		},
		log: log,
	}
}

// Watch starts a background goroutine that polls ExternalSecrets bound
// to vaultPath until their refreshTime passes patchedAt, then sends a
// Callback to the panel.
func (w *Watcher) Watch(ev wire.SecretEvent, matched, patched int, patchedAt time.Time) {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.watch(ev, matched, patched, patchedAt)
	}()
}

// Wait blocks until all in-flight Watch goroutines finish or ctx is
// cancelled. Used by the agent's shutdown path so in-flight callbacks
// have a chance to reach the panel.
func (w *Watcher) Wait(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (w *Watcher) watch(ev wire.SecretEvent, matched, patched int, patchedAt time.Time) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()

	synced := w.pollUntilSynced(ctx, vaultpath.Join(ev.Mount, ev.Path), patchedAt)

	cb := wire.Callback{
		RequestID: ev.RequestID,
		Cluster:   w.cluster,
		Synced:    synced,
		Matched:   matched,
		Patched:   patched,
		ElapsedMS: time.Since(start).Milliseconds(),
	}

	w.log.Info("sync result",
		"request_id", ev.RequestID,
		"synced", synced,
		"elapsed_ms", cb.ElapsedMS,
	)

	if w.panelURL == "" {
		return
	}
	if err := w.sendCallback(context.Background(), cb); err != nil {
		w.log.Warn("callback failed", "request_id", ev.RequestID, "err", err)
	}
}

func (w *Watcher) pollUntilSynced(ctx context.Context, vaultPath string, patchedAt time.Time) bool {
	for {
		if w.allSynced(ctx, vaultPath, patchedAt) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(pollInterval):
		}
	}
}

func (w *Watcher) allSynced(ctx context.Context, vaultPath string, patchedAt time.Time) bool {
	list, err := w.k8s.Resource(patcher.ExternalSecretGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		w.log.Warn("list ExternalSecrets", "err", err)
		return false
	}

	matched, synced := 0, 0
	for _, item := range list.Items {
		ann, ok := nestedString(item.Object, "metadata", "annotations", patcher.SelectorAnnotation)
		if !ok || !patcher.SelectorMatches(ann, vaultPath) {
			continue
		}
		matched++

		rt, ok := nestedString(item.Object, "status", "refreshTime")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339, rt)
		if err == nil && !t.Before(patchedAt.Truncate(time.Second)) {
			synced++
		}
	}
	return matched > 0 && synced == matched
}

func (w *Watcher) sendCallback(ctx context.Context, cb wire.Callback) error {
	body, err := json.Marshal(cb)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, callbackTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, w.panelURL+wire.CallbackPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.AuthHeader, wire.AuthScheme+w.token)

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("panel returned %d", resp.StatusCode)
	}
	return nil
}

// nestedString traverses an unstructured map by keys and returns the
// leaf value as a string.
func nestedString(obj map[string]any, keys ...string) (string, bool) {
	cur := obj
	for i, k := range keys {
		v, ok := cur[k]
		if !ok {
			return "", false
		}
		if i == len(keys)-1 {
			s, ok := v.(string)
			return s, ok
		}
		cur, ok = v.(map[string]any)
		if !ok {
			return "", false
		}
	}
	return "", false
}
