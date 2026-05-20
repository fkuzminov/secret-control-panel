// Package server is the agent's HTTP front-end: it accepts
// wire.SecretEvent values from the panel, delegates patching to a
// Patcher, and starts a background sync watcher for each event.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"secret-control-panel/internal/agent/patcher"
	"secret-control-panel/internal/shared/vaultpath"
	"secret-control-panel/internal/shared/wire"
)

// maxEventBodyBytes caps the size of an incoming event payload.
// Events are a handful of fields; anything larger is either a bug or
// abuse.
const maxEventBodyBytes = 64 << 10

// SyncWatcher confirms ESO reconcile after a patch and sends a
// callback to the panel.
type SyncWatcher interface {
	Watch(ev wire.SecretEvent, matched, patched int, patchedAt time.Time)
}

// Server is the agent's HTTP handler.
type Server struct {
	token   string
	log     *slog.Logger
	patcher patcher.Patcher
	watcher SyncWatcher // optional; nil means no callback
}

// NewServer constructs a Server with the given bearer token, patcher,
// and optional watcher (nil disables callbacks).
func NewServer(token string, p patcher.Patcher, w SyncWatcher, log *slog.Logger) *Server {
	return &Server{
		token:   token,
		log:     log,
		patcher: p,
		watcher: w,
	}
}

// Routes returns an http.Handler for the agent's endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.EventsPath, s.handleEvents)
	mux.HandleFunc("GET "+wire.HealthPath, s.handleHealthz)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if !s.checkAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEventBodyBytes)
	var ev wire.SecretEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		s.log.Warn("decode event", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.log.Info("event received",
		"request_id", ev.RequestID,
		"operation", ev.Operation,
		"path", ev.Path,
		"version", ev.Version,
	)

	patchedAt := time.Now()
	res, err := s.patcher.Patch(r.Context(), patcher.Job{
		VaultPath: vaultpath.Join(ev.Mount, ev.Path),
		Operation: string(ev.Operation),
		Version:   ev.Version,
	})
	if err != nil {
		s.log.Error("patch failed", "err", err, "matched", res.Matched, "patched", res.Patched)
		http.Error(w, "patch failed", http.StatusInternalServerError)
		return
	}

	s.log.Info("patch ok", "matched", res.Matched, "patched", res.Patched)

	if s.watcher != nil {
		s.watcher.Watch(ev, res.Matched, res.Patched, patchedAt)
	}

	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) checkAuth(r *http.Request) bool {
	got := r.Header.Get(wire.AuthHeader)
	expected := wire.AuthScheme + s.token
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
