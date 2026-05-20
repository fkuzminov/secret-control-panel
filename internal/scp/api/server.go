// Package api is the panel's inbound HTTP server: it accepts agent
// registrations and sync callbacks. All other panel work (audit
// ingestion, fanout, dispatch) happens in separate processes.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"secret-control-panel/internal/shared/wire"
)

// maxRequestBodyBytes caps the size of an incoming registration or
// callback payload. Both are a handful of fields; anything larger is
// either a bug or abuse.
const maxRequestBodyBytes = 64 << 10

// Server handles incoming HTTP requests from agents. Bearer tokens are
// validated against the api_tokens table on every call.
type Server struct {
	store *Store
	log   *slog.Logger
}

// New creates a Server.
func New(store *Store, log *slog.Logger) *Server {
	return &Server{store: store, log: log}
}

// Routes returns an http.Handler for all panel API endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.AgentRegisterPath, s.handleRegister)
	mux.HandleFunc("POST "+wire.CallbackPath, s.handleCallback)
	return mux
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if !s.authorize(w, r) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var reg wire.Registration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if reg.Cluster == "" || reg.URL == "" || reg.Token == "" {
		http.Error(w, "cluster, url, token are required", http.StatusBadRequest)
		return
	}

	if err := s.store.UpsertAgent(r.Context(), reg); err != nil {
		s.log.Error("upsert agent", "cluster", reg.Cluster, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.log.Info("agent registered", "cluster", reg.Cluster, "url", reg.URL)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if !s.authorize(w, r) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var cb wire.Callback
	if err := json.NewDecoder(r.Body).Decode(&cb); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if cb.RequestID == "" || cb.Cluster == "" {
		http.Error(w, "request_id and cluster are required", http.StatusBadRequest)
		return
	}

	rows, err := s.store.ApplyCallback(r.Context(), cb)
	if err != nil {
		s.log.Error("apply callback", "request_id", cb.RequestID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if rows == 0 {
		// Callback for an event we never dispatched — stale agent state
		// or a bug. Accept it (don't make the agent retry) but log.
		s.log.Warn("callback matched no event",
			"request_id", cb.RequestID,
			"cluster", cb.Cluster)
	} else {
		s.log.Info("callback applied",
			"request_id", cb.RequestID,
			"cluster", cb.Cluster,
			"synced", cb.Synced,
			"matched", cb.Matched,
			"patched", cb.Patched,
			"elapsed_ms", cb.ElapsedMS,
		)
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorize extracts the bearer token from r, validates it against the
// api_tokens table and writes the appropriate error on failure.
// Returns true if the request is authorized to proceed.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	header := r.Header.Get(wire.AuthHeader)
	token, ok := strings.CutPrefix(header, wire.AuthScheme)
	if !ok || token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	valid, err := s.store.ValidateToken(r.Context(), token)
	if err != nil {
		s.log.Error("validate token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if !valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}
