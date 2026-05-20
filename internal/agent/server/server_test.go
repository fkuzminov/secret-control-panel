package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"secret-control-panel/internal/agent/patcher"
	"secret-control-panel/internal/shared/wire"
)

const testToken = "secret-token"

type fakePatcher struct {
	calls []patcher.Job
	res   patcher.Result
	err   error
}

func (f *fakePatcher) Patch(_ context.Context, j patcher.Job) (patcher.Result, error) {
	f.calls = append(f.calls, j)
	return f.res, f.err
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newServer(t *testing.T, fp *fakePatcher) http.Handler {
	t.Helper()
	var p patcher.Patcher
	if fp != nil {
		p = fp
	}
	return NewServer(testToken, p, nil, quietLogger()).Routes()
}

func postEvent(t *testing.T, h http.Handler, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, wire.EventsPath, bytes.NewReader(body))
	if token != "" {
		req.Header.Set(wire.AuthHeader, wire.AuthScheme+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func sampleEvent() wire.SecretEvent {
	return wire.SecretEvent{
		RequestID: "r-1",
		Operation: wire.Update,
		Mount:     "kv",
		Path:      "app/db",
		Version:   3,
	}
}

func TestHealthz_OK(t *testing.T) {
	h := newServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, wire.HealthPath, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestEvents_Unauthorized_NoToken(t *testing.T) {
	h := newServer(t, &fakePatcher{})
	rec := postEvent(t, h, mustJSON(t, sampleEvent()), "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestEvents_Unauthorized_BadToken(t *testing.T) {
	h := newServer(t, &fakePatcher{})
	rec := postEvent(t, h, mustJSON(t, sampleEvent()), "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestEvents_BadJSON(t *testing.T) {
	h := newServer(t, &fakePatcher{})
	rec := postEvent(t, h, []byte(`{not json`), testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestEvents_HappyPath_DispatchesJob(t *testing.T) {
	fp := &fakePatcher{res: patcher.Result{Matched: 2, Patched: 2}}
	h := newServer(t, fp)

	rec := postEvent(t, h, mustJSON(t, sampleEvent()), testToken)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}

	if len(fp.calls) != 1 {
		t.Fatalf("want 1 patcher call, got %d", len(fp.calls))
	}
	got := fp.calls[0]
	if got.VaultPath != "kv/app/db" {
		t.Errorf("VaultPath = %q, want kv/app/db", got.VaultPath)
	}
	if got.Operation != "update" {
		t.Errorf("Operation = %q, want update", got.Operation)
	}
	if got.Version != 3 {
		t.Errorf("Version = %d, want 3", got.Version)
	}
}

func TestEvents_PatcherError_500(t *testing.T) {
	fp := &fakePatcher{err: errPatcher{}}
	h := newServer(t, fp)
	rec := postEvent(t, h, mustJSON(t, sampleEvent()), testToken)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

type errPatcher struct{}

func (errPatcher) Error() string { return "boom" }
