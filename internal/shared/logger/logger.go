package logger

import (
	"log/slog"
	"os"
	"strings"
)

func New(level string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
