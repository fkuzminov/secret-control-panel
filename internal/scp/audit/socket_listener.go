package audit

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"secret-control-panel/internal/shared/wire"
)

const (
	// defaultSocketBuf is the initial scan buffer size for an audit
	// connection. maxSocketLine caps the size of a single audit line —
	// anything larger fails the scanner rather than buffering forever.
	defaultSocketBuf = 64 * 1024
	maxSocketLine    = 1024 * 1024
)

// SocketListener accepts Vault's socket audit-device stream. Each
// Vault node opens an outbound TCP connection and writes one JSON
// audit record per line; we just listen on a port and parse each
// line.
//
// Multiple concurrent connections are supported (one per node in an
// HA cluster). No persisted offset is kept: the socket source is a
// pure stream with no position concept; gaps while the listener is
// down are expected to be covered by Vault's second audit device
// (file fail-open).
type SocketListener struct {
	address string
	out     chan<- wire.SecretEvent
	log     *slog.Logger
}

// NewSocket constructs a SocketListener bound to address (e.g. ":9090"
// or "0.0.0.0:9090"). A nil logger falls back to slog.Default.
func NewSocket(address string, logger *slog.Logger, out chan<- wire.SecretEvent) *SocketListener {
	if logger == nil {
		logger = slog.Default()
	}
	return &SocketListener{address: address, out: out, log: logger}
}

// Run accepts connections and parses incoming audit lines until ctx
// is cancelled. Returns ctx.Err() on graceful shutdown.
func (l *SocketListener) Run(ctx context.Context) error {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", l.address)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", l.address, err)
	}

	l.log.Info("audit socket listener started", "address", listener.Addr().String())

	// Closing the listener on context cancel unblocks Accept.
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return ctx.Err()
			}
			l.log.Warn("accept failed", "err", err)
			continue
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			l.handleConn(ctx, c)
		}(conn)
	}
}

func (l *SocketListener) handleConn(ctx context.Context, c net.Conn) {
	remote := c.RemoteAddr().String()
	defer func() {
		_ = c.Close()
		l.log.Info("vault audit connection closed", "remote", remote)
	}()
	l.log.Info("vault audit connection accepted", "remote", remote)

	// Closing the connection on context cancel interrupts Read.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()

	scanner := bufio.NewScanner(c)
	scanner.Buffer(make([]byte, defaultSocketBuf), maxSocketLine)

	var nLines, nAccepted int
	for scanner.Scan() {
		nLines++
		line := scanner.Text()
		l.log.Debug("audit line received", "remote", remote, "bytes", len(line))
		ev, ok, reason := parseLine(line)
		if !ok {
			l.log.Debug("audit line skipped", "remote", remote, "reason", reason)
			continue
		}
		nAccepted++
		l.log.Info("audit event accepted",
			"source", "socket",
			"remote", remote,
			"request_id", ev.RequestID,
			"operation", ev.Operation,
			"mount", ev.Mount,
			"path", ev.Path,
			"version", ev.Version,
		)
		select {
		case l.out <- ev:
		case <-ctx.Done():
			return
		}
	}
	l.log.Info("audit connection stats",
		"remote", remote, "lines_seen", nLines, "events_accepted", nAccepted)

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		l.log.Warn("scanner error", "remote", remote, "err", err)
	}
}
