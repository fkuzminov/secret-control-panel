// agent is the cluster-side component: it receives events from the
// panel, patches ExternalSecrets to trigger ESO reconcile, and sends
// sync callbacks back to the panel.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secret-control-panel/internal/agent/patcher"
	"secret-control-panel/internal/agent/server"
	"secret-control-panel/internal/agent/syncer"
	"secret-control-panel/internal/shared/logger"
	"secret-control-panel/internal/shared/wire"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	shutdownTimeout       = 5 * time.Second
	registerRetryInterval = 10 * time.Second
	registerMaxAttempts   = 6
)

type config struct {
	listen     string
	url        string
	cluster    string
	token      string
	panelURL   string
	panelToken string
	logLevel   string
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.listen, "listen", ":8081", "bind address")
	flag.StringVar(&c.url, "url", "", "external URL of this agent as seen by the panel (required)")
	flag.StringVar(&c.cluster, "cluster", "", "cluster name (required)")
	flag.StringVar(&c.token, "token", os.Getenv("SCP_AGENT_TOKEN"), "bearer token for this agent (or env SCP_AGENT_TOKEN)")
	flag.StringVar(&c.panelURL, "panel-url", "", "panel base URL for registration and callbacks (required)")
	flag.StringVar(&c.panelToken, "panel-token", os.Getenv("SCP_PANEL_TOKEN"), "panel bearer token (or env SCP_PANEL_TOKEN)")
	flag.StringVar(&c.logLevel, "log-level", "info", "log level: debug | info | warn | error")
	flag.Parse()
	return c
}

func main() {
	cfg := parseFlags()
	log := logger.New(cfg.logLevel).With("cluster", cfg.cluster)

	if err := validate(cfg); err != nil {
		log.Error(err.Error())
		os.Exit(2)
	}

	if err := run(cfg, log); err != nil {
		log.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

func validate(c config) error {
	switch {
	case c.cluster == "":
		return fmt.Errorf("--cluster is required")
	case c.url == "":
		return fmt.Errorf("--url is required")
	case c.token == "":
		return fmt.Errorf("--token is required (or env SCP_AGENT_TOKEN)")
	case c.panelURL == "":
		return fmt.Errorf("--panel-url is required")
	case c.panelToken == "":
		return fmt.Errorf("--panel-token is required (or env SCP_PANEL_TOKEN)")
	}
	return nil
}

func run(cfg config, log *slog.Logger) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	p, err := patcher.BuildWithClient(log)
	if err != nil {
		return fmt.Errorf("patcher init: %w", err)
	}

	w := syncer.New(p.Client, cfg.cluster, cfg.panelURL, cfg.panelToken, log)
	srv := server.NewServer(cfg.token, p, w, log)

	go registerWithPanel(ctx, cfg, log)

	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: httpReadHeaderTimeout,
	}

	go func() {
		<-ctx.Done()
		log.Info("shutdown requested")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
		// Give in-flight syncer goroutines a chance to send their
		// callbacks before the process exits.
		w.Wait(shutCtx)
	}()

	log.Info("agent listening", "addr", cfg.listen, "url", cfg.url)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

func registerWithPanel(ctx context.Context, cfg config, log *slog.Logger) {
	body, _ := json.Marshal(wire.Registration{
		Cluster: cfg.cluster,
		URL:     cfg.url,
		Token:   cfg.token,
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}

	for attempt := 1; attempt <= registerMaxAttempts; attempt++ {
		err := postRegistration(ctx, client, cfg.panelURL, cfg.panelToken, body)
		if err == nil {
			log.Info("registered with panel", "panel_url", cfg.panelURL)
			return
		}
		log.Warn("registration failed, will retry",
			"attempt", attempt,
			"max", registerMaxAttempts,
			"err", err,
		)
		select {
		case <-ctx.Done():
			return
		case <-time.After(registerRetryInterval):
		}
	}
	log.Error("could not register with panel after max attempts", "panel_url", cfg.panelURL)
}

func postRegistration(ctx context.Context, client *http.Client, panelURL, panelToken string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		panelURL+wire.AgentRegisterPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.AuthHeader, wire.AuthScheme+panelToken)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("panel returned %d", resp.StatusCode)
	}
	return nil
}
