// Command gateway is the Secrets Bridge Gateway: an optional,
// outbound-only observation plane that runs inside a customer boundary.
//
// Rules this process keeps:
//   - Outbound only. The one listener is the loopback /healthz, /readyz
//     and /metrics server; a non-loopback address is refused at boot.
//   - Read-only. Connector HTTP clients are built on internal/readonly,
//     which refuses every method except GET and denies Kubernetes Secret
//     paths.
//   - Bound connectors only. Connectors come from the local connectors
//     file and are referred to by name; nothing in a task can add one.
//   - No database, Redis or Agent dependency; CI checks go.sum.
//
// This build wires configuration, identity, the connector registry and
// the loopback server. The control-plane loop is the cpLoop seam below;
// the build ships standbyLoop, which makes no control-plane calls.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/argocd"
	"github.com/secrets-bridge/gateway/internal/identity"
	"github.com/secrets-bridge/gateway/internal/local"
	"github.com/secrets-bridge/gateway/internal/observability"
)

// buildVersion is set at link time.
var buildVersion = "dev"

// cpLoop is the seam for the control-plane loop (heartbeat, claim,
// observe, report). Run blocks until ctx is cancelled or the loop fails,
// and owns the readiness gate in deps.Probes.
type cpLoop interface {
	Run(ctx context.Context) error
}

// loopDeps is everything a control-plane loop may use. The endpoint and
// HTTP client are validated at boot even though standbyLoop does not use
// them, so a bad endpoint or CA file fails the boot now.
type loopDeps struct {
	Endpoint   *url.URL
	HTTPClient *http.Client
	Identity   identity.Identity
	Registry   *connectors.Registry
	Probes     *local.Probes
	Logger     *slog.Logger
}

// newLoop builds the control-plane loop. A later change replaces it with
// the claim loop.
var newLoop = func(d loopDeps) cpLoop { return standbyLoop{logger: d.Logger, probes: d.Probes} }

// standbyLoop makes no network calls. It keeps the Gateway not ready,
// because a Gateway that cannot claim tasks must not report ready, and
// waits for shutdown.
type standbyLoop struct {
	logger *slog.Logger
	probes *local.Probes
}

func (s standbyLoop) Run(ctx context.Context) error {
	s.probes.SetReady(false)
	s.logger.Warn("control-plane loop is not part of this build; the gateway stays not ready and observes nothing")
	<-ctx.Done()
	return nil
}

// connectorFactories lists the connector kinds this build can run.
// Connectors are added kind by kind; a connectors file that names a kind
// not listed here is refused at boot.
func connectorFactories(cfg Config) connectors.Factories {
	return connectors.Factories{
		connectors.KindArgoCD: argocd.NewFactory(argocd.Options{AllowInsecureHTTP: cfg.InsecureTransport}),
	}
}

func main() {
	if err := run(os.Args[1:], os.LookupEnv); err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) (string, bool)) error {
	cfg, err := parseConfig(args, getenv, os.Stderr)
	if err != nil {
		return err
	}
	logger := observability.NewLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	app, err := setup(cfg, getenv, logger, prometheus.DefaultGatherer)
	if err != nil {
		logger.Error("boot failed", "error", err)
		return err
	}
	return app.serve(ctx)
}

// app is a booted Gateway.
type app struct {
	cfg    Config
	logger *slog.Logger
	local  *local.Server
	loop   cpLoop
}

// setup validates configuration and builds every component without
// starting any of them.
func setup(cfg Config, getenv func(string) (string, bool), logger *slog.Logger, gatherer prometheus.Gatherer) (*app, error) {
	logger.Info("starting secrets-bridge gateway",
		"version", buildVersion,
		"cp_endpoint", redactEndpoint(cfg.CPEndpoint),
		"local_addr", cfg.LocalAddr,
		"connectors_file", cfg.ConnectorsFile,
	)

	endpoint, err := validateEndpoint(cfg.CPEndpoint, cfg.InsecureTransport)
	if err != nil {
		return nil, err
	}
	if cfg.InsecureTransport {
		logger.Warn("SB_INSECURE_TRANSPORT=true: plaintext to the control plane; do not use in production",
			"endpoint", redactEndpoint(endpoint.String()))
	}
	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	id, src, err := identity.Load(getenv, cfg.IdentityFile)
	if err != nil {
		return nil, err
	}
	logger.Info("identity loaded", "source", string(src), "gateway_id", id.GatewayID)

	registry, err := connectors.LoadFile(cfg.ConnectorsFile, connectorFactories(cfg))
	if err != nil {
		return nil, err
	}
	if registry.Len() == 0 {
		logger.Warn("no connectors bound; set SB_GATEWAY_CONNECTORS_FILE")
	}
	logger.Info("connectors bound", "count", registry.Len(), "names", registry.Names())

	probes := local.NewProbes()
	srv, err := local.NewServer(cfg.LocalAddr, probes, gatherer)
	if err != nil {
		return nil, err
	}

	loop := newLoop(loopDeps{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
		Identity:   id,
		Registry:   registry,
		Probes:     probes,
		Logger:     logger,
	})
	return &app{cfg: cfg, logger: logger, local: srv, loop: loop}, nil
}

// serve starts the loopback server and the loop, and shuts both down
// when ctx is cancelled.
func (a *app) serve(ctx context.Context) error {
	srvErr := make(chan error, 1)
	go func() {
		if err := a.local.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
		close(srvErr)
	}()

	loopCtx, cancelLoop := context.WithCancel(ctx)
	defer cancelLoop()
	loopErr := make(chan error, 1)
	go func() { loopErr <- a.loop.Run(loopCtx) }()

	var runErr error
	select {
	case <-ctx.Done():
		a.logger.Info("shutdown requested")
	case err, ok := <-srvErr:
		if ok && err != nil {
			runErr = fmt.Errorf("local server: %w", err)
		}
	case err := <-loopErr:
		loopErr = nil
		if err != nil {
			runErr = fmt.Errorf("control-plane loop: %w", err)
		}
	}

	cancelLoop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownGrace)
	defer cancel()
	if loopErr != nil {
		select {
		case <-loopErr:
		case <-shutdownCtx.Done():
			a.logger.Warn("control-plane loop did not stop within the shutdown grace")
		}
	}
	if err := a.local.Shutdown(shutdownCtx); err != nil {
		a.logger.Warn("local server shutdown", "error", err)
	}
	if runErr != nil {
		a.logger.Error("gateway stopped", "error", runErr)
		return runErr
	}
	a.logger.Info("shutdown complete")
	return nil
}
