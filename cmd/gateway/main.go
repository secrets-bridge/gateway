// Command gateway is the Secrets Bridge Gateway: an optional,
// outbound-only observation plane that runs inside a customer boundary.
//
// Rules this process keeps:
//   - Outbound only. The one listener is the loopback /healthz, /readyz
//     and /metrics server; a non-loopback address is refused at boot.
//   - Read-only. Connector HTTP clients are built on internal/readonly,
//     which allows GET only (plus POST to the two Kubernetes self-review
//     paths) and denies Kubernetes Secret paths.
//   - Bound connectors only. Connectors come from the local connectors
//     file and are referred to by name; nothing in a task can add one.
//   - Over-privileged connectors refuse the boot: a credential that can
//     read Kubernetes Secrets stops the Gateway, with no override.
//   - A control plane that refuses the identity (401) stops claiming
//     and leaves the process up and not ready; it does not exit.
//   - No database, Redis or Agent dependency; CI checks go.sum.
//   - The only writes go to the gateway endpoints of the control plane
//     (internal/client refuses any other method or path).
//
// This build wires configuration, identity, the connector registry, the
// loopback server and the control-plane loop (internal/loop): heartbeat,
// claim, one bounded pass over the locally bound connectors a task
// names, and the evidence result.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secrets-bridge/gateway/internal/client"
	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/argocd"
	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/identity"
	"github.com/secrets-bridge/gateway/internal/local"
	"github.com/secrets-bridge/gateway/internal/loop"
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

// loopDeps is everything a control-plane loop may use. The endpoint,
// HTTP client and CP client are built and validated at boot, so a bad
// endpoint, CA file or gateway id fails the boot.
type loopDeps struct {
	Endpoint   *url.URL
	HTTPClient *http.Client
	CP         *client.Client
	Identity   identity.Identity
	Registry   *connectors.Registry
	Probes     *local.Probes
	Logger     *slog.Logger
	Registerer prometheus.Registerer
	Config     Config
	ReplicaID  string
	Version    string
}

// newLoop builds the control-plane loop. Tests replace it.
var newLoop = func(d loopDeps) cpLoop {
	grace := d.Config.ShutdownGrace
	l, err := loop.New(loop.Config{
		CP:                d.CP,
		Connectors:        d.Registry,
		Ready:             d.Probes,
		Logger:            d.Logger,
		Metrics:           loop.NewMetrics(d.Registerer),
		GatewayID:         d.Identity.GatewayID,
		ReplicaID:         d.ReplicaID,
		GatewayVersion:    d.Version,
		HeartbeatInterval: d.Config.HeartbeatInterval,
		ClaimInterval:     d.Config.ClaimInterval,
		ClaimIdleMax:      d.Config.ClaimIdleMax,
		Concurrency:       d.Config.ClaimConcurrency,
		LeaseMargin:       d.Config.LeaseMargin,
		PassTimeout:       d.Config.PassTimeout,
		UnreachableAfter:  d.Config.UnreachableAfter,
		// Shutdown: wait half the grace for passes, then release what is
		// left; every call stays inside the remaining grace.
		DrainTimeout: grace / 2,
		CallTimeout:  min(loop.DefaultCallTimeout, max(grace/4, 100*time.Millisecond)),
	})
	if err != nil {
		return failedLoop{err: err}
	}
	return l
}

// failedLoop reports a loop construction error from Run.
type failedLoop struct{ err error }

func (f failedLoop) Run(context.Context) error { return f.err }

// gatewayVersion is buildVersion when it is a semantic version, and a
// development placeholder otherwise, because the contract requires one.
func gatewayVersion() string {
	if contract.ValidGatewayVersion(buildVersion) {
		return buildVersion
	}
	return "0.0.0-dev"
}

// connectorFactories lists the connector kinds this build can run.
// Connectors are added kind by kind; a connectors file that names a kind
// not listed here is refused at boot. A variable so tests can bind fakes.
var connectorFactories = func(cfg Config) connectors.Factories {
	return connectors.Factories{
		connectors.KindArgoCD: argocd.NewFactory(argocd.Options{AllowInsecureHTTP: cfg.InsecureTransport}),
	}
}

// selfCheckTimeout bounds each connector self-check at boot.
const selfCheckTimeout = 10 * time.Second

// maxCatalogBytes is the E3 body cap (runtime design 6.5). A local
// configuration whose catalog does not fit refuses to start.
const maxCatalogBytes = 64 << 10

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

	// Self-checks (runtime design 5.3). Over-privilege refuses the boot,
	// with no override (ADR 0001 section 11). Any other failure leaves
	// the replica not ready and is retried before each heartbeat.
	if err := registry.Check(context.Background(), selfCheckTimeout); err != nil {
		if errors.Is(err, connectors.ErrOverPrivileged) {
			return nil, fmt.Errorf("refusing to start: %w; remove every verb on secrets (and any write) from the gateway's RBAC", err)
		}
		return nil, err
	}
	for _, h := range registry.Health() {
		if h.Status != connectors.HealthOK {
			logger.Warn("connector self-check did not pass; not ready until it does", "connector_id", h.Connector, "status", string(h.Status))
		}
	}
	if b, err := json.Marshal(loop.CatalogFor(registry)); err != nil || len(b) > maxCatalogBytes {
		return nil, fmt.Errorf("connectors: the catalog of bound connectors and targets does not fit in %d bytes", maxCatalogBytes)
	}

	version := gatewayVersion()
	cp, err := client.New(endpoint, httpClient, id, version)
	if err != nil {
		return nil, err
	}
	replicaID, err := loop.NewReplicaID()
	if err != nil {
		return nil, err
	}
	logger.Info("replica identity", "replica_id", replicaID, "gateway_version", version)

	probes := local.NewProbes()
	srv, err := local.NewServer(cfg.LocalAddr, probes, gatherer)
	if err != nil {
		return nil, err
	}

	registerer, _ := gatherer.(prometheus.Registerer)
	cpl := newLoop(loopDeps{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
		CP:         cp,
		Identity:   id,
		Registry:   registry,
		Probes:     probes,
		Logger:     logger,
		Registerer: registerer,
		Config:     cfg,
		ReplicaID:  replicaID,
		Version:    version,
	})
	return &app{cfg: cfg, logger: logger, local: srv, loop: cpl}, nil
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
