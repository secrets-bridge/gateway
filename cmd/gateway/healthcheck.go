package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/secrets-bridge/gateway/internal/local"
)

// healthcheckCommand is the subcommand name used by the exec probes.
const healthcheckCommand = "healthcheck"

const (
	defaultHealthcheckTimeout = 2 * time.Second
	maxHealthcheckTimeout     = 30 * time.Second
)

// runHealthcheck implements `gateway healthcheck [--live] [--local-addr
// addr] [--timeout d]`. It sends one GET to the loopback server of the
// Gateway running in the same container: /readyz by default, /healthz
// with --live. It returns nil (exit 0) on 200 and an error (exit 1)
// otherwise. It needs no control-plane setting, reads no identity or
// connectors file and makes no other network call, so the image needs
// no shell or curl for its probes.
func runHealthcheck(ctx context.Context, args []string, getenv func(string) (string, bool), stderr io.Writer) error {
	e := envReader{getenv: getenv}
	addr := e.str("SB_GATEWAY_LOCAL_ADDR", defaultLocalAddr)
	if e.err != nil {
		return e.err
	}

	fs := flag.NewFlagSet("gateway "+healthcheckCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	live := fs.Bool("live", false, "check liveness (/healthz) instead of readiness (/readyz)")
	fs.StringVar(&addr, "local-addr", addr, "loopback address of the Gateway's local server (also SB_GATEWAY_LOCAL_ADDR)")
	timeout := fs.Duration("timeout", defaultHealthcheckTimeout, "deadline for the whole check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%s: unexpected arguments: %d positional argument(s)", healthcheckCommand, fs.NArg())
	}
	if *timeout <= 0 || *timeout > maxHealthcheckTimeout {
		return fmt.Errorf("%s: --timeout must be positive and at most %s", healthcheckCommand, maxHealthcheckTimeout)
	}

	path := local.PathReadyz
	if *live {
		path = local.PathHealthz
	}
	if err := local.Probe(ctx, addr, path, *timeout); err != nil {
		if errors.Is(err, local.ErrProbeFailed) {
			return fmt.Errorf("%s: %w", healthcheckCommand, err)
		}
		return fmt.Errorf("%s: %s unreachable: %w", healthcheckCommand, path, err)
	}
	return nil
}
