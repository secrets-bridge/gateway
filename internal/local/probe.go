package local

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Probe paths served by the loopback server.
const (
	PathHealthz = "/healthz"
	PathReadyz  = "/readyz"
)

// maxProbeBody caps how much of a probe response is read and discarded.
const maxProbeBody = 4 << 10

// ErrProbeFailed means the loopback server answered with a status other
// than 200.
var ErrProbeFailed = errors.New("local: probe failed")

// Probe sends one GET for path to the loopback server at addr and
// returns nil when it answers 200. It is the client side of the exec
// probe (`gateway healthcheck`), so it works in a distroless image with
// no shell or curl.
//
// addr must be a literal loopback address, like the server's. The probe
// dials the address directly over TCP and writes a fixed HTTP/1.1
// request: no proxy, no redirects, no DNS lookup and no connection
// reuse. The whole exchange is bounded by timeout and by ctx.
func Probe(ctx context.Context, addr, path string, timeout time.Duration) error {
	if err := ValidateLoopback(addr); err != nil {
		return err
	}
	if path != PathHealthz && path != PathReadyz {
		return fmt.Errorf("local: probe path must be %s or %s", PathHealthz, PathReadyz)
	}
	if timeout <= 0 {
		return errors.New("local: probe timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("local: probe %s: %w", path, err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := "GET " + path + " HTTP/1.1\r\nHost: " + addr + "\r\nUser-Agent: secrets-bridge-gateway-healthcheck\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("local: probe %s: write: %w", path, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return fmt.Errorf("local: probe %s: read: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBody))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", ErrProbeFailed, path, resp.StatusCode)
	}
	return nil
}
