<p align="center">
  <a href="https://github.com/secrets-bridge"><img src="https://raw.githubusercontent.com/secrets-bridge/.github/main/profile/logo.svg" alt="Secrets Bridge" width="520" /></a>
</p>

<p align="center">
  <b>The brain behind your secrets.</b><br/>
  Unified secrets control plane for cloud-native teams.<br/>
  <a href="https://secrets-bridge.io">secrets-bridge.io</a> · <a href="https://github.com/secrets-bridge">all repos</a>
</p>

---
# secrets-bridge / gateway

**Optional, outbound-only observation plane for [Secrets Bridge](https://github.com/secrets-bridge).** A Gateway runs inside a customer security boundary, reads local integrations (External Secrets Operator, Kubernetes rollout state, ArgoCD) without changing anything, and reports metadata-only evidence that an approved secret change actually reached the workloads.

> **Status: early implementation.** The design is [ADR 0001: Gateway as an outbound-only observation plane](docs/adr/0001-gateway-observation-plane.md) (status: Accepted), with detail in [`docs/design/`](docs/design/) and the wire schemas in [`schemas/`](schemas/). The implementation is in progress on draft pull requests and is not usable yet. The current code boots, loads its identity and locally bound connectors, and serves loopback health and metrics. It heartbeats to the control plane and claims observation tasks. No connector kinds exist yet, so it refuses every task with `unknown_connector` and observes nothing.

## How it fits

```text
Control Plane (api, worker, Postgres)
   ^ outbound HTTPS from the customer side only
   |
   +-- Agent    : executes secret changes (unchanged, no Gateway dependency)
   +-- Gateway  : observes the rollout, read-only, reports evidence
                    |-- External Secrets Operator status
                    |-- Deployment / ReplicaSet rollout
                    +-- ArgoCD sync and health (context only)
```

- **Optional.** Secret governance and execution work without a Gateway. With no Gateway, a change shows as unverified, never as failed.
- **Outbound only.** No inbound listener except a loopback health endpoint. The control plane never connects into the customer network.
- **Read-only.** Never syncs, rolls back or modifies anything.
- **Metadata only.** No secret values in results, logs, traces or metrics, and no read access to Kubernetes Secrets.
- **Stateless.** No database or Redis on the customer side. Several replicas can share one Gateway identity.

## Layout

| Path | Purpose |
|---|---|
| `cmd/gateway` | Entry point: env and flag config, TLS transport to the control plane, boot and graceful shutdown |
| `internal/client` | Typed client for the gateway endpoints of the control plane (enroll, heartbeat, catalog, claim, lease, release, result). It refuses any other method or path, uses no proxy, never follows redirects, caps every response body and never copies response text into errors |
| `internal/contract` | Go structs for the v1 ObservationTask and EvidenceResult, with validation that matches the JSON schemas vendored under `internal/contract/testdata` |
| `internal/loop` | Heartbeat loop and claim loop: jittered polling with idle backoff, bounded concurrency, one pass per lease that ends before the lease runs out, `attempt_id` echoed on every call, and refusal of any task that names a connector not bound locally |
| `internal/connectors` | Connector interface, the registry of locally bound connectors, and the loader for the connectors file. No connector kinds are implemented yet |
| `internal/readonly` | The only transport for connector clients. Per client it allowlists GET path patterns and query keys, allows POST only to the two Kubernetes self-review paths with a JSON body, and refuses opaque or non-canonical URLs, upgrades, exec, attach, portforward, proxy and log paths, and Kubernetes Secret paths before a request leaves the process |
| `internal/identity` | Loads the gateway id and secret from env vars or a JSON file. Read-only, with no enrollment and no keypair. The secret is redacted in every fmt, JSON and slog output |
| `internal/local` | Loopback-only `/healthz`, `/readyz` and `/metrics` server |
| `internal/observability` | JSON structured logger |
| `internal/guard` | Guard tests for the module graph and source tree (see Development) |

Planned next: the ESO, rollout and ArgoCD connectors, the catalog upload, and `enroll` and `healthcheck` subcommands.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SB_CP_ENDPOINT` | required | `https://` only, unless `SB_INSECURE_TRANSPORT=true` (development only) |
| `SB_CP_CA_FILE` | empty | PEM bundle that replaces the system roots |
| `SB_CP_TLS_SERVER_NAME` | empty | TLS server name override |
| `SB_GATEWAY_ID`, `SB_GATEWAY_SECRET` | empty | Credential pair. The id is the UUID the control plane issued. When unset, `SB_GATEWAY_IDENTITY_FILE` is read |
| `SB_GATEWAY_IDENTITY_FILE` | `/etc/secrets-bridge/gateway/identity.json` | `{"gateway_id": "...", "gateway_secret": "..."}`, mode 0400, 0600, or 0440 as a Secret volume with `fsGroup` produces. Any other bit, or group write, is refused |
| `SB_GATEWAY_LOCAL_ADDR` | `127.0.0.1:8091` | Must be a literal loopback IP; `localhost` is refused |
| `SB_GATEWAY_CONNECTORS_FILE` | empty | JSON list of bound connectors, see below. Empty binds none |
| `SB_GATEWAY_SHUTDOWN_GRACE` | `15s` | Graceful shutdown deadline. Half of it is spent waiting for in-flight passes, then unfinished tasks are released |
| `SB_GATEWAY_HEARTBEAT_INTERVAL` | `30s` | Used until the control plane suggests an interval |
| `SB_GATEWAY_CLAIM_INTERVAL` | `5s` | Base claim interval, jittered between half and one and a half times |
| `SB_GATEWAY_CLAIM_IDLE_MAX` | `30s` | Longest claim interval after empty polls |
| `SB_GATEWAY_CLAIM_CONCURRENCY` | `1` | Observation passes in flight per replica, 1 to 16 |
| `SB_GATEWAY_LEASE_MARGIN` | `3s` | A pass stops this long before the lease expires, so the result is sent while the lease is live |
| `SB_GATEWAY_PASS_TIMEOUT` | `30s` | Upper bound for one pass |
| `SB_GATEWAY_CP_UNREACHABLE_AFTER` | `2m` | The Gateway turns not ready when no heartbeat has been accepted for this long |
| `SB_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

Each variable also has a flag; run `gateway -h` for the list.

`SB_CP_ENDPOINT` must not carry userinfo. The Gateway ignores `HTTP_PROXY` and `HTTPS_PROXY` for every connection, to the control plane and to connectors, so a bearer credential never reaches a proxy.

The connectors file is a JSON array. Each entry has a `name` (a DNS label that the control plane binds to), a `kind` (`eso`, `rollout` or `argocd`) and kind-specific `settings`. The loader refuses unknown kinds, duplicate names and unknown fields, and its errors never repeat settings content. This build implements no connector kinds yet, so it refuses any entry at boot as not supported. The shape will look like this:

```json
[
  {"name": "eso-main", "kind": "eso", "settings": {}},
  {"name": "argocd-main", "kind": "argocd", "settings": {}}
]
```

## Development

```sh
go build ./... && go vet ./... && go test -race -count=1 ./...
golangci-lint run
```

CI also checks that `go.mod` and `go.sum` stay tidy. The guard tests in `internal/guard` check that no database, Redis, KV or ORM driver, no `k8s.io/client-go` and no platform module (`api`, `worker`, `agent`, `controller`) appears in `go.mod` (require and replace) or `go.sum` or is imported, that no file outside `internal/readonly` and `internal/client` builds an `http.Transport` and none uses `http.DefaultClient` or `http.Get`, and that no non-test Go file names a Kubernetes Secrets path. Kubernetes and ArgoCD are read with stdlib `net/http`, not `client-go`.

## Contributing

See [`CLAUDE.md`](CLAUDE.md) and the org [contributing guide](https://github.com/secrets-bridge/.github/blob/main/CONTRIBUTING.md). Feature branch, pull request, maintainer review.
