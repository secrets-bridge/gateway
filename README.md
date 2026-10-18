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

> **Status: design phase.** The proposed design is [ADR 0001: Gateway as an outbound-only observation plane](docs/adr/0001-gateway-observation-plane.md) (status: Proposed), with detail in [`docs/design/`](docs/design/) and the wire schemas in [`schemas/`](schemas/). A draft implementation is in progress on pull requests that stay in draft until the ADR is approved. The current code boots, loads its identity and locally bound connectors, and serves loopback health and metrics. It does not call the control plane or observe anything yet.

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
| `cmd/gateway` | Entry point: env and flag config, TLS transport to the control plane, boot and graceful shutdown. The control-plane loop plugs in behind one interface; this build makes no control-plane calls and stays not ready |
| `internal/connectors` | Connector interface, the registry of locally bound connectors, and the loader for the connectors file. No connector kinds are implemented yet |
| `internal/readonly` | HTTP transport for connector clients. It refuses every method except GET and denies Kubernetes Secret paths before a request leaves the process |
| `internal/identity` | Loads the gateway id and secret from env vars or an owner-only JSON file. Read-only, with no enrollment and no keypair |
| `internal/local` | Loopback-only `/healthz`, `/readyz` and `/metrics` server |
| `internal/observability` | JSON structured logger |

Planned next: the control-plane client (`internal/client`) and the ESO, rollout and ArgoCD connectors.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SB_CP_ENDPOINT` | required | `https://` only, unless `SB_INSECURE_TRANSPORT=true` (development only) |
| `SB_CP_CA_FILE` | empty | PEM bundle that replaces the system roots |
| `SB_CP_TLS_SERVER_NAME` | empty | TLS server name override |
| `SB_GATEWAY_ID`, `SB_GATEWAY_SECRET` | empty | Credential pair. When unset, `SB_GATEWAY_IDENTITY_FILE` is read |
| `SB_GATEWAY_IDENTITY_FILE` | `/etc/secrets-bridge/gateway/identity.json` | `{"gateway_id": "...", "gateway_secret": "..."}`, mode 0600 or 0400. Looser modes are refused |
| `SB_GATEWAY_LOCAL_ADDR` | `127.0.0.1:8091` | Must be a loopback address |
| `SB_GATEWAY_CONNECTORS_FILE` | empty | JSON list of bound connectors, see below. Empty binds none |
| `SB_GATEWAY_SHUTDOWN_GRACE` | `15s` | Graceful shutdown deadline |
| `SB_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

Each variable also has a flag; run `gateway -h` for the list.

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

CI also checks that `go.mod` and `go.sum` stay tidy, that no database, Redis, `k8s.io/client-go` or Agent module enters the dependency graph, and that no non-test Go file contains a Kubernetes Secrets API path.

## Contributing

See [`CLAUDE.md`](CLAUDE.md) and the org [contributing guide](https://github.com/secrets-bridge/.github/blob/main/CONTRIBUTING.md). Feature branch, pull request, maintainer review.
