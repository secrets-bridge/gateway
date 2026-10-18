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

> **Status: design phase.** The architecture decision record is still under review, and a draft implementation is in progress on pull requests that stay in draft until it is approved. The current code boots, loads its identity and locally bound connectors, and serves loopback health and metrics. It can read Deployment rollout status through a bound rollout connector, but it does not call the control plane yet, so nothing triggers an observation.

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
| `internal/connectors` | Connector interface, the registry of locally bound connectors, and the loader for the connectors file. The registry checks every result. Facts are typed, reason and caveat codes come from fixed sets, and the rollout and ArgoCD kinds can never report `verified` |
| `internal/connectors/rollout` | Rollout connector. Reads one `apps/v1` Deployment and the ReplicaSets it owns, and reports whether a new ReplicaSet became available after the change marker. It does not read pods, logs, events or Secrets |
| `internal/kube` | Minimal Kubernetes REST client on `net/http`. It uses the in-cluster service account or an explicit server, CA and token file, and re-reads the token file when it rotates. Built on `internal/readonly`, so only GET leaves the process and Secrets paths are refused |
| `internal/safetext` | Strips control characters and caps the length of strings copied from a cluster, so they cannot forge log lines |
| `internal/readonly` | HTTP transport for connector clients. It refuses every method except GET and denies Kubernetes Secret paths before a request leaves the process |
| `internal/identity` | Loads the gateway id and secret from env vars or an owner-only JSON file. Read-only, with no enrollment and no keypair |
| `internal/local` | Loopback-only `/healthz`, `/readyz` and `/metrics` server |
| `internal/observability` | JSON structured logger |
| `deploy/rbac-example.yaml` | Example Role and ClusterRole for the rollout connector: `get` on deployments and `list` on replicasets only. A test fails on any secrets resource, wildcard or write verb |

Planned next: the control-plane client (`internal/client`) and the ArgoCD connector. This build has no ESO connector.

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

The connectors file is a JSON array. Each entry has a `name` (a DNS label that the control plane binds to), a `kind` (`eso`, `rollout` or `argocd`) and kind-specific `settings`. The loader refuses unknown kinds, duplicate names and unknown fields, and its errors never repeat settings content. This build implements the `rollout` kind only and refuses any other kind at boot as not supported.

```json
[
  {
    "name": "rollout-main",
    "kind": "rollout",
    "settings": {
      "namespaces": ["tenant-a-uat"],
      "targets": [
        {"id": "payments-api", "namespace": "tenant-a-uat", "deployment": "payments-api"}
      ]
    }
  }
]
```

The control plane only names a connector and a target id. The namespace and Deployment name stay in this file. A target outside `namespaces` is never read and reports `unverifiable`. Without a `kubernetes` block the connector uses the pod's service account. To reach another cluster, add `"kubernetes": {"server": "https://k8s.example.com:6443", "ca_file": "/etc/gateway/k8s-ca.crt", "token_file": "/etc/gateway/k8s-token"}`. The server must use `https://` unless `SB_INSECURE_TRANSPORT=true`.

A rollout result is `observed` only when the Deployment's current ReplicaSet was created strictly after the change marker and is fully available. It is never `verified`, because nothing in the Deployment ties a rollout to a provider version. With no new ReplicaSet and no Reloader or checksum annotation, the result is `unverifiable` with caveat `reload_mechanism_unknown`, since nothing will restart the pods.

## Development

```sh
go build ./... && go vet ./... && go test -race -count=1 ./...
golangci-lint run
```

CI also checks that `go.mod` and `go.sum` stay tidy, that no database, Redis, `k8s.io/client-go` or Agent module enters the dependency graph, and that no non-test Go file contains a Kubernetes Secrets API path.

## Contributing

See [`CLAUDE.md`](CLAUDE.md) and the org [contributing guide](https://github.com/secrets-bridge/.github/blob/main/CONTRIBUTING.md). Feature branch, pull request, maintainer review.
