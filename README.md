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

> **Status: early implementation.** The design is [ADR 0001: Gateway as an outbound-only observation plane](docs/adr/0001-gateway-observation-plane.md) (status: Accepted), with detail in [`docs/design/`](docs/design/) and the wire schemas in [`schemas/`](schemas/). The implementation is in progress on draft pull requests and is not usable yet.

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

## Planned layout

| Path | Purpose |
|---|---|
| `cmd/gateway` | Entry point, config, task claim loop |
| `internal/client` | Outbound HTTPS client to the control plane |
| `internal/connectors` | Read-only connectors: ESO, Kubernetes rollout, ArgoCD |
| `internal/identity` | Enrollment and persistent identity |

## Contributing

See [`CLAUDE.md`](CLAUDE.md) and the org [contributing guide](https://github.com/secrets-bridge/.github/blob/main/CONTRIBUTING.md). Feature branch, pull request, maintainer review.
