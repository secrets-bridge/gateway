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

**Optional, outbound-only observation plane for [Secrets Bridge](https://github.com/secrets-bridge).** A Gateway runs inside a customer security boundary, reads Argo CD rollout state without changing anything, and reports it to the control plane as metadata-only evidence.

**Release 1 is Argo CD rollout-state observation only.** The Gateway reads the sync status and revision, health, last operation phase and reconcile time of the Argo CD Applications listed in its local configuration. That is observed operational state: Argo CD `Healthy` and `Synced`, or a finished rollout, are never proof that a new secret value reached a running workload. The External Secrets Operator (`eso`) and Kubernetes rollout (`rollout`) connectors are Release 2. Their code stays in the tree, but the Gateway refuses them unless a non-production switch is set (see Configuration).

> **Status: early implementation.** The design is [ADR 0001: Gateway as an outbound-only observation plane](docs/adr/0001-gateway-observation-plane.md) (status: Accepted), with detail in [`docs/design/`](docs/design/) and the wire schemas in [`schemas/`](schemas/). The implementation is in progress on draft pull requests and is not usable yet. The current code boots, loads its identity and locally bound connectors, and serves loopback health and metrics. It heartbeats to the control plane, uploads its catalog and claims observation tasks. It reads Argo CD Application state through bound `argocd` connectors.

## How it fits

```text
Control Plane (api, worker, Postgres)
   ^ outbound HTTPS from the customer side only
   |
   +-- Agent    : executes secret changes (unchanged, no Gateway dependency)
   +-- Gateway  : observes the rollout, read-only, reports evidence
                    +-- Argo CD sync, health and operation state (Release 1)
                    (ESO status and Deployment rollout: Release 2, off by default)
```

- **Optional.** Secret governance and execution work without a Gateway. With no Gateway, a change shows as unverified, never as failed.
- **Outbound only.** No inbound listener except a loopback health endpoint. The control plane never connects into the customer network.
- **Read-only.** Never syncs, rolls back or modifies anything.
- **No Kubernetes access in Release 1.** With only `argocd` connectors, the Gateway needs no Kubernetes API access, no service-account token and no RBAC. It builds no Kubernetes client and runs no Kubernetes self-check.
- **Metadata only.** No secret values in results, logs, traces or metrics, and no read access to Kubernetes Secrets.
- **Stateless.** No database or Redis on the customer side. Several replicas can share one Gateway identity.

## Layout

| Path | Purpose |
|---|---|
| `cmd/gateway` | Entry point: env and flag config, TLS transport to the control plane, boot and graceful shutdown |
| `internal/client` | Typed client for the gateway endpoints of the control plane (enroll, heartbeat, catalog, claim, lease, release, result). It refuses any other method or path, uses no proxy, never follows redirects, caps every response body and never copies response text into errors. Enrollment refuses any URL that is not `https`, and the client never prints the gateway secret |
| `internal/contract` | Go structs for the v1 ObservationTask and EvidenceResult, with validation that matches the JSON schemas vendored under `internal/contract/testdata`. `StageEvidence` is the one evidence model every connector returns |
| `internal/loop` | Heartbeat loop with connector health and the catalog upload, and the claim loop: jittered polling with idle backoff, bounded concurrency, one pass per lease that ends before the lease runs out, `attempt_id` echoed on every call, refusal of any task that names a connector or target not configured locally, the change marker passed to each connector, and stage linkage derived from the facts |
| `internal/connectors` | Connector interface (targets, self-check, observe), the registry of locally bound connectors and their targets, and the loader for the connectors file |
| `internal/connectors/argocd` | ArgoCD connector (Release 1). GET-only, path-allowlisted reads of one Application by name and of `session/userinfo` for the boot check. It proposes an `argocd_context` outcome: at most `observed` with confidence `low`, never `failed`, with caveat `argocd_health_not_proof` on every non-error observation. It never counts toward a verdict |
| `internal/connectors/eso` | ESO connector (Release 2, off by default). Reads one ExternalSecret by name (`external-secrets.io/v1`, falling back to `v1beta1` when `v1` is not served) and proposes an `eso_sync` outcome. It compares the remote keys and pinned versions with the task inside the Gateway and reports only the comparison result. It never reads the target Secret or the condition message |
| `internal/connectors/rollout` | Rollout connector (Release 2, off by default). Reads one `apps/v1` Deployment and the ReplicaSets it owns and proposes a `workload_rollout` outcome. It derives the consumption mode by comparing the Secret names in the pod template with the ExternalSecret target name, and reports only the mode. It does not read pods, logs, events or Secrets |
| `internal/connectors/kubeconn` | What the Release 2 Kubernetes connectors share: settings, the per-connector client, and the boot self-check |
| `internal/kube` | Minimal Kubernetes REST client on `net/http` and `internal/readonly`. Each connector gets its own client with its own path and query allowlist. It uses the in-cluster service account or an explicit server, CA and token file, re-reads the token file when it rotates, and never puts a URL, namespace, object name or label selector in an error |
| `internal/readonly` | The only transport for connector clients. Per client it allowlists GET path patterns and query keys, allows POST only to the two Kubernetes self-review paths with a JSON body, and refuses opaque or non-canonical URLs, upgrades, exec, attach, portforward, proxy and log paths, and Kubernetes Secret paths before a request leaves the process |
| `internal/identity` | Loads the gateway id and secret from env vars or a JSON file. Read-only, with no enrollment and no keypair. The secret is redacted in every fmt, JSON and slog output |
| `internal/local` | Loopback-only `/healthz`, `/readyz` and `/metrics` server |
| `internal/observability` | JSON structured logger |
| `internal/guard` | Guard tests for the module graph and source tree (see Development) |
| `deploy/rbac-example.yaml` | Release 2 only. Example namespaced Role and RoleBinding: `get` on externalsecrets and deployments, `list` on replicasets. There is no ClusterRole. A test fails on any cluster-scoped kind, secrets resource, wildcard or write verb |

`gateway healthcheck` is the client for Kubernetes `exec` probes, because the local server listens on loopback only and the image has no shell or curl. It sends one GET to `/readyz` on `SB_GATEWAY_LOCAL_ADDR` (or `/healthz` with `--live`) and exits 0 on a 200 and 1 otherwise. `--timeout` bounds the check (default `2s`, at most `30s`). It reads no identity, connectors file or control-plane setting, dials the literal loopback address directly and never uses a proxy:

```yaml
livenessProbe:
  exec:
    command: ["/usr/local/bin/gateway", "healthcheck", "--live"]
readinessProbe:
  exec:
    command: ["/usr/local/bin/gateway", "healthcheck"]
```

Planned next: an `enroll` subcommand. Until then, enroll with the curl call in [control-plane design section 4.2](docs/design/control-plane.md#42-e1-enroll).

Runtime behaviour:

- Readiness needs a recent accepted heartbeat, an accepted catalog and a passing self-check on every connector. Claiming starts only after the first heartbeat and catalog are accepted.
- A 401 from the control plane, or an unsupported contract version, stops claiming and leaves the process up and not ready, with the reason in the logs, so the pod does not restart-loop.
- Claiming also pauses, with the reason in the logs, while no heartbeat has been accepted within `SB_GATEWAY_CP_UNREACHABLE_AFTER`, the catalog is not accepted or a connector is unverified. A pass already running finishes. Claiming resumes once all three hold again.
- An `argocd` connector checks at boot that its token works (`GET /api/v1/session/userinfo`) and reads no Application until a task asks for one. It then asks Argo CD's can-i, for each allowed AppProject, whether the token may write or sync applications, exec, read logs, write applicationsets or update or delete the AppProject, and, after the first read of each configured Application, the same for that Application. Any `yes` stops the Gateway; a can-i call that fails keeps the connector unverified (nothing claimed or observed through it) until a recheck passes.
- **Release 1 behaviour change: an Argo CD outage at boot is a crash loop.** If Argo CD cannot be reached, refuses the token, or a can-i call fails while the Gateway starts, the Gateway refuses to start and exits, so Kubernetes restarts the pod with its usual back-off (`CrashLoopBackOff`). Before, the process stayed up and not ready. Nothing is claimed or observed either way. Recovery needs no action on the Gateway: once Argo CD answers and the token works, the next restart passes the self-check and the replica turns ready. To start sooner after fixing the cause, delete the pod or run `kubectl rollout restart` on the Deployment. The log line says which check failed (`unreachable`, `unauthorized` or the can-i resource and action), never the AppProject. An outage that starts after boot does not restart the pod: the replica turns not ready, stops claiming, and recovers on a later recheck.
- The rest of this list applies to the Release 2 Kubernetes connectors only. At boot each Kubernetes connector runs a self-check in every allowed namespace: a SelfSubjectRulesReview, a SelfSubjectAccessReview for `get`, `list` and `watch` on `secrets` (for every verb, `create`, `update`, `patch`, `delete`, `deletecollection` and `*` included, when the rules review is incomplete), and a SelfSubjectAccessReview for each verb the connector needs. If any `secrets` verb is allowed, or a review call fails, the Gateway refuses to start, and no setting overrides that. A failed review call includes a 401 on the pod's service account token: unlike a 401 from the control plane, it makes the pod restart-loop by design, with the reason in the log, because the Gateway must not run without proving it cannot read Secrets.
- The self-check of every connector runs again every 5 minutes. A `secrets` grant added after start makes the replica not ready, stops claiming, logs the reason and stops the Gateway. A missing required verb keeps the replica not ready. These two review creations are the only non-GET Kubernetes requests the transport lets through.
- The Gateway proposes stage outcomes only. It never sends a verdict, and it reports `version_pinned` only when the ExternalSecret pins a version that matches the provider version the agent reported.

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
| `SB_GATEWAY_ENABLE_R2_CONNECTORS` | `false` | Binds the Release 2 `eso` and `rollout` kinds. **Not supported for production**: when it is on, the Gateway logs a WARN at boot saying so. When it is off, a connectors file that names either kind is refused at load |
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

The connectors file is a JSON array. Each entry has a `name` (a DNS label that the control plane binds to), a `kind` and kind-specific `settings`. Release 1 binds `argocd` only. The `eso` and `rollout` kinds are refused at load unless `SB_GATEWAY_ENABLE_R2_CONNECTORS=true`. The loader also refuses unknown kinds, duplicate names and unknown fields, and its errors never repeat settings content.

```json
[
  {
    "name": "argocd-main",
    "kind": "argocd",
    "settings": {
      "base_url": "https://argocd.example.com",
      "token_file": "/etc/secrets-bridge/gateway/argocd/argocd-main/token",
      "ca_file": "/etc/secrets-bridge/gateway/argocd/argocd-main/ca.crt",
      "allowed_projects": ["tenant-a"],
      "applications": [{"id": "payments-api", "name": "payments-api"}]
    }
  }
]
```

The control plane names only a connector and a target id. The Argo CD URL, token and Application names stay in this file, and an Application outside `allowed_projects` is reported as `unverifiable` with no status. The token needs only `applications, get` in Argo CD RBAC ([runtime design section 12](docs/design/runtime.md#12-argocd-account-and-rbac)). An Argo CD-only Gateway can run with `automountServiceAccountToken: false` and no Role.

What the `argocd` connector proposes for stage `argocd_context` (the control plane recomputes every outcome from the facts):

- `observed`, confidence `low`, when the Application is `Healthy` and `Synced` with no operation or a `Succeeded` one, and was reconciled after the change. This is the strongest outcome, and it never counts toward a verdict.
- `not_observed` for anything else, including `Progressing`, `Degraded`, `OutOfSync`, a failed operation (caveat `argocd_operation_unrelated`) and state reconciled at or before the change (caveat `observed_before_not_before`). `Degraded` is context, not a failure of the secret change.
- `unverifiable` for an Application outside the allowed AppProjects, and `error` with a fixed code when Argo CD cannot be read.

### Release 2 connectors (not for production)

With `SB_GATEWAY_ENABLE_R2_CONNECTORS=true` the loader also binds `eso` and `rollout`:

```json
[
  {
    "name": "eso-main",
    "kind": "eso",
    "settings": {
      "namespaces": ["tenant-a-uat"],
      "targets": [{"id": "payments-api", "namespace": "tenant-a-uat", "external_secret": "payments-env"}]
    }
  },
  {
    "name": "rollout-main",
    "kind": "rollout",
    "settings": {
      "namespaces": ["tenant-a-uat"],
      "targets": [{"id": "payments-api", "namespace": "tenant-a-uat", "deployment": "payments-api"}]
    }
  }
]
```

The control plane names only a connector and a target id. The namespace and object name stay in this file, and a target whose namespace is not in `namespaces` is refused at boot. Without a `kubernetes` block a connector uses the pod's service account. To reach another cluster, add `"kubernetes": {"server": "https://k8s.example.com:6443", "ca_file": "/etc/gateway/k8s-ca.crt", "token_file": "/etc/gateway/k8s-token"}`. The server must be an `https://` origin with no path, unless `SB_INSECURE_TRANSPORT=true`.

What the Release 2 Kubernetes connectors propose (the control plane recomputes every outcome from the facts):

- `eso_sync` is `observed` when the ExternalSecret is `Ready=True` with reason `SecretSynced`, a `remoteRef.key` equals the changed secret, and `refreshTime` is strictly after `executed_at` plus skew and the measured API server offset. It is `failed` when `Ready=False` changed after that bound, and `unverifiable` when the key does not match, `dataFrom` uses `find`, the version is pinned to something else, or no timer refresh can happen before the deadline.
- `workload_rollout` is `observed` when the current ReplicaSet was created after the ESO refresh of the same pass (or the revision rose above the control plane's baseline) and the rollout is complete by the `kubectl rollout status` rules. It is `failed` on `ProgressDeadlineExceeded` for such a rollout, `not_applicable` for a volume consumer with no restart trigger, and `unverifiable` for `subPath` mounts, paused or zero-replica Deployments, and env consumers with no reload mechanism.

## Development

```sh
go build ./... && go vet ./... && go test -race -count=1 ./...
golangci-lint run
```

CI also checks that `go.mod` and `go.sum` stay tidy. The guard tests in `internal/guard` check that no database, Redis, KV or ORM driver, no `k8s.io/client-go` and no platform module (`api`, `worker`, `agent`, `controller`) appears in `go.mod` (require and replace) or `go.sum` or is imported, that no file outside `internal/readonly` and `internal/client` builds an `http.Transport` and none uses `http.DefaultClient` or `http.Get`, and that no non-test Go file names a Kubernetes Secrets path. Kubernetes and ArgoCD are read with stdlib `net/http`, not `client-go`.

## Contributing

See [`CLAUDE.md`](CLAUDE.md) and the org [contributing guide](https://github.com/secrets-bridge/.github/blob/main/CONTRIBUTING.md). Feature branch, pull request, maintainer review.
