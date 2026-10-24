# Gateway: runtime and packaging

Status: design detail for [ADR 0001](../adr/0001-gateway-observation-plane.md). Nothing here is implemented. Vocabulary, stage rules, verdict rules and fixed values are defined once in ADR sections 2.1 to 2.5. The wire contract is in [control-plane.md section 4](control-plane.md#4-wire-contract).

Sources read on `main`: `agent/cmd/agent/{main.go,config.go,transport.go}`, `agent/internal/identity/{identity.go,keypair.go}`, `agent/internal/client/{limits.go,jobs.go}`, `agent/internal/local/local.go`, `agent/internal/executor/patch.go`, `api/pkg/storage/{jobs.go,gitops_observations.go,agent_enrollment_tokens.go,agents.go,argocd_endpoints.go}`, `api/pkg/argocd/client.go`, `core/providers/awssecretsmanager/awssecretsmanager.go`, `core/providers/vault/vault.go`, `worker/internal/sweepers/gitops_poller.go`, `charts/agent/{Chart.yaml,templates/_validation.tpl,templates/_helpers.tpl,templates/deployment.yaml,templates/networkpolicy.yaml}`.

## Release 1 scope

Release 1 of the Gateway covers read-only Argo CD rollout-state observation only ([#12](https://github.com/secrets-bridge/gateway/issues/12), [#15](https://github.com/secrets-bridge/gateway/issues/15)). The Gateway is the only Secrets Bridge component that talks to Argo CD ([#13](https://github.com/secrets-bridge/gateway/issues/13)).

- **Supported kind: `argocd`.** It reports Application sync status and revision, health, the last operation phase and reconcile time, as stage `argocd_context` (section 3.5). This is observed operational state. It is not proof that a secret value reached a running workload: the stage is at most `observed` with confidence `low`, never `failed` or `not_applicable`, has linkage `none`, carries caveat `argocd_health_not_proof` on every non-error observation, and never makes a verdict `verified` or failed (ADR 0001 section 2.3). State reconciled at or before the change is `not_observed`, an unreachable or refusing Argo CD is `error`, and an Application outside the allowed AppProjects is `unverifiable`. None of these is reported as a success.
- **No Kubernetes API access.** With only `argocd` connectors configured, the Gateway reads no in-cluster configuration, so it needs no service-account token, no `KUBERNETES_SERVICE_HOST` and no RBAC. It builds no Kubernetes client and runs no Kubernetes self-check (section 5.3). The chart can set `automountServiceAccountToken: false` and render no Role.
- **Release 2 kinds: `eso` and `rollout`.** The code stays in the tree for Release 2, but these kinds are not Release 1 features. The connectors file loader refuses them unless the operator sets `SB_GATEWAY_ENABLE_R2_CONNECTORS=true` (flag `--enable-r2-connectors`). That switch is for non-production use only, and the Gateway logs a WARN at boot saying so whenever it is on. The refusal names the entry index, the connector name and the kind, never settings content. With the switch off no Kubernetes connector factory runs.

Sections 3.3, 3.4 and 5 describe the Release 2 Kubernetes connectors. They apply only when the switch is on.

## 1. Findings from the code that shape the runtime

1. **Agent enrollment persists a file on a ReadWriteOnce PVC.** `identity.Save`, the chart's `identity-pvc.yaml` and the `maxSurge: 0` strategy make the agent a single-writer workload. A stateless, multi-replica Gateway cannot do that, so it reuses the token model (hash only, single use, expiry, revoke) but enrolls outside the pod (section 4).
2. **Loopback health versus kubelet probes.** The agent chart changelog records that kubelet `httpGet` probes cannot reach a `127.0.0.1` listener and the chart moved to `0.0.0.0`. The Gateway keeps loopback and uses an `exec` probe (`gateway healthcheck`). Metrics scraping is then opt-in (section 7).
3. **The worker's ArgoCD verdict would break the Gateway rule.** `decideTerminalState` in `worker/internal/sweepers/gitops_poller.go` maps `Healthy && Synced && (idle or Succeeded)` to `applied`. Parity testing must compare stage observations, not this mapping.
4. **Secret metadata is out of scope.** The epic lists "Kubernetes Secret metadata" as evidence. Reading Secret metadata, even with `PartialObjectMetadata`, still needs `get` or `list` on `secrets`, which also returns data. ExternalSecret status is the substitute.
5. **`api/pkg/argocd` cannot be imported.** It pulls the `api` module graph (pgx, go-redis). The Gateway copies the `readOnlyTransport` idea instead. The same applies to `api/pkg/sanitize`; the Gateway sends no free text, so it does not need it.

## 2. Process and repository layout

The Gateway mirrors `agent/` in shape and dependency discipline (stdlib `net/http`, `log/slog`, Prometheus client). It reads Kubernetes and ArgoCD with a stdlib `net/http` REST client on top of `internal/readonly`, not `k8s.io/client-go` (ADR 0001 section 6). It imports nothing from `api`, `worker`, `agent` or `controller` and nothing from `core/providers`.

```text
gateway/
  cmd/gateway/
    main.go            boot: config, identity, CP client, connector registry, loops, shutdown
    config.go          env and flags (SB_GW_*), envOr/envInt/envDuration helpers as in the agent
    transport.go       validateEndpoint, buildHTTPClient, buildTLSConfig, refuseRedirect (copied from agent)
    enroll.go          `gateway enroll`: exchange a one-time token, print the identity JSON to stdout
    healthcheck.go     `gateway healthcheck`: GET http://127.0.0.1:<port>/readyz (`--live`: /healthz), exit 0 or 1
  internal/
    client/            CP client: heartbeat, catalog, claim, lease, release, result
      limits.go        decodeJSON with per-endpoint caps (agent internal/client/limits.go pattern)
    identity/          read gateway_id and gateway_secret from a read-only file or env; no Save()
    config/            local connectors and targets file, validated at boot, catalog digest
    connectors/
      connector.go     interfaces and registry
      eso/             ExternalSecret reader, v1 with v1beta1 fallback
      rollout/         Deployment and ReplicaSet reader, raw read and projected decode
      argocd/          GET-only, path-allowlisted ArgoCD client
    evidence/          typed result structs, schema version, size guard
    clock/             Date-header offset tracking for the CP and the API server
    ratelimit/         per-connector token buckets
    runner/            claim loop, semaphore, bounded task context, result submission, release
    local/             loopback /healthz /readyz /metrics (agent internal/local pattern)
  Dockerfile           golang alpine build, distroless/static:nonroot runtime
  .github/workflows/ci.yml
```

CI guards:

CI runs these as Go tests in `internal/guard`, which parse `go.mod` (require and replace, both sides), `go.sum` and the Go source, plus a check of the resolved module graph (`go list -m all`).

- `no-db-or-redis`: no module path matching `pgx`, `pgconn`, `lib/pq`, `go-pg`, `mysql`, `mssqldb`, `clickhouse-go`, `sqlite`, `bolt`, `badger`, `goleveldb`, `pebble`, `mongo`, `redis`, `redigo`, `rueidis`, `valkey`, `radix`, `etcd`, `gorm`, `bun`, `ent` or `xorm`, and no `database/sql` import.
- `no-client-go`: no `k8s.io/client-go` or `controller-runtime` module.
- `no-platform-import`: no `github.com/secrets-bridge/{api,worker,agent,controller}` in `go.mod`, `go.sum` or any import.
- `http-transport-confined`: no `http.Transport` outside `internal/readonly` and `internal/client`, and no `http.DefaultClient`, `http.DefaultTransport`, `http.Get`/`Post`/`Head`/`PostForm` or `http.ProxyFromEnvironment` anywhere.
- `no-secrets-access`: no string literal in non-test Go outside `internal/readonly` that names `secrets` as a path segment or on its own (this covers concatenation and `path.Join`), and no `.Secrets` selector; render the chart with every values fixture and fail on any `secrets` resource. The self-check uses `readonly.SecretsResource`.
- `no-write-verbs`: enforced at runtime by `internal/readonly`, which allows `GET` on per-client path patterns and `POST` with a JSON body to exactly `/apis/authorization.k8s.io/v1/selfsubjectaccessreviews` and `/apis/authorization.k8s.io/v1/selfsubjectrulesreviews` (section 5.3), and refuses every other method before sending, with tests. Each client's policy also pins the scheme, host and port it was built for, and a request to any other origin is refused before it is sent, so a connector credential cannot reach another server.
- `no-typed-workloads`: fail on `appsv1.Deployment` or `appsv1.ReplicaSet` decoding outside tests; workloads are read raw (section 3.4).

## 3. Connectors

### 3.1 Local configuration, catalog and tasks

A connector can act only when three layers agree:

1. **Local configuration (Helm values, customer-owned).** Connectors: `eso-main` of kind `eso` allowed in namespaces `tenant-a-uat`; `rollout-main` of kind `rollout`; `argocd-main` of kind `argocd` with URL `https://argocd.example.com`, CA, token file and allowed AppProjects. Targets per connector: `target_id`, namespace and object name (and for ArgoCD, the Application name and optional app namespace). URLs and credentials exist only here.
2. **Catalog and binding (CP, admin-approved, audited).** At boot and when the heartbeat reports a different `catalog_version`, the Gateway sends `PUT /catalog` with connector ids, kinds, target ids, namespace and name for display only (ADR 0001 section 11), `refresh_interval_seconds` for ESO targets and `progress_deadline_seconds` for rollout targets, and `identity` for Argo CD targets once known (section 3.5). No URLs, no credentials and no raw uid. The body is closed and follows `schemas/gateway-catalog.schema.json`. The Gateway also sends it again when its local catalog changed since the last accepted upload, which happens when an Argo CD target's identity becomes known. An admin approves connectors and binds targets to a secret scope.
3. **Task.** `connector_refs[]` of `{connector_id, target_id, stage}` plus the change marker. No URL, namespace, object name, credential, header or command.

Before any read the runner checks: the schema version is supported; every `connector_id` exists locally with a kind that supports the stage; every `target_id` exists in that connector; the target namespace is in the connector allowlist and in `rbac.namespaces`. Any failure, or any unknown field, gives `attempt_status: refused` with a `refusal_reason` (`unknown_connector`, `unbound_target`, `stage_not_supported_by_connector`, `schema_violation`, `unsupported_schema_version`, `deadline_passed`, and `target_snapshot_stale` for a discovered target with no usable snapshot, section 3.6) and no connector call. A compromised CP can therefore only choose among objects the customer listed.

### 3.2 Interfaces

```go
package connectors

type Kind string   // "eso", "rollout", "argocd"
type Stage string  // "eso_sync", "workload_rollout", "argocd_context"
type Outcome string // "observed", "not_observed", "not_applicable", "unverifiable", "failed", "error"
type Linkage string // "version_pinned", "time_ordered", "none"

// Target comes from local configuration only, never from a task.
type Target struct {
    ID           string
    Connector    string
    Namespace    string // eso, rollout; must be in the connector allowlist
    Name         string // ExternalSecret, Deployment or Application name
    AppNamespace string // argocd "apps in any namespace", optional
}

// Expectation is built from task.expected_change and task.rollout_baseline.
type Expectation struct {
    SecretRefName     string
    ProviderVersionID string    // empty when version_source is none
    ExecutedAt        time.Time // CP clock
    DeadlineAt        time.Time
    SkewMargin        time.Duration
    Baseline          *RolloutBaseline
    ESORefreshTime    time.Time // filled by the runner from the eso_sync stage of the same pass
    ESOTargetSecret   string    // spec.target.name from the eso_sync stage of the same pass
}

type Observation struct {
    Stage      Stage
    Source     Source     // connector_id, target_id, api
    ObservedAt time.Time
    Outcome    Outcome
    Linkage    Linkage
    Confidence string
    Caveats    []Caveat   // enum
    ErrorCode  string     // enum, only with OutcomeError
    Resource   *Resource
    Facts      any        // one of ESOFacts, RolloutFacts, ArgoFacts; never map[string]any
}

type Connector interface {
    Kind() Kind
    // Check validates permissions at boot (section 5.3, section 3.5).
    Check(ctx context.Context) error
    // Observe does one bounded read pass. No watches, no retries inside.
    Observe(ctx context.Context, t Target, exp Expectation) (Observation, error)
}
```

`Observe` is a snapshot. The Gateway holds no informer cache and no state between passes. The runner runs `eso_sync` first in a pass so the rollout connector can compare against the `refreshTime` it just read. Repeated observation over time is the CP's job.

### 3.3 ESO connector (Release 2)

Refused at config load unless `SB_GATEWAY_ENABLE_R2_CONNECTORS=true` (see Release 1 scope).

API version: there is no discovery call at boot, and `GET /apis/external-secrets.io` is not in the allowlist. Each read asks for the object in `v1` first. When the API server answers that the group version is not served (a 404 without a `NotFound` Status), the same read retries in `v1beta1`. The connector remembers the version that last answered and tries it first on the next read. If neither version is served, the `eso_sync` stage reports `error` with `api_version_not_served`. Recent ESO releases serve `v1` and are removing `v1beta1` (verify for the supported range).

Read: `GET /apis/external-secrets.io/<version>/namespaces/{ns}/externalsecrets/{name}` with the dynamic client. `ClusterExternalSecret` is out of MVP.

Fields used:

- `metadata.generation`, `metadata.uid`, `metadata.resourceVersion`
- `spec.refreshInterval`, converted to seconds (0 means no timer refresh)
- `spec.refreshPolicy` when present (newer ESO; verify), which changes when `refreshTime` moves. An unknown or on-change-only policy gives caveat `refresh_interval_exceeds_deadline` unless a refresh after the change is already visible.
- `spec.target.name`, name only, never read the Secret
- `spec.data[].remoteRef.key`, `spec.data[].remoteRef.version`, `spec.dataFrom[].extract.key`: compared inside the Gateway with `expected_change.secret_ref.name` and `provider_version_id`. Only the results `remote_ref_match` and `remote_version_pin` are sent, never the keys or versions.
- `status.refreshTime`
- `status.syncedResourceVersion`, compared for equality only (verify that its format is still `<generation>-<hash of metadata>` and contains nothing derived from data)
- `status.conditions[type=Ready]`: `status`, `reason`, `lastTransitionTime`. `message` is never read into evidence or logs at info level.

Not used: the `reconcile.external-secrets.io/data-hash` annotation on the target Secret (a hash of values, and on an object the Gateway cannot read), and any `force-sync` annotation (a write).

Proposed outcome: the ADR 2.3 `eso_sync` rules, with `T = expected_change.executed_at` and skew from section 9. The refresh check: if not yet observed and `refreshInterval == 0` or `refreshTime + refreshInterval > deadline_at`, propose `unverifiable` with `refresh_interval_exceeds_deadline` on the first pass.

### 3.4 Rollout connector (Release 2)

Refused at config load unless `SB_GATEWAY_ENABLE_R2_CONNECTORS=true` (see Release 1 scope).

Read:

- `GET /apis/apps/v1/namespaces/{ns}/deployments/{name}` through the stdlib REST client, read as raw bytes.
- `GET /apis/apps/v1/namespaces/{ns}/replicasets?labelSelector=...&limit=50` with the selector built from `spec.selector`, following continue tokens, stopping after 200 items. Results are filtered to ReplicaSets whose `ownerReferences` include the Deployment `uid`.

Both responses are decoded from raw bytes into projected structs. The Deployment struct holds:

- `metadata.generation`, `metadata.uid`, `metadata.annotations["deployment.kubernetes.io/revision"]`
- `spec.replicas` (1 when unset), `spec.paused`, `spec.progressDeadlineSeconds` (600 when unset)
- `spec.template.metadata.annotations`: presence of allowlisted keys (Reloader keys, checksum annotation keys; verify the exact Reloader keys for the installed version), and the value of `kubectl.kubernetes.io/restartedAt` only, which is a timestamp
- `spec.template.spec.containers[].envFrom[].secretRef.name`, `containers[].env[].valueFrom.secretKeyRef.name`, `volumes[].secret.secretName`, `containers[].volumeMounts[].subPath` presence
- `status.observedGeneration`, `status.replicas`, `status.updatedReplicas`, `status.readyReplicas`, `status.availableReplicas`, `status.unavailableReplicas`, `status.conditions[type=Progressing|Available]` (`status`, `reason`)

It never holds `env[].value`, other annotation values, or anything else from the pod spec. Reloader's env-var and annotation strategies can write a hash of Secret data; those values are never decoded. The ReplicaSet struct holds `metadata.creationTimestamp`, the revision annotation, `ownerReferences[].uid`, `status.replicas` and `status.availableReplicas`.

Consumption mode, derived locally by comparing the referenced Secret names with the `spec.target.name` read in the same pass: `env`, `volume`, `subpath_volume`, `mixed`, `not_referenced`, `unknown`. Only the mode is sent.

Rollout complete (the `kubectl rollout status` rules): `observedGeneration >= generation`, `updatedReplicas == spec.replicas`, `status.replicas == updatedReplicas`, `availableReplicas == updatedReplicas`. `.status.replicas` alone is not used as the desired count, because during a rollout it includes old pods.

Qualifying rollout, in order:

1. The newest owned ReplicaSet (by revision) has `creationTimestamp` strictly after the ESO `refreshTime` plus skew: `rollout_trigger = replicaset_created_after_change`.
2. Otherwise, if `task.rollout_baseline` is set and the Deployment revision is greater than `baseline.deployment_revision`: `replicaset_revision_bumped_after_change` with caveat `replicaset_reused`. This covers a rollback or a template that matches an older revision, which reuses an old ReplicaSet with an old `creationTimestamp`. The CP stores the baseline from the earliest pass with `eso_sync` observed, so the Gateway stays stateless. A reuse that happened before that first pass is not detected and stays `not_observed`.
3. Otherwise `no_rollout_since_change`.

Proposed outcome: the ADR 2.3 `workload_rollout` rules. In particular: `volume` with no restart trigger gives `not_applicable` with `volume_refresh_not_observable`; `subpath_volume` gives `unverifiable` with `subpath_mount_not_refreshed`; `env` with `reload_mechanism = none_detected` and no qualifying rollout gives `unverifiable` with `reload_mechanism_unknown`; `spec.replicas == 0` gives `unverifiable` with `zero_replicas`; `spec.paused` gives `unverifiable` with `rollout_paused`.

Pods are not read in MVP.

### 3.5 ArgoCD connector (Release 1)

Only these requests are possible:

- `GET /api/v1/applications/{name}` (with `?appNamespace=` when the target sets it)
- `GET /api/v1/session/userinfo` at boot and on every recheck, with no query
- `GET /api/v1/account/can-i/{resource}/{action}/{object}`, with no query, for each question of the negative probe below, the read probe `applications` `get` on the literal object `*/*` (one exact path, sent as two `*` segments), and nothing else: per allowed AppProject `applications` `sync`, `update`, `delete`, `create`, `override`, `action`, `rollback` and `invoke`, `exec` `create`, `logs` `get` and `applicationsets` `create`, `update` and `delete` on `<project>/*`, and `projects` `update` and `delete` on `<project>`; per configured Application and allowed AppProject the same `applications` actions, `exec` `create` and `logs` `get` on `<project>/<app>`, and also on `<project>/<app-namespace>/<app>` when the target sets `app_namespace`. Each is an exact path in the transport allowlist.
- `GET /api/v1/applications?projects={project}&fields={projection}`: the application list, for discovery (ADR 0002 condition C1). It is in the policy only while `discovery.enabled` is true; with discovery off the policy has no list route and the transport refuses the request before it is sent. Only the discovery lease holder sends it, once per allowed AppProject per run (section 3.6).

The transport refuses every method other than GET before the request leaves the process, refuses redirects, and applies a path allowlist (`^/api/v1/applications/[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`, plus the exact paths above). Query keys are judged per path. The single-application GET admits only `appNamespace`. The list requires `projects` with exactly one value from the local AppProject allowlist (one request per AppProject) and `fields` with exactly one value, the fixed projection `metadata.resourceVersion,items.metadata.name,items.metadata.namespace,items.metadata.uid,items.spec.project` (no `creationTimestamp`: first seen comes from the control-plane clock, decision D3), and admits no other key; `refresh` is refused everywhere because it makes Argo CD patch the Application. userinfo and can-i carry no query. The `*` in a can-i path is sent literally and matches only those exact paths, never a wildcard pattern. The `exec` resource name is a plain path parameter of can-i, so only the exact `exec` can-i routes may carry that segment; every other path with an `exec`, `attach`, `portforward`, `proxy` or `log` segment is still refused. The list response is read up to `discovery.max_response_bytes` (default 16 MiB, at most 64 MiB) and decoded item by item into a struct with only `metadata.name`, `metadata.namespace`, `metadata.uid` and `spec.project`; once the run has decoded more than `discovery.max_applications` items across its AppProjects (default 2000, at most 10000), or a body is over the byte cap, the whole run is refused with `catalog_too_large`, never truncated. The decode does not rely on the server honouring `projects` or `fields`: an item from another AppProject, or with an invalid name, namespace or uid, is dropped and counted. `resource-tree`, `managed-resources` and `manifests` are blocked even though the `applications, get` permission allows them, because they can return rendered resource bodies. Names are validated against the Kubernetes name grammar before the path is built (`url.PathEscape("..")` returns `..`). The response is read through `io.LimitReader` (2 MiB) and decoded into a struct with only `metadata.name`, `metadata.namespace`, `metadata.uid`, `status.sync.status`, `status.sync.revision`, `status.health.status`, `status.operationState.phase`, `status.operationState.startedAt`, `status.operationState.finishedAt`, `status.reconciledAt` and `spec.project` (checked against the local AppProject allowlist). `spec.source.helm.values`, `valuesObject`, `status.health.message` and `operationState.message` are never decoded.

Outcome: always stage `argocd_context`, linkage `none`, caveat `argocd_health_not_proof`.

Identity: an Application is identified by its `metadata.uid`, not its name (ADR 0002 condition C3). An answer without a valid uid is an `internal` error and records nothing. A target can pin its uid in settings (`applications[].uid`, a lower-case UUID; any other value refuses the connectors file, so the Gateway does not start). A settings pin is checked from the first read on every replica and after every restart, and is never replaced by a read: it is the integrator's explicit, replica-wide confirmation of which object the target is. A target without one is pinned to the uid of the first successful read in each process. That auto pin lasts for the lifetime of the process only: a restart, or a replica that has not read the target yet, pins whatever object holds the name at that moment, so it is not a confirmation. A read that returns another uid than the pinned one (the Application was deleted and recreated) is answered with an `error` stage, `error_code` `target_identity_changed`, no resource and no facts, so nothing about the replacement (status, health, project) is reported, and a warning in the log. The integrator confirms the new object by setting its uid in settings, or by giving the target a new id.

Evidence boundary: the raw uid never leaves the Gateway. Argo CD evidence carries `resource.identity_digest` instead of `resource.uid`: `"d-"` followed by the first 130 bits, in lower-case base32, of `SHA-256("sb-argocd-target/v1" || uint32_be(len(connector_id)) || connector_id || uid)`, 28 characters in total, the same derivation ADR 0002 C3 uses for discovered target ids. The digest is one-way and scoped to the connector; the control plane can compare it across observations to see that the object behind a target changed, without learning the uid. The schema refuses `uid` on an `argocd_context` resource, and the uid is not logged or used as a metric label.

Identity in the catalog: each Argo CD target carries `identity` in the E3 catalog once its uid is known, the same digest as the evidence `identity_digest` below and never the raw uid. With a settings uid it is sent from boot. Without one it is sent after the first verified read: the Application named, a valid uid now pinned, an allowed AppProject, and the per-target probe passed. The first self-check makes that read for every target without a settings uid (the startup read, one GET per target per process start, the same request as an observation). A startup read that fails or is not verified changes nothing and does not refuse the start; the target is then learned on its first task. The control plane pins the first identity it accepts for a target, so a target recreated and then read by a restarted process, which pins the new object locally, arrives with a different identity and is caught there. Kubernetes connectors never carry `identity`.

The startup read is chosen over waiting for the first task: it costs one GET per static target per start, and the per-target probe it triggers would run at the first task anyway. In return the control plane can pin the object that exists when the Gateway starts, normally before a binding is made, instead of whatever object holds the name at the first task, and a narrow write grant on a static target refuses the start instead of surfacing at the first task.

Self-check, at boot and on every recheck: `GET /api/v1/session/userinfo` confirms the token works, then the project probe asks every project question listed above for each allowed AppProject, then the read probe, then (first check only) the startup read, then the target probe asks the target questions for each static target whose AppProject a verified read has told. A target not read yet is probed on its first verified read, before that observation is returned, and on every recheck after that; a target that moves to another allowed AppProject is probed again for it. The target probe catches a grant on one named Application or on a glob narrower than `<project>/*` (for example `sync` on `<project>/payments-*`), which Argo CD does not match against the `<project>/*` object of the project probe. Any `yes` is `over_privileged`, the same as the Kubernetes rule: the Gateway refuses to start, and at runtime it turns not ready, stops claiming and observing at once, and stops at the next recheck. The probe fails closed: a probe that fails or answers anything but `yes` or `no`, or that cannot run because userinfo failed, refuses the start at boot and leaves the connector unverified (not ready, nothing claimed or observed through it, no observation of the target returned) at runtime until a recheck passes. One answer is accepted as covered: `applications` `rollback` answered with HTTP 400. Argo CD releases before 3.6 have no `rollback` RBAC action, so their can-i refuses it as an unknown action, and their rollback endpoint enforces `sync`, which the probe asked on the same object just before and which answered `no`. Discovered targets (ADR 0002, S3) get the same target probe on both object forms: new ones once before they can enter a snapshot, bound ones on every recheck, and any one before a task when its last probe is older than the recheck interval (section 3.6). The daily sweep is deferred past the demo.

Read probe: `applications` `get` on `*/*`. A `yes` means the token can read Applications outside the allowlist. It is not over-privilege, because the token only reads and the local allowlist and the `projects` rule still bound every read. The connector reports `degraded` in the heartbeat, stays verified and ready, and is not checked again before every heartbeat; the full recheck asks again and reports `ok` once the grant is gone. The Gateway logs a warning that names the connector id, never the URL. A read probe that fails follows the fail-closed rules above.

A refused start names the failed check and how it failed, in fixed words: the resource and action (`applications sync`, `session userinfo`) and one of `can-i yes`, `unreachable`, `unauthorized`, `forbidden`, `timeout`, `tls`, `malformed`, `bad request`, `refused locally`, `not logged in` or `error`. It never names the AppProject, the object, the URL or the token.

A static target id may not start with `d-`, the prefix of discovered target ids (ADR 0002 condition C3). Such an id refuses the connectors file at boot.

Limits of can-i, checked against the Argo CD source (`server/account`, `util/rbac`, `assets/model.conf`): the action is one path segment and must be one of Argo CD's fixed action names, and Argo CD matches the policy's action as a glob against the question's action. A policy that grants `action/*` or `action/<group>/<kind>/<name>` therefore does not answer `yes` to the question `action`, and no can-i question can name such an action. The probe catches resource actions only through a wildcard action grant (`*`), so a resource-action grant is not detected. `invoke` is enforced by Argo CD on `extensions`, not `applications`; the `applications` `invoke` question only catches a wildcard grant. The Gateway lists applications only with `projects` set to allowed AppProjects. `api/pkg/argocd.SelfCheckRBAC` lists every application and only asserts that reads work, so it is not reused.

### 3.6 Discovery (ADR 0002 S3)

An `argocd` connector can discover its targets instead of, or next to, listing them in `applications`. The wire contract is [discovery-contract.md](discovery-contract.md); this section says what the Gateway does with it.

Settings: the `discovery` block of the connector settings, off by default. With `enabled: false` the connector is exactly Release 1: no list route, no new request.

| Setting | Default | Bounds |
|---|---|---|
| `enabled` | `false` | |
| `interval` | `5m` | whole seconds, `60s` to `30m` (the C9 floor) |
| `snapshot_max_age` | `15m`, or twice `interval` when that is longer | at least twice `interval`, at most `1h` |
| `max_applications` | `2000` | 1 to 10000, across all allowed AppProjects of one run |
| `max_response_bytes` | `16777216` (16 MiB) | 1024 to 67108864 (64 MiB), per list response |
| `identity_mode` | `names` | `names` only; `opaque`, `project_aliases` and `label_key` refuse the start until opaque mode ships |

With discovery on, `applications` may be empty, `allowed_projects` holds at most 64 AppProjects and none twice, and a static id still may not start with `d-`.

Snapshot key: discovery needs `snapshot_key`, standard base64 of 32 random bytes (`openssl rand -base64 32` at enroll), a key of the Gateway identity Secret mounted as a file at `SB_GATEWAY_SNAPSHOT_KEY_FILE` (default `/etc/secrets-bridge/gateway/snapshot_key`), with the same mode rules as the identity file. It is never read from an environment variable: with discovery on, `SB_GATEWAY_SNAPSHOT_KEY` set refuses the start. A missing file, a file that is too open, or a value that is not exactly 32 bytes refuses the start with `snapshot_key_invalid`. It is decoded once, the seal key is derived from it with HKDF-SHA256 (info `sb-gateway-snapshot-seal/v1`), and neither is ever sent, logged or used as a metric label. It is not derived from the Gateway secret, which the control plane sees on every request. With discovery off the file is not read.

Negotiation: every heartbeat lists contracts `1` and `2`. The first heartbeat after start is contract 1 shaped; after a response that answers `2`, heartbeats add `bound_targets_version` and, per Argo CD connector, `scope_digest`, `discovery_enabled` and (when enabled) `discovery_interval_seconds`. A 400 on a contract 2 shaped heartbeat (an old api replica during a rolling deploy) makes the next one contract 1 shaped again. While the control plane answers `1`, a discovery connector serves its static targets only, reports `degraded`, and the Gateway logs `discovery_unavailable` once with the reason `control_plane_contract_1`; it never lists without a lease. The heartbeat response is read up to 512 KiB.

Scope digest (C6): `scope_digest` is SHA-256 over the canonical JSON of the kind, `endpoint_digest`, the sorted allowed AppProjects, the discovery switch and the identity mode. `endpoint_digest` is SHA-256 over a label, the Gateway id, the connector id (both length-prefixed) and the normalized base URL. The URL itself is never sent.

Run, by the lease holder only: a heartbeat response grants a lease to at most one replica per connector. The holder:

1. takes `discovered_at` (Gateway clock, whole seconds) and must have its upload answered before `expires_at` minus 15 seconds, read on the local clock through the `Date` offset;
2. lists each allowed AppProject once through the C1 route, carrying the count cap across them; a body or count over a cap refuses the whole run with `catalog_too_large`;
3. keeps an item only with a valid name, namespace and uid in the AppProject it asked for (C3, C5), and drops and counts every other one in `entries_rejected`; a uid seen twice is dropped each time;
4. derives each target id from the uid, `d-` and 26 base32 characters (C3), so a deleted and recreated Application is a new target and a rename or project move keeps its id;
5. runs the per-target probe of every new target before it can enter the snapshot (C2). Targets the probe cannot reach before the deadline are left out and counted in `entries_deferred`, and are probed first next run. A `yes` stops the replica `over_privileged`; a failed probe leaves the connector unverified (decision D10). Either way nothing is uploaded;
6. seals the targets (id, AppProject, namespace, name, uid) with AES-256-GCM under the seal key and a fresh nonce, with associated data that binds the Gateway id, the connector id, the generation and `discovered_at`;
7. uploads the entries (id, AppProject, namespace, name, never the uid) and the sealed snapshot with E8, after checking the body against the contract and the 2 MiB cap, and retries the same bytes on a 5xx, a 429 or a network error while the lease is live.

The holder uses its own snapshot only after a 200 (`accepted` or `duplicate`) for its generation. On `lease_not_held`, `discovery_generation_stale`, `scope_digest_mismatch`, `catalog_too_large`, `schema_violation` or a 404 (an old api replica) it drops the run and keeps what it had. There is never a partial catalog.

Other replicas: when `snapshot_generations` is higher than the highest generation a replica has opened, and once when a task arrives for a discovered target while it has no usable snapshot (at most every 30 seconds), it fetches E9 (read up to 3 MiB, decoded strictly) and opens it, failing closed: the algorithm, a 12-byte nonce and the GCM open with associated data rebuilt from its own Gateway id and the connector it asked about; the plaintext schema; every target id equal to the digest of its uid; every AppProject in the local allowlist; a generation not lower than one it already opened; and an age within `snapshot_max_age` and not more than 60 seconds in the future. Any failure, a 404 included, leaves the replica with no usable snapshot. It never falls back to an older blob or to a name lookup. A blob sealed with a key derived from the Gateway secret, or under a rotated `snapshot_key`, fails the open. A network error or a 5xx keeps the current snapshot, which still expires at its maximum age.

Tasks: a task for a `d-` target on a connector with discovery on resolves through the snapshot only. With no usable snapshot, or one older than `snapshot_max_age` (checked again for every task), it is refused with `target_snapshot_stale` before any read. A `d-` id that is not in a usable snapshot is refused with `unbound_target`. Otherwise, when the target's last per-target probe is older than `SB_GATEWAY_PRIVILEGE_RECHECK_INTERVAL`, the probe runs first, then the one `GET /api/v1/applications/<name>?appNamespace=<namespace>` of Release 1. The answer must carry the snapshot's name and namespace and a uid whose digest is the target id, or the stage is `error` with `target_identity_changed` and nothing about the new object; an AppProject outside the allowlist is `unverifiable`. Discovery data is never evidence (C7).

Bound targets: each contract 2 response may carry the bound target list (a full replace, at most 4096 ids). A discovered target counts as bound when it is in that list or had a task in the last 24 hours, and every bound discovered target gets the per-target probe at each recheck.

Logs and metrics: discovery logs the connector id, generation, counts and closed codes only, never names, uids, digests of values or key material. `sb_gateway_discovery_runs_total{outcome}` counts runs and `sb_gateway_snapshot_fetches_total{outcome}` fetches, with closed outcome labels.

Deferred past the MVP: opaque mode, the daily full sweep and `argocd.probe_rate`, static to discovered migration. Without the sweep, an app-specific write grant added on an unbound target after its first probe is found only once the target is bound and rechecked or a task arrives; the Gateway never observes an unbound target.

## 4. Identity and enrollment

- **CP side.** `gateways` and `gateway_enrollment_tokens` (control-plane.md sections 3.1 and 3.2). The admin creates the Gateway row first and mints a token for it.
- **Enrollment.** The operator runs `gateway enroll --endpoint https://secrets-bridge.example.com --token-file token.txt` (or the equivalent curl against E1) from a workstation or CI step. It prints `{gateway_id, gateway_secret}` once. The operator stores it in a Kubernetes Secret, for example through ESO from their own vault. The chart mounts that Secret read-only. The pod never enrolls and never writes a credential, so the Gateway ServiceAccount needs no write access to anything.
- **Authentication.** `X-Gateway-Secret` on every call after enrollment.
- **Replica identity.** A random UUIDv4 generated at process start, sent as `replica_id` in each body. It does not come from the pod name or UID, which keeps cluster naming out of the CP. Ownership is enforced only by `attempt_id`.
- **Revocation.** The next call gets 401. The runner stops claiming, `/readyz` turns not ready, and the pod stays up so operators see the reason in logs (the agent posture).
- **Rotation.** Not in v1: revoke and re-create, as for agents. A two-hash `gateway_credentials` table is out of v1 (ADR 0001 section 11).
- **No keypair.** The Gateway never receives wraps or values, so it has no X25519 keypair and no DEK path.

## 5. Kubernetes RBAC (Release 2)

This section applies only when `eso` or `rollout` connectors are bound, which needs `SB_GATEWAY_ENABLE_R2_CONNECTORS=true`. An Argo CD-only Gateway (Release 1) has no Kubernetes RBAC and runs no Kubernetes self-check.

### 5.1 Default: namespaced Roles

One `Role` and `RoleBinding` per namespace in `rbac.namespaces`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secrets-bridge-gateway-read
  namespace: tenant-a-uat
rules:
  - apiGroups: ["external-secrets.io"]
    resources: ["externalsecrets"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["replicasets"]
    verbs: ["list"]
```

- `get` is enough for ExternalSecrets and Deployments because every read is by name from local configuration.
- `list` is needed on ReplicaSets to find the owned ones.
- No `watch`: connectors take snapshots. A later version that adds watches must add the verb explicitly.
- No `events` in MVP: events carry free-text `note` and `message` fields, and the evidence is limited to ExternalSecret status and Deployment or ReplicaSet metadata.
- No `secrets` in any form, no `configmaps`, no `pods`, `pods/log`, `pods/exec`, no subresources, no `*`.
- `SelfSubjectRulesReview` and `SelfSubjectAccessReview` creation is allowed for every authenticated user through `system:basic-user` and needs no rule here.

### 5.2 No ClusterRole

The MVP renders namespaced Roles only (ADR 0001 section 11). There is no `rbac.scope: cluster`: a cluster-wide `get` on Deployments would expose every `env[].value` literal in the cluster.

### 5.3 Boot self-check

For each allowed namespace, each Kubernetes connector:

1. Sends `SelfSubjectRulesReview`. A rule that grants any verb on `secrets` or a `secrets` subresource (directly or through `*`) is over-privilege, and so is a rule that grants a write verb (`create`, `update`, `patch`, `delete`, `deletecollection` or `*`) on a resource the connector reads (`externalsecrets`, `deployments`, `replicasets`) or one of its subresources.
2. Sends `SelfSubjectAccessReview` (`authorization.k8s.io/v1`) on core `secrets` for `get`, `list` and `watch`. If the rules review has `status.incomplete: true` (for example with a webhook authorizer), it sends one for every verb instead: `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, `deletecollection` and `*`, and one for each of those write verbs on each resource the connector reads. Any `allowed: true` is over-privilege. If any of these calls fails, the check fails closed. A 2xx answer without `status.allowed` (or, for the rules review, without `status.incomplete`) counts as a failed call, not as a denial.
3. Sends `SelfSubjectAccessReview` for the required verbs on `externalsecrets`, `deployments` and `replicasets`, and refuses readiness if any is missing.

A write grant on an observed resource is over-privilege, not a warning (gateway#11). The Gateway only observes, so such a grant only widens what a stolen pod token could change. There is no exception for shared or customer-provisioned service accounts.

On over-privilege the Gateway refuses to start and logs the reason. There is no override (ADR 0001 section 11); the fix belongs in the customer's RBAC.

A check that cannot prove the absence of Secrets access also refuses the start. This covers a failed review call of steps 1 and 2, including a 401 on the pod's service account token and an unreadable token file. The pod then restart-loops by design, with the reason in the log, until the credential or RBAC is fixed. This is the opposite of a 401 from the control plane, which stops claiming and keeps the process up and not ready (section 4), because a Gateway that cannot prove its Kubernetes permissions must not run at all.

The check runs again while the Gateway runs. A connector whose last check failed is checked before every heartbeat. Every connector, including those that passed, is checked again every `SB_GATEWAY_PRIVILEGE_RECHECK_INTERVAL` (`--privilege-recheck-interval`, default 5 minutes, at least 1 minute; a shorter value refuses the start; ADR 0002 decision D4). If a `secrets` grant, or a write grant on a resource a connector reads, was added after start, the replica turns not ready, stops claiming, sends an `over_privileged` heartbeat, logs the reason and exits; the next start refuses as above. A recheck that cannot prove the absence of Secrets access or of write access (a review call of steps 1 or 2 fails, or a review answer has no `status.allowed` or `status.incomplete`) fails closed until a later check passes: that connector is degraded and unverified, the replica is not ready, the claim loop claims no tasks while any connector is unverified, and the registry refuses to observe through that connector. Not ready alone would not be enough, because readiness only takes a pod out of a Service and the Gateway is not behind one. When the recheck passes, the connector is verified again and claiming resumes.

Creating these review objects is the only non-GET call the Gateway makes to the Kubernetes API. The read-only transport allows `POST` to exactly these two paths and refuses every other non-GET request. They persist nothing.

## 6. Polling, concurrency and limits

### 6.1 Task shape

One task is one observation pass over the `connector_refs` of one binding. The CP schedules the next pass after each accepted non-final result (control-plane.md section 5.1). The lease is 60s. A killed replica costs at most one pass.

### 6.2 Claim loop

Based on the agent's `claimLoop` and `claimOne`, with jitter and idle backoff added (the agent uses a fixed ticker):

```text
interval = SB_GW_CLAIM_INTERVAL
loop:
  wait jitter(interval)                 // uniform in [interval/2, interval*1.5]
  if in-flight slots full: continue     // non-blocking acquire, default 1 slot
  POST /api/v1/gateways/{id}/tasks/claim  (10s timeout)
    200 task  -> validate locally, run in a goroutine; interval = base
    204       -> interval = max(Retry-After, min(interval*2, SB_GW_CLAIM_IDLE_MAX))
    401       -> stop claiming, readiness false
    409 contract_version_unsupported -> stop claiming, readiness false, log at error
    429/503   -> honour Retry-After (capped 60s), else interval*2
    other     -> interval*2, capped
```

Long-poll is off in MVP (ADR 0001 section 11).

The heartbeat loop is separate, jittered by plus or minus 10 percent, and carries `replica_id`, `gateway_version`, `contract_versions`, replica status, in-flight count, `catalog_version` and connector health. When the response `catalog_version` differs from the local digest, the replica sends E3.

### 6.3 Bounded task execution

- Task context deadline: the earliest of the parent context, `lease_expires_at - 3s` (CP clock, adjusted by the measured offset) and 30s. If a pass needs longer, the runner renews once through E5.
- Per-call timeout: 5s for Kubernetes, 10s for ArgoCD.
- The result is posted once, with up to 3 retries on network errors or 5xx (1s, 2s, 4s) inside the remaining lease. The same body is resent, so a retry after a lost 200 gets 200 `duplicate`.
- 409 `attempt_superseded`, `lease_expired` or `task_closed`: drop the result and log at info. The CP schedules another pass.
- Shutdown: SIGTERM sets readiness false, sends a heartbeat with status `shutting_down`, stops claiming, waits up to `SB_GW_SHUTDOWN_GRACE` for in-flight passes, then calls E6 release with reason `shutdown` for anything unfinished.

### 6.4 Rate limits towards integrations

A central queue does not stop 100 replicas from sending 100 concurrent requests to one ArgoCD. Limits are layered:

- Per replica, per connector token bucket (`golang.org/x/time/rate`): Kubernetes default 5 qps, burst 10 (also set on `rest.Config.QPS` and `Burst`); ArgoCD default 2 qps, burst 4.
- Per replica, per connector concurrency cap: 2 in-flight requests.
- When a bucket would wait past the task context deadline, the stage reports `error` with `error_code: rate_limited` instead of blocking.

A fleet-wide budget hint from the CP (per-connector qps divided by active replicas) is a possible follow-up; it is not in the v1 heartbeat response.

### 6.5 Size limits

| Direction | Limit | How |
|---|---|---|
| Claim response | 64 KiB | `decodeJSON` with `io.LimitReader`, reject over limit |
| Heartbeat response | 512 KiB | same; the Gateway always lists contract 2, so a contract 2 api may send the bound target list |
| Catalog, lease, result and discovery upload responses | 16 KiB | same |
| Discovery upload (E8) body | 2 MiB | the run fails locally with `catalog_too_large`; the CP answers 413 above it |
| Snapshot fetch (E9) response | 3 MiB | read limit, then strict decode |
| Argo CD list response | `discovery.max_response_bytes`, default 16 MiB, at most 64 MiB | the run fails with `catalog_too_large` |
| Result body (Gateway to CP) | 64 KiB | the `evidence` package refuses to build a larger body; the CP enforces the same cap |
| Catalog body | 64 KiB | refuse to start if the local configuration does not fit |
| ArgoCD Application response | 2 MiB | `io.LimitReader`; projected decode |
| Kubernetes responses | per-call timeout, named GETs | ReplicaSet list with `limit=50` and continue tokens, stop after 200 |
| `connector_refs` per task | 3 | refuse larger tasks |

## 7. Health, metrics and logging

- `/healthz` (process up) and `/readyz` (identity loaded, first heartbeat accepted, catalog accepted, all connector self-checks passed, CP reachable within `cp.unreachableReadinessAfter`), `/metrics`, on `127.0.0.1:8091`.
- The claim loop checks the same state before every claim, not only once at start: a heartbeat accepted within `cp.unreachableReadinessAfter`, the current catalog accepted, and every connector verified. While any of them is false it claims nothing and logs the reason once; a pass already in flight finishes and posts its result. Readiness alone would not stop the poller, because the Gateway is not behind a Service.
- Probes: `exec: ["/usr/local/bin/gateway", "healthcheck"]` for readiness and `["/usr/local/bin/gateway", "healthcheck", "--live"]` for liveness, which work in `distroless/static` with no shell.
- Metrics scraping: `metrics.exposeOnPodIP: false` by default. When true, the chart binds `0.0.0.0:8091` and the NetworkPolicy allows ingress on that port only from `metrics.allowFrom`. This is the one documented exception to loopback-only, and it is opt-in.
- Metric names, with no namespace, object, application or request names as labels:
  - `sb_gateway_claims_total{outcome="task|empty|unauthorized|error"}`
  - `sb_gateway_tasks_inflight`
  - `sb_gateway_pass_duration_seconds{stage}`
  - `sb_gateway_connector_requests_total{connector,code}`
  - `sb_gateway_connector_ratelimited_total{connector}`
  - `sb_gateway_results_total{outcome="accepted|duplicate|superseded|lease_expired|rejected|error"}`
  - `sb_gateway_discovery_runs_total{outcome}` and `sb_gateway_snapshot_fetches_total{outcome="opened|not_found|refused|error"}` (section 3.6)
  - `sb_gateway_selfcheck_ok{connector}` (0 or 1)
  - `sb_gateway_clock_offset_seconds{peer="cp|apiserver"}`
- Logs: JSON through `slog`. Task id, attempt id, connector id, target id, stage and outcome are logged as attributes. Namespaces and object names are logged at debug only. Condition messages, response bodies, headers and tokens are never logged at any level. The ArgoCD token is read from file at use time and the endpoint is redacted like `redactEndpoint` in the agent. Panics are recovered per pass and logged without the value that was being processed.

## 8. Evidence construction

- Evidence is built from typed structs per stage (`ESOFacts`, `RolloutFacts`, `ArgoFacts`). There is no `map[string]any` and no raw or extra field.
- Condition reasons are checked against `^[A-Za-z][A-Za-z0-9]{0,63}$`; anything else becomes `Other`. ArgoCD statuses are mapped to the schema enums, unknown values to `Unknown`.
- No free text in any field. No messages, no operator opt-in for messages.
- No hashes of anything derived from values. `syncedResourceVersion` and `deployment.kubernetes.io/revision` are object revision markers and are allowed.
- Every result carries `schema_version`, `gateway_id`, `replica_id`, `gateway_version`, `attempt_id`, `clock`, and `observed_at` per stage.

## 9. Clocks and skew

Three clocks meet: the ESO controller writes `refreshTime` and the API server writes `creationTimestamp`; the CP writes `executed_at`; the agent or Vault writes `provider_version_at`. The Gateway records:

- `cp_offset_ms`: Gateway clock minus the `Date` header of the claim response;
- `apiserver_offset_ms`: Gateway clock minus the `Date` header of the Kubernetes responses in this pass.

Both are reported in `clock`. The CP applies `skew = margin + |cp_offset_ms| + |apiserver_offset_ms|` and compares strictly after `executed_at + skew` rounded up to the next second (control-plane.md section 5.2). `Date` has one-second resolution, so offsets below one second are reported as measured but have limited meaning; the margin covers them.

## 10. Stateless HA behaviour

- Any number of replicas share one Gateway id. They do not coordinate: no leader election and no Lease objects (which would need `coordination.k8s.io` write RBAC). Discovery is single flight through a lease the control plane grants in the heartbeat response (section 3.6); the Gateway keeps no shared state of its own.
- Ownership is per task through `attempt_id` and the lease. A replica that dies leaves a lease that expires after 60s; another replica claims with a new `attempt_id`; a late result from the dead attempt gets 409.
- Duplicate work is possible and harmless: reads are idempotent, and the CP accepts one result per `attempt_id`.
- Each replica reads the local configuration at boot and holds it in memory. A ConfigMap change rolls the pods through a checksum annotation.
- When the CP is unreachable, replicas keep heartbeating with backoff, turn not ready and stop claiming after `cp.unreachableReadinessAfter` (default 2m), and do not buffer evidence.
- PodDisruptionBudget `minAvailable: 1` when `replicaCount >= 2`. Topology spread is opt-in.
- HPA is supported, not default. Scaling on CPU would mostly scale idle pollers; queue depth per Gateway is a CP metric and would need an external metrics adapter. Out of MVP.

## 11. Helm chart

### 11.1 Location

`secrets-bridge/charts`, new directory `gateway/` next to `agent/`, chart name `secrets-bridge-gateway`. A separate chart, because the Gateway installs inside the customer boundary like the agent. Publishing follows the existing chart publish workflow.

### 11.2 Templates

```text
gateway/
  Chart.yaml
  values.yaml
  values.schema.json          types and enums; additionalProperties false at top level
  templates/
    _helpers.tpl              fullname, labels, image (digest or pinned tag), agent regex helpers
    _validation.tpl           render-time fail guards (11.4)
    serviceaccount.yaml
    rbac.yaml                 Role and RoleBinding per namespace
    configmap-connectors.yaml connectors and targets, URLs, allowlists (no tokens)
    deployment.yaml
    networkpolicy.yaml
    pdb.yaml
    NOTES.txt
```

No Service, no Ingress, no PVC, no StatefulSet, no Redis or database subcharts, no `DATABASE_URL` or `REDIS_URL`.

### 11.3 Values (outline)

```yaml
replicaCount: 2

image:
  repository: ghcr.io/secrets-bridge/gateway
  digest: ""             # preferred: sha256:<64 hex>
  tag: ""                # or X.Y.Z; default .Chart.AppVersion
  allowMutableTag: false # dev only
  pullPolicy: IfNotPresent

cp:
  endpoint: ""                 # required, https://secrets-bridge.example.com
  insecureTransport: false
  caExistingSecret: ""
  caExistingSecretKey: ca.crt
  tlsServerName: ""
  claimInterval: 5s
  claimIdleMax: 30s
  claimConcurrency: 1
  heartbeatInterval: 30s
  unreachableReadinessAfter: 2m
  egressCIDRs: []              # NetworkPolicy cannot match hostnames

identity:
  existingSecret: ""           # required; keys SB_GW_ID and SB_GW_SECRET, or identity.json
  mode: file                   # file (read-only mount, default) or env

rbac:
  create: true
  namespaces: []               # e.g. [tenant-a-uat]

connectors:
  eso:
    - name: eso-main
      namespaces: [tenant-a-uat]
      qps: 5
      burst: 10
      targets:
        - id: payments-api
          namespace: tenant-a-uat
          externalSecret: payments-env
  rollout:
    - name: rollout-main
      namespaces: [tenant-a-uat]
      qps: 5
      burst: 10
      targets:
        - id: payments-api
          namespace: tenant-a-uat
          deployment: api
  argocd:
    - name: argocd-main
      url: ""                  # https://argocd.example.com
      caExistingSecret: ""
      tlsServerName: ""
      tokenExistingSecret: ""  # required when this entry exists
      tokenExistingSecretKey: token
      projects: [tenant-a]     # local AppProject allowlist
      qps: 2
      burst: 4
      targets:
        - id: payments-api
          application: payments-api
          appNamespace: ""
      egress:
        namespaceSelector: {}
        podSelector: {}
        cidrs: []
        port: 8080

kubernetesAPI:
  egressCIDRs: []              # required with networkPolicy and any eso or rollout connector
  port: 443

selfCheck:
  argocdCanIProbe: false       # verify endpoint support before enabling

metrics:
  exposeOnPodIP: false
  port: 8091
  allowFrom: []

networkPolicy:
  enabled: true
  dnsNamespaceSelector: {}

serviceAccount:
  create: true
  name: ""
  annotations: {}

podSecurityContext:
  runAsNonRoot: true
  seccompProfile: { type: RuntimeDefault }
containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: [ALL] }

resources:
  requests: { cpu: 20m, memory: 48Mi }
  limits: { memory: 128Mi }

podDisruptionBudget:
  enabled: true
  minAvailable: 1
topologySpreadConstraints: []
nodeSelector: {}
tolerations: []
affinity: {}
```

The ESO API version is not a value; each read tries `v1` and falls back to `v1beta1` (section 3.3).

### 11.4 Render-time guards

- `cp.endpoint` required and `https://` unless `cp.insecureTransport=true`.
- `identity.existingSecret` required. No inline credential and no enrollment token value.
- Image pin guard identical to the agent chart: `image.digest` must match `^sha256:[0-9a-f]{64}$`, otherwise a pinned tag, unless `image.allowMutableTag=true`.
- `rbac.namespaces` non-empty.
- Every connector namespace and every target namespace is in `rbac.namespaces` and in its connector's `namespaces`.
- Connector names unique across kinds; target ids unique per connector; both DNS-label format.
- Each ArgoCD entry: `https://` URL, `tokenExistingSecret` and non-empty `projects`.
- `networkPolicy.enabled=true` requires `cp.egressCIDRs`, `kubernetesAPI.egressCIDRs` when any eso or rollout connector exists, and a selector or CIDRs for each ArgoCD entry. No fallback to "443 to anywhere".
- `metrics.exposeOnPodIP=true` requires `metrics.allowFrom`.
- `automountServiceAccountToken` cannot be false when any eso or rollout connector exists.
- There is no `rbac.extraRules`. A helm-unittest renders every fixture and asserts no `secrets` resource, no `*`, and only the verbs in section 5.1.

### 11.5 NetworkPolicy

```yaml
policyTypes: [Ingress, Egress]
ingress: []                       # or metrics.allowFrom on metrics.port when exposeOnPodIP
egress:
  - to: [ DNS namespace selector ] ports: 53/UDP, 53/TCP
  - to: [ ipBlock per cp.egressCIDRs ] ports: 443/TCP
  - to: [ ipBlock per kubernetesAPI.egressCIDRs ] ports: kubernetesAPI.port/TCP
  - per argocd connector: [ namespaceSelector and podSelector ] or [ ipBlock per cidrs ], port egress.port/TCP
```

Kubernetes API egress under NetworkPolicy depends on the CNI: some evaluate the Service ClusterIP, others the endpoint IPs. The values documentation tells operators to list both, and NOTES prints `kubectl get endpoints kubernetes -n default` as a hint.

### 11.6 Deployment specifics

- `strategy: RollingUpdate` with defaults (no PVC, so surge is fine).
- Identity Secret mounted read-only at `/etc/secrets-bridge/gateway/identity`, `defaultMode: 0400`, `fsGroupChangePolicy: OnRootMismatch` when `fsGroup` is set (`readCredentialFile` refuses any "other" bit and group write or execute, and accepts group read, so 0440 from `fsGroup` works).
- ArgoCD tokens mounted read-only per connector at `/etc/secrets-bridge/gateway/argocd/<name>/token`.
- The connectors ConfigMap mounted read-only, with a `checksum/connectors` pod annotation.
- No downward API env for pod name or UID.
- Probes are `exec` on `/usr/local/bin/gateway healthcheck` (readiness) and `healthcheck --live` (liveness).

## 12. ArgoCD account and RBAC

In `argocd-cm`:

```yaml
data:
  accounts.sb-gateway: apiKey
```

In `argocd-rbac-cm`, one line per allowed AppProject (`<project>/*`) or per application:

```csv
p, role:sb-gateway-read, applications, get, tenant-a/*, allow
g, sb-gateway, role:sb-gateway-read
```

Token: `argocd account generate-token --account sb-gateway --expires-in 2160h`, stored by the operator in the Secret named by `connectors.argocd[].tokenExistingSecret`.

- `applications, get` is the only permission. No `sync`, `override`, `action/*`, `update`, `delete`, `exec`, `logs`, and nothing on `clusters`, `repositories`, `projects` or `accounts`.
- The account should not have the `login` capability.
- `applications, get` also allows `manifests`, `managed-resources` and `resource-tree`. ArgoCD RBAC cannot split those, so the transport path allowlist blocks them.
- For "apps in any namespace" the policy object is `<project>/<app-namespace>/<app>` (verify on the installed version).
- No endpoint lists a token's permissions; the `can-i` probe (section 3.5) checks specific write and danger actions on each allowed AppProject and each static target. It cannot see an `action/<group>/<kind>/<name>` grant (section 3.5), so keep `action` out of the role by review.
- The token stays customer-side. The control plane no longer holds Argo CD tokens or URLs: api migration 0049 dropped the `argocd_endpoints` table, and the CP calls no Argo CD API.

## 13. Verify list

Each item must be checked against the supported versions before implementation relies on it:

- ESO: served API versions (`v1`, `v1beta1`) for the supported range; `status.binding`; the `syncedResourceVersion` format and the meaning of `observed_generation_matches`; `spec.dataFrom[].extract.version`; `spec.refreshPolicy` and how it moves `refreshTime`; default `refreshInterval` (1h in recent releases); provider client or value caching per ESO provider; whether any status field exposes the fetched provider version; the data-hash annotation name.
- Reloader: annotation keys per strategy, and whether they contain a hash of Secret data.
- Kubernetes: `kubectl rollout status` conditions as written in section 3.4.
- ArgoCD: RBAC object format for apps in any namespace (the probe asks both `<project>/<app>` and `<project>/<app-namespace>/<app>`; Argo CD 3.4 and later normalize the second form on can-i); `GET /api/v1/account/can-i/...` support and object format (route `/api/v1/account/can-i/{resource}/{action}/{subresource=**}` from 2.14 on, checked in the source, not on a running server); whether a `fields` filter exists on single-application GET; `status.reconciledAt` and `operationState.finishedAt` availability.
- Providers: read-after-write behaviour of AWS Secrets Manager and of Vault performance standbys, to size the default skew margin.
