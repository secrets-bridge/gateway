# Gateway: threat model (STRIDE)

Status: design detail for [ADR 0001](../adr/0001-gateway-observation-plane.md). Defensive and design-level only. Vocabulary and verdict rules are defined in ADR section 2; the wire contract is in [control-plane.md section 4](control-plane.md#4-wire-contract); runtime controls are in [runtime.md](runtime.md).

## 0. Sources read

| File | What it tells us |
|---|---|
| `gateway/CLAUDE.md`, `skills/gateway/SKILL.md` | Gateway invariants and agreed review notes |
| `api/pkg/storage/jobs.go` | `ClaimNext` (`FOR UPDATE SKIP LOCKED`, lease, re-claim of expired claims), `Complete` (owner check on `claimed_by`) |
| `api/pkg/storage/gitops_observations.go` | CP-side observation rows; `ClaimNextActive` has no `claimed_by` column and no lease |
| `api/pkg/storage/agent_enrollment_tokens.go`, `api/pkg/storage/agents.go` | One-time token, SHA-256 hash only, `ConsumeAndCreateAgent` in one transaction, revoke, heartbeat |
| `api/internal/middleware/agentauth.go`, `api/internal/services/agents.go` (`Authenticate`) | `X-Agent-Secret`, SHA-256 and `subtle.ConstantTimeCompare`, generic 401, 60s hash cache, revoke deletes the cache entry |
| `api/internal/middleware/ratelimit.go`, `api/cmd/api/main.go` | Redis sliding window, fail-open by default; on the agent group only `/heartbeat` is rate-limited, after `AgentAuth` |
| `api/pkg/sanitize/sanitize.go` | Redaction patterns, JSON-blob stripping, length caps |
| `api/pkg/argocd/client.go`, `worker/internal/sweepers/gitops_poller.go` | GET-only transport, no redirects, status-field projection, `url.PathEscape` on the app name, no response size limit |
| `agent/internal/client/jobs.go`, `agent/internal/executor/patch.go`, `core/providers/awssecretsmanager/awssecretsmanager.go` | `PutValue` returns `SecretVersion.ID`; the patch executor discards it; `JobOutcome` has only `status` and `error` |
| `api/.github/workflows/docker-publish.yml` | SHA-pinned actions, semver tag on `main`, SBOM and SLSA provenance, cosign keyless signing by digest with `--recursive` |

## 1. System under analysis

```text
            Control plane (CP)                          Customer security boundary (tenant-a-uat)
  +-------------------------------------+         +------------------------------------------------+
  | api: gateway enroll / heartbeat /   |  HTTPS  |  Gateway Deployment (N replicas, stateless)    |
  |   catalog / claim / lease /         | <------ |   - CP client (outbound only)                  |
  |   release / result                  |         |   - connectors and targets (local config)      |
  | Postgres: gateways, connectors,     |         |       ESO (ExternalSecret status)              |
  |   bindings, observation_tasks,      |         |       apps/v1 Deployment, ReplicaSet           |
  |   evidence, audit_events            |         |       ArgoCD API (Application status)          |
  | Redis: rate limits, auth cache      |         |   - loopback /healthz /readyz /metrics         |
  | worker: sweepers, legacy ArgoCD     |         |  Agent (unchanged, separate identity)          |
  |   poller (until migrated)           |         |  kube-apiserver, ESO, ArgoCD                   |
  | ui: renders evidence                |         |                                                |
  +-------------------------------------+         +------------------------------------------------+
```

The Gateway opens every connection. The CP never connects into the customer boundary. The Gateway never talks to the Agent.

### 1.1 Trust boundaries

| ID | Boundary | Crossing | Direction |
|---|---|---|---|
| TB1 | Customer egress to CP ingress | Gateway HTTPS calls to `/api/v1/gateways/...` | Gateway to CP |
| TB2 | Gateway pod to kube-apiserver | ServiceAccount token, RBAC | Gateway to cluster |
| TB3 | Gateway pod to ArgoCD API | ArgoCD read-only token held customer-side | Gateway to ArgoCD |
| TB4 | CP api to Postgres and Redis | CP internal | CP internal |
| TB5 | CP evidence to UI viewer | Rendered evidence and labels | CP to browser |
| TB6 | One Gateway's scope to another's inside the CP | Routing, claim filter, result validation | CP internal |
| TB7 | Build pipeline to registry to customer cluster | Image digest, signature, chart | Supply chain |
| TB8 | Gateway credential versus Agent credential | Two identity kinds on one CP | CP internal |

## 2. Assets

| ID | Asset | Sensitivity | Why it matters |
|---|---|---|---|
| AS1 | Integrity of the verdict (`verified`, `partially_observed`, `unverified`, `timed_out`) | High | Change sign-off depends on it. A false `verified` is the main harm this component can cause. |
| AS2 | Gateway credential (enrollment token, long-lived Gateway secret) | High | Bearer material; grants claim and result rights for one Gateway |
| AS3 | Customer-side read credentials (ServiceAccount token, ArgoCD token) | High | Never leave the customer boundary |
| AS4 | Secret values and hashes of values in objects the Gateway can see | Critical | Must never be read into evidence, logged or sent. Section 5.2 lists where they hide. |
| AS5 | Observation metadata (request ids, ExternalSecret names, namespaces, app names, provider version ids) | Medium | Confidential to the customer; shows organisational structure |
| AS6 | Task queue state (leases, attempts) | Medium | Corruption causes lost, duplicated or misattributed evidence |
| AS7 | Availability of the CP api and of the customer kube-apiserver and ArgoCD | Medium | The Gateway must not become a load source on either side |
| AS8 | Audit trail of enrollment, bindings, claims, accepted and rejected results | High | Non-repudiation; append-only by trigger |
| AS9 | Agent execution path (wraps, patch jobs) | Critical | A Gateway compromise must not reach it |

## 3. Attacker profiles

| ID | Profile | Capabilities assumed | Goals |
|---|---|---|---|
| P1 | Malicious customer admin (legitimate admin of tenant-a-uat) | Owns its cluster, its Gateway and its Gateway secret; can modify Gateway code or run a fake Gateway | Forge `verified` for its own requests to pass a gate; read or influence another Gateway's tasks; overload the CP |
| P2 | Compromised Gateway pod | Code execution in the pod; reads its mounted credentials and SA token; network as the pod | Reach Secret values through RBAC; exfiltrate cluster metadata; submit false evidence; attack CP endpoints; reach the Agent |
| P3 | Stolen Gateway secret | Holds the bearer secret only, from a leaked values file, CI log or backup | Impersonate the Gateway from anywhere; read task metadata; post false evidence; starve real replicas |
| P4 | Network position | On-path proxy, TLS-terminating egress, compromised DNS | Capture bearer secrets; replay or alter results; redirect connector calls |
| P5 | CP insider or compromised CP | DB access; can create bindings and tasks; a DBA can bypass triggers | Use the Gateway as a read probe into customer clusters; fabricate evidence; hide failures |
| P6 | Workload author in the customer cluster | Can create or change Deployments, ExternalSecrets and ArgoCD apps in some namespace | Inject text through status messages; make a broken rollout look complete |

## 4. Findings in existing code that must not be copied blindly

| ID | Finding | Evidence | Consequence for the Gateway |
|---|---|---|---|
| F1 | `ClaimNext` has no scope predicate; any authenticated agent claims the oldest queued job | `jobs.go` `ClaimNext`: `WHERE status = 'queued' OR (status = 'claimed' AND claim_expires_at < now())` | The Gateway claim query filters on `gateway_id = <authenticated id>`, never on a request field |
| F2 | `Complete` fences only on `claimed_by` and `status = 'claimed'`; no attempt token and no lease-expiry check | `jobs.go` `Complete`: `WHERE id = $3 AND claimed_by = $4 AND status = 'claimed'` | With 100 replicas sharing one Gateway id, a late result from replica 7 would be accepted over replica 12's claim, and a result after lease expiry would be accepted. The Gateway uses a per-claim `attempt_id` and rejects results after `lease_expires_at` (section 5.3). |
| F3 | The provider version is not recorded | `agent/internal/executor/patch.go`, `agent/internal/client/jobs.go` | Needs the additive `result.provider_version` change (ADR 2.2). Without it no task can be `verified`. |
| F4 | `AgentAuth` accepts any row in `agents`; there is no kind discriminator | `agentauth.go`, `agents.go` | If Gateways were stored as agents, a Gateway secret could call `/agents/:id/jobs/claim` and `/agents/:id/wraps/:wrap_id`, which return sealed or plaintext secret values (AS9). Separate tables, middleware and route group. |
| F5 | The agent claim route has no rate limit, and the limiter fails open on Redis errors | `cmd/api/main.go` agent group; `ratelimit.go` | Gateway routes are limited after auth with an in-process fallback (section 5.6) |
| F6 | `ClaimNextActive` holds the row lock only for the statement and has no owner or lease | `gitops_observations.go` | Not a model for remote claim |
| F7 | The ArgoCD client escapes the app name with `url.PathEscape` but does not reject `..`, and decodes responses with no size limit | `pkg/argocd/client.go` | `url.PathEscape("..")` returns `..`. The Gateway validates names against the Kubernetes name grammar, applies a path allowlist and wraps bodies in `io.LimitReader`. |
| F8 | `pkg/sanitize` lives in the `api` module | `api/pkg/sanitize/sanitize.go` | Importing it would pull pgx and go-redis into the Gateway. The Gateway sends no free text, so it does not need it; the CI guard forbids the `api` module. |

## 5. Cross-cutting controls

### 5.1 Bound connectors versus SSRF

Invariant: a task names a connector the CP bound to this Gateway, never a URL, namespace, credential or command.

1. Connectors and targets are defined customer-side in Helm values: connector name, kind (`eso`, `rollout`, `argocd`), endpoint (ArgoCD URL), credential reference (mounted token file, or the pod ServiceAccount), namespace allowlist, and per-connector targets (target id, namespace, object name).
2. The Gateway advertises ids through `PUT /catalog`. An admin approves connectors and creates bindings that reference `(connector_id, target_id)` pairs. Advertising never creates a binding.
3. A task carries `task_id`, `attempt_id`, `request_id`, `correlation_id`, `connector_refs[{connector_id, target_id, stage}]`, the change marker and `deadline_at`. The task schema has no field for a namespace, object name, URL, credential, header or command.
4. The Gateway maps each id through local configuration. An unknown connector, unknown target, stage the connector kind cannot serve, or a target namespace outside the allowlist gives `attempt_status: refused` with an enum `refusal_reason`, and no read happens.
5. Both schemas are closed (`additionalProperties: false`). Unknown fields cause refusal.
6. HTTP clients: GET-only transport, no redirects (`CheckRedirect` returning `http.ErrUseLastResponse`), HTTPS required except an explicit dev flag, optional CA pin, response size cap, per-call timeout, and for ArgoCD a path allowlist.
7. Local object names are validated against the Kubernetes name grammar at boot (F7).
8. NetworkPolicy egress: DNS, CP, kube-apiserver, listed ArgoCD endpoints. Nothing else.

Result: a forged or malicious task cannot point the Gateway at a new host, namespace or object. A compromised CP can only choose among objects the customer listed.

### 5.2 No RBAC on Secrets, and where values still hide

Invariant: no `get`, `list` or `watch` on `secrets`.

RBAC removes direct Secret reads but not every path to value-derived data. Kubernetes has no server-side field selection on GET, so the full object reaches the Gateway process. Field projection in code is therefore required:

| Object | Value-derived content it may contain | Control |
|---|---|---|
| `apps/v1` Deployment | `spec.template.spec.containers[].env[].value` literals set by workload authors; Reloader may write a hash of Secret data into an env var or annotation (verify per strategy) | Read raw (a GET through the stdlib REST client), decode only into a projected struct: metadata scalars, `spec.replicas`, `spec.paused`, `spec.progressDeadlineSeconds`, `envFrom[].secretRef.name`, `env[].valueFrom.secretKeyRef.name`, `volumes[].secret.secretName`, `volumeMounts[].subPath` presence, allowlisted annotation key presence, the `kubectl.kubernetes.io/restartedAt` value, and status counts and condition `type`, `status`, `reason`. No typed `appsv1.Deployment`. Never `env[].value` or other annotation values. |
| ReplicaSet | Same pod template | Projected decode: `creationTimestamp`, revision annotation, `ownerReferences[].uid`, `status.replicas`, `status.availableReplicas` |
| ExternalSecret | `status.conditions[].message` can echo provider error text; the target Secret carries a data-hash annotation (verify the name) | Read `status.conditions[type=Ready]` `status`, `reason`, `lastTransitionTime`, `status.refreshTime`, `status.syncedResourceVersion`, `metadata.generation`, `spec.refreshInterval`, `spec.target.name`, and compare `remoteRef` keys locally. Never forward `message` or any hash. |
| ArgoCD Application | `spec.source.helm.values`, `valuesObject` and plugin env may hold inline secrets; `manifests`, `managed-resources` and `resource-tree` return rendered resources | Only `GET /api/v1/applications/{name}` and `GET /api/v1/session/userinfo` (path allowlist in the transport). Bounded body, projected decode of `status.sync.status`, `status.sync.revision`, `status.health.status`, `status.operationState.phase/startedAt/finishedAt`, `status.reconciledAt`, `spec.project`. Never `spec.source`. |
| Pod | `spec` holds env values | Not read in MVP |

Also never used: `secrets.checksum` and the provider `Checksum` field, which are fingerprints of values.

ESO linkage: `.status.syncedResourceVersion` tracks the ExternalSecret's own spec and metadata, not the provider version (verify). ESO status does not report the fetched provider version (verify). Time-ordered evidence can reach `verified` under the ADR 2.4 rule and is labelled "verified by time order"; `version_pinned` is the stronger link. This is ADR open question 1.

CI checks:

- Chart RBAC lint: rendered `Role` objects contain no `secrets`, no `*`, and exactly `get` on `externalsecrets`, `get` on `deployments`, `list` on `replicasets`.
- Static checks: no `corev1.Secret` reference, no typed `appsv1.Deployment` decoding, no Kubernetes write call outside the two review-object creates.

### 5.3 Fencing versus replayed and late results

Requirements: at-least-once delivery, no two active owners, stale or replayed results refused, accepted results persisted before completion.

- `observation_tasks` has `current_attempt_id` (UUID minted by the CP on each claim), `attempt_count`, `leased_replica_id` (informational), `lease_expires_at`, `state`. The `attempt_id` is not a credential on its own; every call also needs the Gateway secret.
- Claim: `FOR UPDATE SKIP LOCKED` filtered on `gateway_id = <authenticated id>` (F1).
- Result: inside one transaction, in order: ownership (404 for another Gateway's task), replay lookup in `observation_task_attempts` (same digest gives 200 `duplicate`, different gives 409 `result_conflict`), current attempt (409 `attempt_superseded`), lease still live (409 `lease_expired`, even if nobody re-claimed), deadline (409 `task_closed`), schema, scope, time window.
- Evidence insert, outcome, verdict and task transition happen in one transaction. There is no separate ack.
- Time bounds: `observed_at` within the attempt window plus skew. Connector timestamps (ESO `refreshTime`, ReplicaSet `creationTimestamp`) at or before `executed_at` plus skew cannot support an `observed` stage.
- Replay across tasks is blocked because `attempt_id` is per claim and the result binds `task_id`, `attempt_id` and the connector and target of the claimed task.

### 5.4 Scope isolation

- Each Gateway has one scope: its `boundary` label and an optional `environment_id`, set by the admin who created the row. The pre-created row, not the enrollment body, defines it. A Gateway cannot change its scope.
- Every Gateway endpoint derives identity from the authenticated Gateway id, never from the body, query or headers.
- Bindings are checked at creation: connectors belong to the same Gateway and are approved; targets are advertised; when `gateways.environment_id` is set, the binding's environment equals it.
- Tasks are created only from bindings. A request in one environment never produces a task for a Gateway bound to another.
- Result validation repeats the ownership and connector checks.
- Out-of-scope ids return 404, not 403.
- Separate identity kinds (F4): Gateway credentials are rejected by `AgentAuth`, and agent credentials by `GatewayAuth`.

### 5.5 Evidence is customer-side attestation

Everything the Gateway reports is produced inside a boundary the customer controls (P1, P2 and P6 can influence it). The CP cannot check it independently.

- Evidence is stored with `gateway_id`, `replica_id`, `gateway_version` and connector, and shown as "observed by Gateway <name>". Never "verified by Secrets Bridge".
- The CP computes the verdict from accepted evidence plus CP-held facts (`executed_at`, provider version). The Gateway sends observations; the schema has no verdict field. The CP recomputes each stage outcome and audits mismatches.
- Consistency checks: ESO `refreshTime` after `executed_at` plus skew; rollout after the refresh; ArgoCD `Healthy` is context only.
- Policy gates that consume the verdict must be able to require "CP-side evidence" or "Gateway attestation acceptable" per environment, so a customer cannot self-attest past a control owned by another party.
- Post-MVP: a per-Gateway signing key registered at enrollment, with results signed over a canonical form. This detects CP-side tampering of evidence rows (P5); it does not stop P1 from signing false data.

### 5.6 Denial of service in both directions

CP side:

- Empty claims are cheap: `observation_tasks_claim_idx (gateway_id, not_before, created_at) WHERE state IN ('queued','leased')`; 204 with growing `Retry-After`.
- Rate limits after authentication, keyed on the authenticated Gateway id, on heartbeat, claim, lease, release and result, with an in-process per-instance token bucket because the Redis limiter fails open (F5).
- `max_replicas` on the Gateway row: heartbeats from more distinct replica ids are refused and audited, which also flags a stolen secret used in parallel (P3).
- In-flight limits: 1 per replica, `max_inflight_tasks` per Gateway.
- Body limits per route (64 KiB for results); schema-capped arrays and enums only.
- Authentication: SHA-256 and constant-time compare with a 60s cache; unknown-id rejections rolled up per window.

Customer side (the Gateway must not overload kube-apiserver or ArgoCD, even if the CP is compromised and floods tasks):

- Jittered polling with exponential backoff on errors and 429.
- One in-flight task per replica by default.
- Per-connector token buckets and concurrency caps enforced locally.
- Per-task context deadline; passes past the deadline are refused (`deadline_passed`) without reads.
- Direct GETs on named objects, not cluster-wide informers.

### 5.7 Log and UI injection from connector data

P6 controls status text: ESO `status.conditions[].message`, Deployment condition `message`, ArgoCD `status.health.message` and `status.operationState.message`.

- No free text crosses to the CP in v1. Condition `reason` values are checked against `^[A-Za-z][A-Za-z0-9]{0,63}$` (otherwise `Other`) and ArgoCD statuses are mapped to enums.
- Gateway logs use structured JSON (`slog.NewJSONHandler`). Connector data is never interpolated into a format string or a message key, and condition messages are not logged.
- The CP stores only schema-validated enums, ids and timestamps. `gateways.last_error` is written by the CP only.
- The UI renders evidence as text (React default escaping), with no HTML rendering and no link detection.
- Metric labels never include object names, messages or request ids.

### 5.8 Supply chain

The Gateway image adopts the pipeline in `api/.github/workflows/docker-publish.yml`:

- Third-party actions pinned by commit SHA; `persist-credentials: false`.
- Strict semver tags on `main` before anything is published.
- Multi-arch build with `provenance: mode=max` and `sbom: true`.
- `cosign sign --yes --recursive "${IMAGE}@${DIGEST}"`, keyless, identity bound to the Gateway repo workflow; release notes print the `cosign verify` command with `--certificate-identity` and `--certificate-oidc-issuer https://token.actions.githubusercontent.com`.

Gateway additions:

- The chart references the image by digest by default and never defaults to rolling `dev` or `main` tags.
- Docs give an admission policy example that verifies the signature identity.
- CI fails if `go.sum` contains a database or Redis driver, or the `api` or `agent` module.
- Non-root, distroless, read-only root filesystem, no added capabilities, ServiceAccount token mounted only for the Gateway SA.

## 6. STRIDE by component

Legend: OUT outbound only, RO read-only, NOVAL no secret values or hashes, BIND bound connectors only, STATE stateless, NOAGT no Agent dependency, HON honest states. Section numbers refer to section 5.

### C1. Enrollment (E1 and admin mint)

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| S | Reused or guessed enrollment token | P3, P4 | 32-byte random token, SHA-256 hash only, single use, expiry, revoke of unused tokens; consume and set `secret_hash` in one transaction with `WHERE secret_hash IS NULL` | 5.4 |
| S | Token for one Gateway used to take over another | P1 | The token row names one pre-created Gateway; scope is never read from the body | 5.4 |
| T | Enroll body claims capabilities or scope | P1 | The E1 body has only the token and an optional cluster name | BIND |
| R | Admin denies minting a token | P5 | `gateway.enrollment_token.create` and `.revoke`, `gateway.enroll` audit events | 5.4 |
| I | Plaintext token or secret logged or returned twice | P5 | Returned once; never stored; tests scan Postgres and audit rows for a canary | NOVAL |
| D | Enrollment endpoint flood | P3 | Per-IP limiter, generic errors | 5.6 |
| E | Gateway enrolled as an agent and inherits agent routes | P2, P3 | Separate tables and middleware (F4) | NOAGT |

### C2. Claim (E4)

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| S | Stolen secret claims tasks from outside the cluster | P3 | Bearer auth as for agents; `max_replicas` and replica-count alerts; revoke; post-MVP proof-of-possession | 5.6 |
| T | Request names another scope or task | P1 | Identity from the authenticated id only; claim takes no task id | 5.4 |
| R | Gateway denies having claimed | P1 | `observation_task_attempts` row and `observation.task.claimed` audit with replica id and attempt | 5.3 |
| I | Task payload leaks another Gateway's metadata | P1 | `gateway_id` predicate (F1); closed task schema | 5.4 |
| I | Task payload carries values or credentials | P5, bug | The schema has no field that can hold them | NOVAL, BIND |
| D | 100 replicas tight-loop the claim route | P1, bug | Section 5.6 limits, 204 with `Retry-After` | 5.6 |
| D | Task hoarding: claim everything and never report | P3 | 60s lease, inline re-claim on expiry, per-replica and per-Gateway in-flight caps in SQL | 5.3 |
| E | Claim route reachable with an agent credential | P2 | Separate route group and middleware | NOAGT |

### C3. Result (E7)

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| S | Result from a replica that no longer holds the lease | bug, P2 | `attempt_id` and lease-expiry check (F2) | 5.3 |
| T | Replayed result from an older attempt | P4, P3 | Replay lookup by `(task_id, attempt_id)` and digest; older attempts get 409 | 5.3 |
| T | Gateway sends a verdict | P1 | No verdict field; CP computes verdict and recomputes stage outcomes | 5.5, HON |
| T | Fabricated timestamps make a rollout look later than the write | P1 | Time window checks, comparison with CP-held `executed_at`, attestation label | 5.5 |
| R | Customer disputes evidence it sent | P1 | Accepted and rejected results audited with Gateway id, replica id, attempt and reason | 5.3 |
| I | Result contains values, hashes, env literals, messages or manifests | P2, bug | Projected decode in the Gateway; closed schema with enums and tight patterns in the CP | 5.2, NOVAL |
| D | Oversized or deeply nested JSON | P1 | 64 KiB route limit, bounded arrays, fixed depth | 5.6 |
| E | Result for a task of another Gateway | P1 | Ownership check returns 404 | 5.4 |

### C4. Heartbeat, catalog and registry (E2, E3)

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| S | Stolen secret keeps a revoked Gateway looking alive | P3 | Revoke deletes the auth cache entry; heartbeat rejected after revoke | 5.4 |
| T | Heartbeat reports a false version or status | P1 | Informational only, enums only; never used for authorization | BIND |
| T | Catalog advertises a target in a namespace the customer did not intend | P2 | Catalog is built from local configuration only; an admin must approve the connector and create the binding; the chart refuses targets outside `rbac.namespaces` | 5.1 |
| I | Registry exposes other Gateways | P1 | Admin list endpoints behind `gateway.list` | 5.4 |
| D | Heartbeat or catalog flood | P1 | Limits after auth; body caps | 5.6 |

### C5. Task routing and queue (CP Postgres, worker)

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| T | Routing bug places a task under the wrong Gateway | bug | Tasks created only from bindings; binding checks; the result path rechecks connector ownership | 5.4 |
| T | Worker poller and Gateway both record evidence for one request | bug | `environments.observation_source` read once per request; test asserts exclusivity | HON |
| T | A later write's evidence is credited to an earlier request | bug | Older open tasks for the same secret are cancelled with `superseded_by_later_write`; the verdict rule requires no later CP-known write | HON |
| R | A task becomes `timed_out` without trace | bug | Sweeper transitions audited with reason | HON |
| D | Lease churn from crashing replicas | bug | Lease expiry is free but bounded by the deadline; `error` stages count toward `max_failures` | 5.3 |
| E | Worker gains connector credentials | P5 | The CP holds no customer-side connector credentials for Gateway environments | OUT |

### C6. Gateway runtime (pod, CP client)

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| S | Gateway talks to a fake CP | P4 | HTTPS required, TLS 1.2 minimum, optional CA pin and server name (agent `transport.go`), no redirects | OUT |
| T | Fake CP sends tasks that try to steer connectors | P4, P5 | Closed task schema; ids resolved against local configuration only | 5.1 |
| I | Gateway secret read by a co-located process or debug endpoint | P2 | Secret mounted as a file readable by the Gateway user; no pprof or debug listener; loopback-only health and metrics | OUT, STATE |
| I | Bearer secret visible to a TLS-terminating egress proxy | P4 | Documented residual risk; post-MVP short-lived session tokens | 5.6 |
| I | Value literals reach logs through a panic trace or debug log | P2, bug | Raw reads and projected decode, so literals are never in a Go struct; per-pass panic recovery that logs no values | 5.2 |
| D | CP unreachable causes retry storms | bug | Capped jittered backoff; no local spool | STATE, HON |
| E | Pod compromise reaches Secret values through RBAC | P2 | No `secrets` RBAC; boot self-check with SSAR fails closed; namespaced Roles; no `pods/exec`; the only Kubernetes creates are `SelfSubjectRulesReview` and `SelfSubjectAccessReview` | 5.2, RO |
| E | Pod compromise reaches the Agent | P2 | No Agent client code; NetworkPolicy denies Gateway to Agent; the Agent has no listener except loopback | NOAGT |

### C7. Connectors (ESO, rollout, ArgoCD)

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| S | Connector pointed at an attacker-controlled endpoint | P5 | Endpoints defined locally only | 5.1 |
| T | Workload author makes a rollout look complete (scale to 0, pause, change generation) | P6 | `kubectl rollout status` conditions with `spec.replicas`; `spec.replicas == 0` and `spec.paused` are `unverifiable`; rollout must follow the ESO refresh | HON |
| T | Rollback reuses an old ReplicaSet and hides a real rollout | P6 | Revision bump against the CP-stored baseline (`replicaset_revision_bumped_after_change`) | HON |
| T | ArgoCD `Healthy` used as proof | P6 | Never counted (invariant) | HON |
| I | Projection gap forwards env literals, inline Helm values or hash annotations | P2, bug | Projected decode structs, annotation key allowlist, golden tests with canary values | 5.2 |
| I | Path traversal in an ArgoCD app name reaches other GET endpoints | P5 | Name grammar validation and path allowlist (F7) | 5.1 |
| D | Large responses exhaust memory | P6 | `io.LimitReader` on all HTTP bodies; bounded ReplicaSet list | 5.6 |
| E | A future change issues a write | bug | GET-only transports; static write-call guard; RBAC has no write verbs | RO |

### C8. Evidence store and presentation (CP, UI)

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| S | Evidence shown as platform-verified | design | Label "observed by Gateway <name>" with id and version | 5.5 |
| T | CP insider edits evidence rows | P5 | `observation_evidence` and `audit_events` append-only by trigger; post-MVP signed results | 5.5 |
| I | One project's users see another's evidence | P1 | Existing request access check applies to evidence reads | 5.4 |
| E | Stored text renders as HTML | P6 | No free text stored; text rendering only | 5.7 |

### C9. Gateway logs, metrics, traces

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| T | Log forging through newlines or ANSI in status messages | P6 | Messages not logged; structured JSON | 5.7 |
| I | Values, secrets or tokens in logs | bug | Never log tokens, headers or bodies; canary log scan test | NOVAL |
| D | High-cardinality metric labels | P6 | Labels limited to connector id, stage and outcome | 5.7 |

### C10. Supply chain and Helm chart

| STRIDE | Threat | Attacker | Mitigation | Maps to |
|---|---|---|---|---|
| S | Unsigned or substituted image | supply chain | Cosign keyless signature by digest; chart pins digest; admission guidance | 5.8 |
| T | Malicious dependency adds write calls or a DB driver | supply chain | `go.sum` guard, RBAC lint, GET-only transport tests, SBOM review | 5.8, RO, STATE |
| I | Values file stores the Gateway secret in Git | P3 vector | Chart takes `existingSecret` only | 5.6 |
| E | Chart grants broad RBAC by default | design | Namespaced Roles only, with listed namespaces; no ClusterRole; no free-form rules | 5.2 |

## 7. Residual risks accepted for MVP

| Risk | Why accepted | Revisit trigger |
|---|---|---|
| A malicious customer admin can produce false evidence for its own requests | Inherent to customer-side observation; contained by labelling, CP recomputation and per-environment gate policy | Signed evidence (#7), required before Gateway evidence is presented as compliance evidence |
| Bearer secret replay through a TLS-terminating proxy | Same posture as the Agent today | Post-MVP proof-of-possession or short-lived session tokens |
| ESO linkage is time-ordered unless the version is pinned | ESO status does not expose the fetched provider version (verify) | ESO exposes a fetched-version field, or customers pin `remoteRef.version` |
| Out-of-band provider writes between the change and the ESO refresh are invisible | The CP only knows writes made through Secrets Bridge | Optional provider metadata read (not in v1; would add a provider credential to the Gateway) |
| A CP insider with DB access can fabricate rows | Same as the rest of the CP | Signed evidence |

## 8. Security tests required before release

Each test must fail when its control is removed: delete the control in a scratch branch and confirm the test goes red.

| ID | Control under test | Test | Fails without the control because |
|---|---|---|---|
| T01 | Claim predicate (F1) | Tasks for Gateways A and B; A claims until 204; no B task returned | The oldest task, from B, is handed to A |
| T02 | Ownership recheck on result | A posts a result for a B task id | The row is updated or 200 returned instead of 404 |
| T03 | Attempt fencing (F2) | Replica 1 claims, lease expires, replica 2 claims; replica 1 posts | Both share the Gateway id, so replica 1's result is accepted |
| T04 | Lease-expiry check | Claim, wait past `lease_expires_at` without re-claim, post | A late result is accepted |
| T05 | Idempotent accepted result | Post the same accepted result twice; then a changed body | Two evidence rows exist, or the changed body is accepted |
| T06 | Replay ordering | Lose the 200 after acceptance, retry | The retry gets 409 instead of 200 `duplicate` |
| T07 | No concurrent active owner | 100 pollers, 20 tasks; record live leases per task | Two replicas hold one task |
| T08 | Evidence persisted with the transition | Inject a failure after the evidence insert and before commit | The task is `done` with no evidence, or the reverse |
| T09 | Separate identity kinds (F4) | Gateway credential on `/agents/:id/jobs/claim` and `/agents/:id/wraps/:wrap_id`; agent credential on Gateway routes | The credential is accepted on the wrong routes |
| T10 | Closed task schema | Tasks containing `url`, `namespace`, `token`, `headers`, `command` | The Gateway acts on the field instead of refusing |
| T11 | Local resolution | Task names a `connector_id` or `target_id` absent from local configuration | The Gateway reads something |
| T12 | No redirects | Fake ArgoCD returns 302 to another host | The token is resent to the other host |
| T13 | GET-only transport and path allowlist | POST, PATCH, DELETE through every connector client; GET on `resource-tree` and `manifests` | The request reaches the server |
| T14 | Name grammar validation (F7) | Local config with app name `..` or containing `/` | The request path changes |
| T15 | Response size cap (F7) | Fake connector returns 50 MB | Memory grows unbounded |
| T16 | RBAC has no Secrets access | Render the chart; assert exact verbs; in an envtest cluster assert `get secrets` is forbidden for the Gateway SA | A widened Role passes review |
| T17 | Self-check fails closed | Grant `get secrets` through an aggregated role; also simulate `incomplete: true` with a failing SSAR | The Gateway becomes ready |
| T18 | Projection on Deployments | Canary literal in `env[].value` and a canary annotation value; run a pass, force a panic in a test build, enable debug logging; scan result body, logs and stored evidence | The canary appears |
| T19 | Projection on ArgoCD Applications | Canary in inline Helm values and in `operationState.message` | The canary is forwarded |
| T20 | CP-side schema on ingest | Result with an AWS-key-shaped string, a field named `data`, a free-text caveat | It is stored |
| T21 | Message never forwarded | ESO condition message containing a canary, `\n`, ANSI escapes and a fake JSON log line | The canary appears in the result or a forged log line appears |
| T22 | No verdict from the Gateway | Result containing `verdict: verified` | The stage or task is set from the Gateway's claim |
| T23 | `Healthy` alone is not proof | ArgoCD `Healthy`/`Synced` and no ESO or rollout evidence | The request shows `verified` |
| T24 | Timestamp bounds | ESO `refreshTime` equal to or before `executed_at` plus skew | The stage is `observed` |
| T25 | Rate limit after auth, with fallback | Poll at 10x budget; repeat with Redis stopped; send unauthenticated calls with a real Gateway id | No 429; or Redis loss removes the limit; or the real Gateway's budget is burnt |
| T26 | `max_replicas` | Heartbeats from `max_replicas + 1` replica ids | The extra replica is accepted silently |
| T27 | Revocation | Revoke, then claim within the 60s cache window; check leased tasks | The call succeeds, or tasks stay leased |
| T28 | Single-use enrollment | Two concurrent enrolls with one token | Two credentials exist |
| T29 | No Gateway to Agent path | NetworkPolicy test in a kind cluster; `go list -deps` shows no agent package | The path exists |
| T30 | Exclusive source | `gateway` environment: complete a request; no `gitops_observations` row | Both sources record evidence |
| T31 | No DB, Redis, api or agent module (F8) | CI `go.sum` grep | A transitive import goes unnoticed |
| T32 | Signed release image | `cosign verify` with the workflow identity; chart test asserts digest | Verify fails or a tag can be swapped |
| T33 | HTTPS required to the CP | Start with an `http://` endpoint and no dev flag | It connects in cleartext |
| T34 | Unknown-id audit roll-up | 10,000 requests with random Gateway ids | `audit_events` grows by 10,000 rows |
| T35 | No value fingerprint used | Static check and query log: no Gateway path selects `secrets.checksum` | A fingerprint of the value enters the evidence path |

## 9. Items to verify before implementation

- ESO: any `status` field that exposes the fetched provider version; `.status.syncedResourceVersion` semantics; the data-hash annotation name on target Secrets; served API versions.
- Reloader: the exact annotation or env var it writes, and whether it contains a hash of Secret data.
- ArgoCD: `status.reconciledAt` and `status.operationState.finishedAt` on supported versions; `account/can-i` support.
- Fiber global `BodyLimit` in `api/cmd/api/main.go`, so the 64 KiB route limit is not undercut by a smaller global setting.
- Agreement that the optional `result.provider_version` on job completion is acceptable under "Agent unchanged" (approved, ADR 0001 section 11).
