# Gateway: control plane changes

Status: design detail for [ADR 0001](../adr/0001-gateway-observation-plane.md). Nothing here is implemented. Vocabulary, stage rules, verdict rules and fixed values are defined once in ADR sections 2.1 to 2.5 and are not repeated here.

Sources read on `main`: `api/pkg/storage/{jobs.go,gitops_observations.go,agent_enrollment_tokens.go,agents.go,access_requests.go}`, `api/pkg/storage/migrations/{0001,0010,0012,0014,0015,0028,0030,0034,0038,0040}_*.up.sql`, `api/internal/services/{requests.go,requests_binding.go,gitops.go,jobs.go,agents.go,agent_enrollment.go}`, `api/internal/handlers/{jobs.go,agent_enrollment.go,agents.go}`, `api/internal/middleware/{agentauth.go,ratelimit.go}`, `api/cmd/api/{main.go,config.go}`, `api/internal/auth/permissions.go`, `agent/internal/executor/patch.go`, `agent/internal/client/jobs.go`, `core/providers/{provider.go,awssecretsmanager/awssecretsmanager.go,vault/vault.go}`, `worker/internal/sweepers/{gitops_timeout.go,jobs_recovery.go,gitops_poller.go,agents_stale.go}`, `ui/src/pages/request/GitOps.tsx`.

## 1. Summary

1. Queue: Postgres `FOR UPDATE SKIP LOCKED` on a new `observation_tasks` table, filtered by `gateway_id` in the claim predicate. No Redis Streams in the MVP.
2. Identity: new `gateways` and `gateway_enrollment_tokens` tables with the shape and single-use transaction of `agent_enrollment_tokens`. The agent token table is not reused (section 3.2).
3. Routing: a task is created only from an admin-made `gateway_connector_bindings` row that matches the request's scope. The task carries `{connector_id, target_id, stage}` triples, never a URL, namespace, credential or command.
4. Fencing: every claim mints a new `attempt_id`. A result is accepted only for the current attempt, while the lease is live, before the deadline.
5. Evidence: append-only `observation_evidence`, enforced by the same trigger pattern as `audit_events`.
6. Linkage: the agent reports the provider version from `PutValue` in an optional `result` field on job completion (section 11).
7. Coexistence: `environments.observation_source` decides whether the worker poller or the Gateway observes a request.

## 2. What exists and how it is reused

| Existing piece | File | Reused how |
|---|---|---|
| Claim with `FOR UPDATE SKIP LOCKED`, lease column, inline re-entry of expired claims | `api/pkg/storage/jobs.go` `ClaimNext` | Same CTE shape. Adds a `gateway_id` predicate, an attempt id and a deadline filter. |
| Owner check on completion (`claimed_by = $4 AND status = 'claimed'`) | `jobs.go` `Complete` | Same idea, keyed on `attempt_id` plus lease expiry instead of the caller id. |
| Per-request observation row after `executed`, timeout column, terminal sweeper | `gitops_observations.go`, `services/gitops.go`, `worker/internal/sweepers/gitops_timeout.go` | Same lifecycle. `GatewayObservationService.Start` is a sibling of `GitOpsService.Start`, called from the same hook. |
| One-time hashed enrollment token, guard `consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $2`, consume and create in one transaction | `agent_enrollment_tokens.go` `ConsumeAndCreateAgent` | Copied for `gateway_enrollment_tokens`, with "set `secret_hash` on the pre-created row" in place of "create". |
| SHA-256 credential hash, constant-time compare, 60s Redis hash cache, revoke check and cache delete, rolled-up `agent.auth.rejected` | `services/agents.go` `Authenticate` | Same for `GatewayService.Authenticate`. |
| `X-Agent-Secret` middleware on `/agents/:id`, generic 401 | `middleware/agentauth.go` | `GatewayAuth` with `X-Gateway-Secret` on `/gateways/:id`. |
| Session-exempt machine prefix, admin routes kept off it | `cmd/api/main.go` (`RequireAuthedExcept(publicV1Paths, "/api/v1/agents/")`, `/admin/agents`) | Add `/api/v1/gateways/` to the exempt list. Admin routes under `/api/v1/admin/gateways`. |
| Rate limiter placed after `AgentAuth`, keyed on the authenticated agent | `cmd/api/main.go` agent group, `middleware/ratelimit.go` | Same placement after `GatewayAuth`, keyed on the authenticated Gateway id (section 4.1). |
| Append-only trigger | `0001_initial_schema.up.sql` `audit_events_reject_mutations` | Same trigger on `observation_evidence`. |
| Exactly-one-of scope CHECK | `0012` `gitops_app_mappings_one_scope` | Same CHECK on `gateway_connector_bindings`. |
| Raw-SQL sweepers with `UPDATE ... RETURNING`, per-row audit, one notification per run | `worker/internal/sweepers/{jobs_recovery.go,agents_stale.go}` | New sweepers in the same style. |
| Seed role migrations | `0015`, `0034` | Same style for the new permissions. |

### 2.1 What must not be copied as is

- `SyncJobs.ClaimNext` has no scope predicate: `WHERE status = 'queued' OR (status = 'claimed' AND claim_expires_at < now())`. For the Gateway the scope predicate is the main security property, so `gateway_id = $1` is mandatory and ownership is checked again at result time.
- `SyncJobs.Complete` fences on `claimed_by = agentID` and does not check lease expiry. Gateway replicas share one identity, so caller-id fencing would let replica A's late result land on replica B's attempt. The Gateway uses a per-claim `attempt_id` and rejects results after `lease_expires_at`.
- `SyncJobs.Complete` returns success for any second call on a terminal row, whatever the body. The Gateway stores a digest and returns 409 for a different body.

## 3. Schema

Latest migration on `main` is `0040_logo_object_keys`. Proposed order, each with a `.down.sql`:

| Order | Name | Content |
|---|---|---|
| 1 | `gateway_registry` | `gateways`, `gateway_enrollment_tokens`, `gateway_replicas`, `gateway_connectors`, `gateway_connector_bindings` |
| 2 | `observation_tasks` | `observation_tasks`, `observation_task_attempts`, `observation_evidence` and the append-only trigger |
| 3 | `sync_jobs_result` | nullable `sync_jobs.result JSONB` |
| 4 | `environments_observation_source` | `environments.observation_source` |
| 5 | `seed_gateway_permissions` | new permissions on the seeded `admin` role |

Numbers are assigned when the PRs land.

### 3.1 `gateways`

```sql
CREATE TABLE gateways (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),  -- e.g. tenant-a-uat-gw
    -- The security boundary this Gateway speaks for: a label chosen by the
    -- admin (e.g. "tenant-a-uat"), used for display. Not a hostname.
    boundary             TEXT NOT NULL CHECK (length(boundary) BETWEEN 1 AND 128),
    -- When set, every binding for this Gateway must be in this environment.
    environment_id       UUID REFERENCES environments(id) ON DELETE RESTRICT,
    secret_hash          BYTEA,                          -- SHA-256 of the credential; NULL until enrolled
    status               TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','active','stale','disabled','revoked')),
    gateway_version      TEXT,
    contract_versions    JSONB NOT NULL DEFAULT '[]',
    max_inflight_tasks   INTEGER NOT NULL DEFAULT 20 CHECK (max_inflight_tasks BETWEEN 1 AND 1000),
    max_replicas         INTEGER NOT NULL DEFAULT 200 CHECK (max_replicas BETWEEN 1 AND 1000),
    last_seen_at         TIMESTAMPTZ,
    -- Enum set from heartbeat facts; never free text from the Gateway.
    last_status          TEXT CHECK (last_status IN ('ok','degraded','not_ready','over_privileged','shutting_down')),
    -- Written by the CP only (for example "connector eso-main missing from catalog").
    last_error           TEXT,
    disabled_at          TIMESTAMPTZ,
    revoked_at           TIMESTAMPTZ,
    revoked_by           TEXT,
    created_by           TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX gateways_status_idx    ON gateways (status);
CREATE INDEX gateways_last_seen_idx ON gateways (last_seen_at);
CREATE TRIGGER gateways_touch_updated_at BEFORE UPDATE ON gateways
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
```

There is no tenant entity in the CP schema (no `tenants` table and no `tenant_id` column under `api/pkg/storage/migrations/`; `environments` belongs to `projects`). Scope is `boundary` plus the optional `environment_id`, and bindings carry their own `environment_id` (section 3.5).

### 3.2 `gateway_enrollment_tokens`

Why not reuse `agent_enrollment_tokens`: in 0038 it has `provider_connection_id UUID NOT NULL` and `consumed_by_agent_id UUID REFERENCES agents(id)`. A Gateway has no provider connection and is not an agent. Reusing the table would make a certified column nullable and add a polymorphic consumer. A separate table with the same guard is less risky; Go code can share the hashing helper and the guard string.

```sql
CREATE TABLE gateway_enrollment_tokens (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id             UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    token_hash             BYTEA NOT NULL UNIQUE,
    expected_cluster_name  TEXT,                    -- optional, like agent tokens
    expires_at             TIMESTAMPTZ NOT NULL,
    consumed_at            TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ,
    revoked_by             TEXT,
    created_by             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT gateway_enrollment_tokens_expiry_after_creation CHECK (expires_at > created_at)
);
```

Flow: the admin creates the `gateways` row (name, boundary, optional environment) with `secret_hash NULL`, then mints a token for it. Enrollment burns the token and runs `UPDATE gateways SET secret_hash = $hash, status = 'active' WHERE id = $gw AND secret_hash IS NULL AND status = 'pending'` in the same transaction. Zero rows updated means the Gateway was already enrolled or revoked, and the transaction rolls back. Re-enrollment after a leak is: revoke the Gateway, create a new one. TTL bounds copy `agent_enrollment.go` (default 15m, min 1m, max 24h).

### 3.3 `gateway_replicas`

```sql
CREATE TABLE gateway_replicas (
    gateway_id      UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    replica_id      UUID NOT NULL,            -- random UUIDv4 per Gateway process
    gateway_version TEXT,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (gateway_id, replica_id)
);
```

Upserted on heartbeat only. A heartbeat from a new `replica_id` when the Gateway already has `max_replicas` rows seen within the retention window is refused with 429 `replica_limit` and audited, which also flags a stolen secret used in parallel. A sweeper prunes old rows.

### 3.4 `gateway_connectors` and advertised targets

The Gateway's Helm values define connectors (name, kind, local endpoint and credential path) and targets (target id, namespace, object name). The Gateway advertises them through E3. The CP records them; an admin approves each connector.

```sql
CREATE TABLE gateway_connectors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id          UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    name                TEXT NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),  -- connector_id on the wire
    kind                TEXT NOT NULL CHECK (kind IN ('eso','rollout','argocd')),
    -- [{target_id, namespace, name, refresh_interval_seconds?, progress_deadline_seconds?, stale}]
    advertised_targets  JSONB NOT NULL DEFAULT '[]',
    status              TEXT NOT NULL DEFAULT 'advertised'
        CHECK (status IN ('advertised','approved','disabled','missing')),
    approved_by         TEXT,
    approved_at         TIMESTAMPTZ,
    last_advertised_at  TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (gateway_id, name)
);
```

On the wire, `connector_id` is `gateway_connectors.name`, not the UUID primary key. A connector that disappears from the catalog moves to `missing`; no new tasks use it and open tasks are cancelled with verdict `unverified`, reason `connector_missing`. A target that disappears is marked `stale` in `advertised_targets`; bindings to it stay but no tasks are issued against it.

`namespace` and `name` in the catalog are for admin display (ADR open question 2). If the owner decides against sending them, the catalog carries ids only and the evidence `resource` object must drop them too.

### 3.5 `gateway_connector_bindings`

The only path from a request to a task. Admin-created. It names a Secrets Bridge secret scope on one side and up to three `(connector, target)` pairs on the other.

```sql
CREATE TABLE gateway_connector_bindings (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id             UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    environment_id         UUID NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    -- Secret scope, exactly one form (like gitops_app_mappings_one_scope):
    --   patch requests resolve to a catalog row (secrets.id) through the
    --   lookup boundProviderConfig uses in requests_binding.go;
    --   cross_team requests carry destination_provider_connection_id and
    --   destination_secret_ref on access_requests.
    secret_id              UUID REFERENCES secrets(id) ON DELETE CASCADE,
    provider_connection_id UUID REFERENCES provider_connections(id) ON DELETE CASCADE,
    secret_ref             TEXT,
    expected_stages        JSONB NOT NULL DEFAULT '["eso_sync","workload_rollout"]',
    eso_connector_id       UUID NOT NULL REFERENCES gateway_connectors(id) ON DELETE RESTRICT,
    eso_target_id          TEXT NOT NULL,
    rollout_connector_id   UUID REFERENCES gateway_connectors(id) ON DELETE RESTRICT,
    rollout_target_id      TEXT,
    argocd_connector_id    UUID REFERENCES gateway_connectors(id) ON DELETE RESTRICT,
    argocd_target_id       TEXT,
    observation_timeout_s  INTEGER NOT NULL DEFAULT 1800 CHECK (observation_timeout_s BETWEEN 60 AND 86400),
    enabled                BOOLEAN NOT NULL DEFAULT TRUE,
    created_by             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at             TIMESTAMPTZ,
    CONSTRAINT gateway_connector_bindings_one_scope CHECK (
        (secret_id IS NOT NULL AND provider_connection_id IS NULL AND secret_ref IS NULL) OR
        (secret_id IS NULL AND provider_connection_id IS NOT NULL AND secret_ref IS NOT NULL)
    ),
    CONSTRAINT gateway_connector_bindings_rollout_pair CHECK ((rollout_connector_id IS NULL) = (rollout_target_id IS NULL)),
    CONSTRAINT gateway_connector_bindings_argocd_pair  CHECK ((argocd_connector_id IS NULL) = (argocd_target_id IS NULL))
);
CREATE INDEX gateway_connector_bindings_secret_idx ON gateway_connector_bindings (secret_id, environment_id) WHERE deleted_at IS NULL;
CREATE INDEX gateway_connector_bindings_conn_idx   ON gateway_connector_bindings (provider_connection_id, secret_ref, environment_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX gateway_connector_bindings_one_per_target
    ON gateway_connector_bindings (gateway_id, eso_connector_id, eso_target_id, COALESCE(secret_id::text, provider_connection_id::text || ':' || secret_ref))
    WHERE deleted_at IS NULL;
```

Service checks at bind time (foreign keys cannot express "same Gateway", so these stay in the service with tests):

- Each referenced connector belongs to the binding's `gateway_id`, has `status = 'approved'`, and has the matching kind (`eso`, `rollout`, `argocd`).
- Each target id is in that connector's `advertised_targets` and not stale.
- `expected_stages` lists `workload_rollout` only when a rollout pair is set; `argocd_context` is never required and is added to the task when an ArgoCD pair is set.
- If `gateways.environment_id` is set, it equals the binding's `environment_id`.
- Duplicates within one Gateway are refused by the unique index. Across Gateways the CP cannot tell two clusters from one, because connector ids are local to each Gateway. When the catalog carries namespace and name, the CP warns (does not refuse) if another Gateway already has an enabled binding for the same secret scope, environment, namespace and name; the request rollup (ADR 2.4) then keeps the two verdicts apart.
- Deadline hint: if the ESO target advertises `refresh_interval_seconds` of 0 or longer than the computed deadline cap, the bind form warns that `eso_sync` will be `unverifiable` under default settings.

Open: patch requests resolve to `secrets.id` through `project_secrets`; whether they also resolve to a `provider_connection_id` (for `expected_change.secret_ref.provider_connection_id`) needs checking against `boundProviderConfig`. The task schema makes that field optional.

### 3.6 `observation_tasks`

One row per (request, binding). `state` is the delivery lifecycle, `verdict` is what the evidence supports.

```sql
CREATE TABLE observation_tasks (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id             UUID NOT NULL REFERENCES access_requests(id) ON DELETE RESTRICT,
    correlation_id         UUID NOT NULL,          -- sync_jobs.correlation_id of the completing job
    job_id                 UUID REFERENCES sync_jobs(id) ON DELETE SET NULL,
    gateway_id             UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    binding_id             UUID NOT NULL REFERENCES gateway_connector_bindings(id) ON DELETE RESTRICT,
    -- Snapshot from the binding at creation, so a later edit cannot retarget an open task.
    connector_refs         JSONB NOT NULL,         -- [{connector_id, target_id, stage}]
    expected_stages        JSONB NOT NULL,
    -- Secret reference, for supersede and later-write checks.
    provider_type          TEXT NOT NULL,
    secret_scope_key       TEXT NOT NULL,          -- secrets.id, or provider_connection_id:secret_ref
    secret_ref             TEXT NOT NULL,
    provider_connection_id UUID,
    -- Change marker. Never a value or a hash of one.
    provider_version_id    TEXT,                   -- AWS SM VersionId or Vault KV version; NULL if not reported
    provider_version_at    TIMESTAMPTZ,            -- agent or provider clock
    version_source         TEXT NOT NULL CHECK (version_source IN ('agent_reported','none')),
    executed_at            TIMESTAMPTZ NOT NULL,   -- CP clock
    schema_version         TEXT NOT NULL DEFAULT 'gateway.observation-task/v1',

    state                  TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued','leased','done','dead','cancelled')),
    verdict                TEXT NOT NULL DEFAULT 'pending'
        CHECK (verdict IN ('pending','verified','partially_observed','unverified','timed_out')),
    verdict_reason         TEXT,                   -- enum, see section 5.4
    stages                 JSONB NOT NULL DEFAULT '{}',   -- latest CP outcome per stage
    rollout_baseline       JSONB,                  -- {deployment_revision, observed_at}

    current_attempt_id     UUID,
    attempt_count          INTEGER NOT NULL DEFAULT 0,
    failure_count          INTEGER NOT NULL DEFAULT 0,   -- Gateway-reported error stages only
    max_failures           INTEGER NOT NULL DEFAULT 5,
    leased_replica_id      UUID,
    leased_at              TIMESTAMPTZ,
    lease_expires_at       TIMESTAMPTZ,
    not_before             TIMESTAMPTZ NOT NULL DEFAULT now(),
    deadline_at            TIMESTAMPTZ NOT NULL,
    last_result_at         TIMESTAMPTZ,

    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    terminal_at            TIMESTAMPTZ,
    UNIQUE (request_id, binding_id),
    CONSTRAINT observation_tasks_lease_consistent CHECK (
        (state = 'leased') = (current_attempt_id IS NOT NULL AND lease_expires_at IS NOT NULL)
    )
);
CREATE INDEX observation_tasks_claim_idx
    ON observation_tasks (gateway_id, not_before, created_at)
    WHERE state IN ('queued','leased');
CREATE INDEX observation_tasks_lease_idx    ON observation_tasks (lease_expires_at) WHERE state = 'leased';
CREATE INDEX observation_tasks_deadline_idx ON observation_tasks (deadline_at) WHERE state IN ('queued','leased');
CREATE INDEX observation_tasks_request_idx  ON observation_tasks (request_id);
CREATE INDEX observation_tasks_open_scope_idx ON observation_tasks (secret_scope_key) WHERE state IN ('queued','leased');
```

`observation_tasks_claim_idx` is the only claim index. Its predicate uses no time function (Postgres rejects `now()` in an index predicate); the lease and `not_before` checks stay in the query.

`UNIQUE (request_id, binding_id)` makes task creation idempotent if `OnJobCompleted` fires twice.

`correlation_id` is the `sync_jobs.correlation_id` of the job that completed the change. Existing GitOps audit rows use the request id as `CorrelationID` (`GitOpsService.Start`); `access_requests` has no correlation column.

`ON DELETE RESTRICT` on `request_id` differs from `gitops_observations` (which cascades). Evidence is append-only with a trigger that raises on DELETE, so a cascade would fail anyway.

### 3.7 `observation_task_attempts`

```sql
CREATE TABLE observation_task_attempts (
    attempt_id        UUID PRIMARY KEY,
    task_id           UUID NOT NULL REFERENCES observation_tasks(id) ON DELETE RESTRICT,
    attempt_count     INTEGER NOT NULL,
    gateway_id        UUID NOT NULL,
    replica_id        UUID NOT NULL,
    claimed_at        TIMESTAMPTZ NOT NULL,
    lease_expires_at  TIMESTAMPTZ NOT NULL,
    ended_at          TIMESTAMPTZ,
    outcome           TEXT CHECK (outcome IN ('result_accepted','result_rejected','lease_expired','released','deadline','cancelled')),
    result_sha256     BYTEA,                       -- digest of the accepted body (RFC 8785 canonical JSON)
    UNIQUE (task_id, attempt_count)
);
```

The replay check (section 4.8 step 3) reads `outcome = 'result_accepted'` and `result_sha256` here, before the current-attempt check, because accepting a result clears `observation_tasks.current_attempt_id`.

### 3.8 `observation_evidence` (append-only)

```sql
CREATE TABLE observation_evidence (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id            UUID NOT NULL REFERENCES observation_tasks(id) ON DELETE RESTRICT,
    attempt_id         UUID NOT NULL REFERENCES observation_task_attempts(attempt_id) ON DELETE RESTRICT,
    gateway_id         UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    replica_id         UUID NOT NULL,
    gateway_version    TEXT NOT NULL,
    schema_version     TEXT NOT NULL,
    stage              TEXT NOT NULL CHECK (stage IN ('eso_sync','workload_rollout','argocd_context')),
    connector_id       UUID NOT NULL REFERENCES gateway_connectors(id) ON DELETE RESTRICT,
    reported_outcome   TEXT NOT NULL CHECK (reported_outcome IN ('observed','not_observed','not_applicable','unverifiable','failed','error')),
    cp_outcome         TEXT NOT NULL CHECK (cp_outcome       IN ('observed','not_observed','not_applicable','unverifiable','failed','error')),
    linkage            TEXT NOT NULL CHECK (linkage IN ('version_pinned','time_ordered','none')),
    observed_at        TIMESTAMPTZ NOT NULL,                  -- Gateway clock
    received_at        TIMESTAMPTZ NOT NULL DEFAULT now(),    -- CP clock
    body               JSONB NOT NULL,                        -- the validated stage object
    body_sha256        BYTEA NOT NULL,                        -- digest of the whole EvidenceResult body
    UNIQUE (task_id, attempt_id, stage)
);
CREATE INDEX observation_evidence_task_idx ON observation_evidence (task_id, received_at);
CREATE TRIGGER observation_evidence_no_update BEFORE UPDATE ON observation_evidence
    FOR EACH ROW EXECUTE FUNCTION observation_evidence_reject_mutations();
CREATE TRIGGER observation_evidence_no_delete BEFORE DELETE ON observation_evidence
    FOR EACH ROW EXECUTE FUNCTION observation_evidence_reject_mutations();
```

`body_sha256` hashes metadata-only evidence, never a secret value; the schema has no field that could hold one. Retention follows the audit retention decision (ADR open question 8), not a delete path in the API.

### 3.9 `sync_jobs.result`

```sql
ALTER TABLE sync_jobs ADD COLUMN result JSONB;  -- nullable; metadata only
```

Holds `{"provider_version": {"id": "...", "created_at": "..."}}` for a succeeded patch job. Section 11 has the agent and handler change.

### 3.10 `environments.observation_source`

```sql
ALTER TABLE environments ADD COLUMN observation_source TEXT NOT NULL DEFAULT 'control_plane'
    CHECK (observation_source IN ('control_plane','gateway','none'));
```

Default keeps today's behaviour. Section 7.

## 4. Wire contract

All bodies are JSON with `Content-Type: application/json`. Error bodies are `{"error": "<code>"}` from a closed list. No error body echoes request content. Admin routes (create, bind, revoke, list, mint token) live under `/api/v1/admin/gateways` behind the session gate and are not part of this contract.

### 4.1 Common rules

- **Auth**: `X-Gateway-Secret: <gateway_secret>` on E2 to E7. SHA-256 at rest, constant-time compare, 60s hash cache deleted on revoke, the same as `AgentService.Authenticate`. Unknown Gateway and wrong secret are both a generic 401, with detail in the audit log (rolled up per id and reason so random ids cannot flood `audit_events`).
- **Existence**: a task that belongs to another Gateway returns 404, the same as one that does not exist.
- **Replica id**: every E2, E4, E5, E6 and E7 body carries `replica_id` (UUIDv4 generated at process start). It is recorded for audit and limits. It is not an authorization input and it is not the fence.
- **Rate limits**: applied after `GatewayAuth`, keyed on the authenticated Gateway id, on E2, E4, E5, E6 and E7. A pre-auth bucket keyed on the path id would let an unauthenticated caller burn a real Gateway's budget, which is why the agent heartbeat limiter in `cmd/api/main.go` sits after `AgentAuth`. The existing limiter fails open on Redis errors (`middleware/ratelimit.go`), so claim also has an in-process per-instance token bucket. 429 responses carry `Retry-After`.
- **Body limits**: E7 64 KiB (413 above), E2 and E3 64 KiB, others 4 KiB.
- **Versioning**: path `/api/v1`. `schema_version` constants `gateway.observation-task/v1` and `gateway.evidence-result/v1`. Both schemas are closed (`additionalProperties: false`), so adding an optional field is a new version. The Gateway sends `contract_versions` on heartbeat; the CP hands a task only to a Gateway that listed its version and otherwise answers E4 with 409 `contract_version_unsupported`.

### 4.2 E1 enroll

`POST /api/v1/gateways/enroll`, no `X-Gateway-Secret`. Called once by the operator outside the pod (`gateway enroll` subcommand or curl); the pod never enrolls.

```json
{ "enrollment_token": "<one-time token>", "cluster_name": "tenant-a-uat" }
```

`cluster_name` is optional and checked only when the token has `expected_cluster_name`.

- 201: `{"gateway_id": "<uuid>", "gateway_secret": "<returned once>", "heartbeat_interval_seconds": 30, "claim_poll_seconds": 5}`.
- 401 `enrollment_token_invalid` or `enrollment_token_expired`; 409 `enrollment_token_already_consumed` or `gateway_already_enrolled`; 403 `enrollment_token_revoked`; 400 `cluster_name_mismatch` or `invalid_request`; 503 `enrollment_not_configured`. These follow `api/internal/handlers/agent_enrollment.go`.
- No idempotency by design: the token is single use. A lost 201 means the admin revokes the Gateway and creates a new one.
- Scope comes from the pre-created `gateways` row, never from the body. Per-IP rate limit, like login.

### 4.3 E2 heartbeat

`POST /api/v1/gateways/{id}/heartbeat`

```json
{
  "replica_id": "7f3c9e2a-1b2c-4d5e-8f90-123456789abc",
  "gateway_version": "0.1.0",
  "contract_versions": ["1"],
  "status": "ok",
  "in_flight": 1,
  "catalog_version": "3f1c...",
  "connectors": [
    {"connector_id": "eso-main", "kind": "eso", "status": "ok"},
    {"connector_id": "argocd-main", "kind": "argocd", "status": "unreachable"}
  ]
}
```

`status` (replica) is one of `ok`, `degraded`, `not_ready`, `over_privileged`, `shutting_down`. Connector `status` is one of `ok`, `degraded`, `unreachable`, `unauthorized`, `over_privileged`. No URLs, messages or error text. `catalog_version` is an opaque digest of the last catalog the replica sent; a mismatch with the stored one triggers a catalog upload.

- 200: `{"status": "ok", "server_time": "<rfc3339>", "next_heartbeat_seconds": 30, "claim_poll_seconds": 5, "contract_version": "1", "catalog_version": "<stored digest>"}`.
- 400 invalid body; 401; 429 rate limited or `replica_limit`.
- Last write wins per `(gateway_id, replica_id)`. Updates `gateways.last_seen_at`, `last_status`, `gateway_version`, `contract_versions` and upserts `gateway_replicas`. A replica that reports `shutting_down` has its releases and lease expiries excluded from any failure accounting (none count anyway, see section 5.3).

### 4.4 E3 catalog

`PUT /api/v1/gateways/{id}/catalog`. Full replace, idempotent.

```json
{
  "connectors": [
    {
      "connector_id": "eso-main",
      "kind": "eso",
      "targets": [
        {"target_id": "payments-api", "namespace": "payments", "name": "payments-env", "refresh_interval_seconds": 60}
      ]
    },
    {
      "connector_id": "rollout-main",
      "kind": "rollout",
      "targets": [
        {"target_id": "payments-api", "namespace": "payments", "name": "api", "progress_deadline_seconds": 600}
      ]
    },
    {
      "connector_id": "argocd-main",
      "kind": "argocd",
      "targets": [{"target_id": "payments-api", "namespace": "argocd", "name": "payments-api"}]
    }
  ]
}
```

- 200 `{"accepted": n, "targets_stale": m, "catalog_version": "<digest>"}`.
- Ids use the DNS-label pattern. `namespace` and `name` use Kubernetes name patterns and are display-only (ADR open question 2). Intervals are integers.
- Advertising never creates or approves anything. New connectors appear as `advertised`; an admin approves them and creates bindings.

### 4.5 E4 claim

`POST /api/v1/gateways/{id}/tasks/claim`

```json
{ "replica_id": "7f3c9e2a-1b2c-4d5e-8f90-123456789abc", "max_tasks": 1 }
```

v1 accepts only `max_tasks: 1`.

- 200: one ObservationTask (`schemas/observation-task.schema.json`).
- 204 with `Retry-After`: nothing claimable. `Retry-After` grows with consecutive empty polls up to 30s.
- 401; 409 `contract_version_unsupported`; 429 rate limited, replica at its in-flight limit (default 1), or Gateway at `max_inflight_tasks`.

Example 200 body:

```json
{
  "schema_version": "gateway.observation-task/v1",
  "task_id": "0b6f2a4e-3c1d-4e5f-8a9b-0c1d2e3f4a5b",
  "attempt_id": "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
  "attempt_count": 2,
  "lease_expires_at": "2026-10-18T10:00:30Z",
  "deadline_at": "2026-10-18T10:30:00Z",
  "request_id": "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d",
  "correlation_id": "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b",
  "skew_margin_seconds": 5,
  "gateway_scope": {"gateway_id": "1f2e3d4c-5b6a-4978-8695-a4b3c2d1e0f9"},
  "connector_refs": [
    {"connector_id": "eso-main", "target_id": "payments-api", "stage": "eso_sync"},
    {"connector_id": "rollout-main", "target_id": "payments-api", "stage": "workload_rollout"},
    {"connector_id": "argocd-main", "target_id": "payments-api", "stage": "argocd_context"}
  ],
  "expected_change": {
    "provider_type": "aws-sm",
    "secret_ref": {"name": "team-alpha/uat/db"},
    "provider_version_id": "a1b2c3d4-0000-4000-8000-000000000001",
    "provider_version_at": "2026-10-18T09:58:02Z",
    "version_source": "agent_reported",
    "executed_at": "2026-10-18T09:58:03Z"
  },
  "rollout_baseline": null
}
```

`expected_change.secret_ref.name` is the provider path. The ESO connector needs it to compute `remote_ref_match`; it is compared, never dialled, and the pattern refuses `://`. `provider_version_id` is not secret but identifies a change to a specific secret, so it goes only to the Gateway bound to the request.

Claim query:

```sql
WITH inflight AS (
    SELECT count(*) AS n FROM observation_tasks
    WHERE gateway_id = $1 AND state = 'leased' AND lease_expires_at > now()
),
replica_inflight AS (
    SELECT count(*) AS n FROM observation_tasks
    WHERE gateway_id = $1 AND state = 'leased' AND lease_expires_at > now() AND leased_replica_id = $2
),
picked AS (
    SELECT t.id
    FROM observation_tasks t
    WHERE t.gateway_id = $1                               -- authenticated id, never a body field
      AND t.state IN ('queued','leased')
      AND (t.state = 'queued' OR t.lease_expires_at < now())
      AND t.not_before <= now()
      AND t.deadline_at > now()
      AND (SELECT n FROM inflight) < (SELECT max_inflight_tasks FROM gateways WHERE id = $1)
      AND (SELECT n FROM replica_inflight) < $4           -- per-replica limit, default 1
    ORDER BY t.not_before, t.created_at
    LIMIT 1
    FOR UPDATE OF t SKIP LOCKED
)
UPDATE observation_tasks t
SET state              = 'leased',
    current_attempt_id = gen_random_uuid(),
    attempt_count      = t.attempt_count + 1,
    leased_replica_id  = $2,
    leased_at          = now(),
    lease_expires_at   = LEAST(now() + $3::interval, t.deadline_at)
FROM picked
WHERE t.id = picked.id
RETURNING t.*;
```

In the same transaction, insert one `observation_task_attempts` row and, for a re-claimed expired lease, close the previous attempt with `outcome = 'lease_expired'`. Lease expiry does not change `failure_count`.

The in-flight counts are a soft cap: two concurrent claims can read the same count, so the overshoot is bounded by the number of concurrent claim calls. If a hard cap is wanted, take `SELECT ... FROM gateways WHERE id = $1 FOR UPDATE` first, which serialises claims per Gateway.

Load: 100 replicas with jitter and idle backoff to 30s is a few to about 20 index range scans per second on `observation_tasks_claim_idx` for one Gateway.

### 4.6 E5 renew lease

`POST /api/v1/gateways/{id}/tasks/{task_id}/lease`, body `{"replica_id": "...", "attempt_id": "..."}`.

- 200 `{"lease_expires_at": "<rfc3339>"}`, set to `LEAST(now() + lease, deadline_at)`, only when `current_attempt_id` matches and the lease is still live.
- 409 `attempt_superseded`, 409 `lease_expired`, 409 `task_closed`, 404.
- Renewing twice just moves the expiry.

### 4.7 E6 release

`POST /api/v1/gateways/{id}/tasks/{task_id}/release`, body `{"replica_id": "...", "attempt_id": "...", "reason": "shutdown"}`. `reason` is one of `shutdown`, `over_capacity`, `connector_unavailable`.

- 204. The task goes back to `queued` with `not_before = now()`, the attempt closes with `outcome = 'released'`. `failure_count` is not changed.
- 409 `attempt_superseded`; 404.
- A second release of the same attempt returns 204 if the task has not been re-claimed, 409 after.

### 4.8 E7 result

`POST /api/v1/gateways/{id}/tasks/{task_id}/result`. Body: one EvidenceResult (`schemas/evidence-result.schema.json`).

| Status | Code | When |
|---|---|---|
| 200 | `accepted` | Stored. `{"status": "accepted", "task_state": "<state>", "verdict": "<verdict>", "next": "none" or "rescheduled"}` |
| 200 | `duplicate` | Same `(task_id, attempt_id)` already accepted with the same digest; returns the stored response |
| 400 | `invalid_request` | Not JSON, or path and body ids differ |
| 401 | | Auth |
| 404 | | Unknown task, or another Gateway's task |
| 409 | `result_conflict` | Same `(task_id, attempt_id)` already accepted with a different digest |
| 409 | `attempt_superseded` | `attempt_id` is not the current attempt and was never accepted |
| 409 | `lease_expired` | Current attempt, but `lease_expires_at` has passed, whether or not anyone re-claimed |
| 409 | `task_closed` | Task terminal, or `deadline_at` passed (the task is moved to `timed_out` in the same transaction if still open) |
| 413 | | Body over 64 KiB |
| 422 | `schema_violation` | Fails the schema, unsupported `schema_version`, a stage not in the task, more than one entry per stage, or a `source` connector or target not in the claimed task |
| 422 | `evidence_out_of_window` | An `observed_at` outside `[started_at - skew, finished_at + skew]`, `finished_at` after `server_time + skew`, or a `started_at` before the attempt's `claimed_at - skew` |

Checks run in this order inside one transaction that starts with `SELECT ... FROM observation_tasks WHERE id = $task FOR UPDATE`:

1. Identity: `GatewayAuth` passed and the Gateway is not `revoked` or `disabled`.
2. Ownership: `task.gateway_id = authenticated id`, else 404 (audit reason `foreign_task`).
3. Replay: look up `observation_task_attempts` for `(task_id, attempt_id)` with `outcome = 'result_accepted'`. Same `result_sha256` gives 200 `duplicate`; different gives 409 `result_conflict`.
4. Current attempt: `body.attempt_id = task.current_attempt_id AND task.state = 'leased'`, else 409 `attempt_superseded` (audit distinguishes `stale_attempt` from `unknown_attempt`).
5. Lease: `task.lease_expires_at > now()`, else 409 `lease_expired`.
6. Deadline: `now() < task.deadline_at`, else 409 `task_closed`.
7. Schema: strict decode with unknown fields refused, schema validation, stage set within `task.expected_stages` plus `argocd_context` when bound. 422 leaves the attempt leased so a fixed body can be resubmitted within the lease.
8. Scope: each `source.connector_id` and `source.target_id` equals the pair the task snapshot names for that stage; the connector is still `approved`; `resource.kind` matches the connector kind (`eso` gives `ExternalSecret`, `rollout` gives `Deployment`, `argocd` gives `Application`). 422 `schema_violation`, audited as denied.
9. Time window: as in the table, with skew from section 5.2.

When all pass: recompute each stage outcome from `facts` (ADR 2.3), insert `observation_evidence` rows, close the attempt with `result_accepted` and the digest, update `task.stages`, update `rollout_baseline` if this is the first pass with `eso_sync` observed, compute the verdict (ADR 2.4), set `state` to `done` or back to `queued` with backoff, clear `current_attempt_id`, commit. Audit after commit, best effort, as in the rest of the API.

The digest is SHA-256 over the RFC 8785 canonical JSON of the whole body. Delivery is at least once; the idempotency key and the attempt fence make a duplicate harmless. There is no separate ack, so "persist before ack" holds by construction.

## 5. Evaluation in the CP

### 5.1 Re-poll instead of holding a task

One claim is one observation pass. If every expected stage is terminal, the CP computes the verdict and sets `state = 'done'`. Otherwise it sets `state = 'queued'`, clears the lease and sets `not_before = now() + backoff` (15s, 30s, 60s, capped at 120s). This is the loop the worker poller runs today with `RecordPoll` and `Transition` on `gitops_observations`, moved to a claim and result pair.

### 5.2 Skew

`skew = skew_margin + |clock.cp_offset_ms| + |clock.apiserver_offset_ms|`, with `skew_margin` default 5s. "After T plus skew" means strictly greater than `executed_at + skew` rounded up to the next whole second. When the offsets are larger than a configured bound (default 30s), the stage gets caveat `clock_skew_suspected` and cannot be `observed`.

### 5.3 Failure accounting

`failure_count` increments only when an accepted result has a stage with `error`. Lease expiries, releases and claims do not change it, so rolling restarts and replica deaths cannot kill a healthy task; the deadline bounds the churn. At `max_failures` the task goes `dead`, verdict `unverified`, reason `gateway_errors`.

### 5.4 Verdict reasons

`verdict_reason` is an enum: `no_provider_version`, `volume_refresh_not_observable`, `subpath_mount_not_refreshed`, `reload_mechanism_unknown`, `refresh_interval_exceeds_deadline`, `failure_observed`, `no_stage_observed`, `superseded_by_later_write`, `source_changed`, `connector_missing`, `gateway_errors`, `gateway_over_privileged`, `gateway_unavailable`, `deadline_reached`. `gateway_over_privileged` is set when the Gateway heartbeat reports `over_privileged` (fail-open self-check mode); it caps the task below `verified`. `gateway_unavailable` is set on `timed_out` when the Gateway was `stale` for the whole window.

### 5.5 Later writes and request rollup

When a task is created, the CP looks up open tasks with the same `secret_scope_key` (index `observation_tasks_open_scope_idx`) and cancels them (`state = cancelled`, verdict `unverified`, reason `superseded_by_later_write`, audit `observation.task.superseded`). The request page computes the request rollup from its tasks as defined in ADR 2.4.

## 6. Task creation when a request reaches `executed`

Call site: `RequestService.OnJobCompleted` in `api/internal/services/requests.go`. After a successful transition to `executed` it currently calls `s.gitops.Start(ctx, req)`. Proposed: a second optional starter, wired by `WithGatewayObservation(...)` like `WithGitOps`:

```go
type ObservationStarter interface {
    Start(ctx context.Context, request *storage.AccessRequest, job *storage.SyncJob) error
}
```

The job is passed because it carries `Result.ProviderVersion` and the correlation id. `GitOpsStarter.Start` keeps its signature.

`GatewayObservationService.Start`:

1. Return if `SB_GATEWAY_ENABLED` is off.
2. Only `patch` and `cross_team` requests.
3. Load the environment. If `observation_source != 'gateway'`, audit `request.observation_skipped` reason `source_control_plane` and return.
4. Resolve the scope: for `patch`, the catalog row through the lookup `boundProviderConfig` uses in `requests_binding.go` (refactor it to return the selected secret id too); for `cross_team`, `DestinationProviderConnectionID` and `DestinationSecretRef`.
5. Find enabled bindings for that scope and environment whose Gateway is not revoked or disabled and whose connectors are approved.
6. None: audit `request.observation_skipped` reason `no_gateway_binding`. The request page shows "no observation configured".
7. For each binding: cancel superseded open tasks (section 5.5), then `INSERT ... ON CONFLICT (request_id, binding_id) DO NOTHING` with the snapshot fields, `deadline_at` from ADR 2.5, `executed_at = now()`, `not_before = now() + 10s`.
8. Audit `observation.task.created` per row (task id, gateway id, binding id, `version_source`).

Failures are audited and not bubbled, like `GitOpsService.Start`.

`OnJobCompleted` runs after the job completion commit, not in the same transaction. A reconcile sweeper (section 8) creates missing tasks for recently executed requests in `gateway` environments.

## 7. Coexistence with the worker ArgoCD poller

One source per environment, from `environments.observation_source`:

- `control_plane` (default): `GitOpsService.Start` runs as today; `GatewayObservationService.Start` skips.
- `gateway`: `GitOpsService.Start` skips (audit `request.gitops_observation_skipped` reason `source_gateway`); the Gateway path runs.
- `none`: both skip.

Both starters read the column at the same moment, so one request never gets both. A change applies to requests executed after it; open `gitops_observations` rows finish on the poller. Switching back to `control_plane` cancels open Gateway tasks in that environment with reason `source_changed`. The UI renders whichever rows exist and never sums them. Shadow mode is post-MVP.

## 8. Worker sweepers

All in `worker/internal/sweepers/`, raw SQL, `UPDATE ... RETURNING`, one audit row per change, one notification per run with counts. Each update guards on the current state so a race with the result path is a no-op.

| Sweeper | Query sketch | Audit |
|---|---|---|
| `observation-lease-expiry` | `UPDATE observation_tasks SET state='queued', current_attempt_id=NULL, lease_expires_at=NULL, leased_replica_id=NULL, not_before=now() WHERE state='leased' AND lease_expires_at < $now RETURNING ...`; close the attempt with `lease_expired`. Not needed for correctness (claim re-enters expired leases). No `failure_count` change. | `observation.task.lease_expired` (first per task, then counted in metrics) |
| `observation-deadline` | `UPDATE observation_tasks SET state='done', verdict='timed_out', verdict_reason=..., terminal_at=$now, current_attempt_id=NULL, lease_expires_at=NULL WHERE state IN ('queued','leased') AND deadline_at < $now RETURNING ...` | `observation.task.timed_out` |
| `observation-dead` | open tasks with `failure_count >= max_failures` to `state='dead'`, `verdict='unverified'`, `verdict_reason='gateway_errors'` | `observation.task.dead` |
| `gateways-stale` | `UPDATE gateways SET status='stale' WHERE status='active' AND last_seen_at < $cutoff RETURNING id`, as `agents_stale.go`; reversed by the next heartbeat | `gateway.stale` |
| `gateway-replicas-prune` | `DELETE FROM gateway_replicas WHERE last_seen_at < $retention` | none |
| `observation-intent-reconcile` | executed `patch` and `cross_team` requests in `gateway` environments within the last N hours, with a matching enabled binding and no task: create it | `observation.task.created` with `source: reconcile` |

Revocation is not a sweeper. `POST /admin/gateways/:id/revoke` sets `status = 'revoked'`, deletes the auth cache entry, and in the same transaction moves the Gateway's `leased` tasks to `queued` with no attempt (closing those attempts as `cancelled`). Those tasks then time out, or are picked up by another Gateway if the admin rebinds.

## 9. Permissions

Added to `api/internal/auth/permissions.go` and `Catalog`, mirroring the Agents group:

| Permission | Gates |
|---|---|
| `gateway.mint` | Create a Gateway record, mint and revoke enrollment tokens. Mirrors `agent.mint`. |
| `gateway.revoke` | Revoke or disable a Gateway. Mirrors `agent.revoke`. |
| `gateway.list` | List Gateways, replicas, connectors, tasks and status. Mirrors `agent.list`. |
| `gateway.bind` | Approve connectors; create, edit and delete bindings; set `environments.observation_source`. Its catalog description states that it does not imply `integration.bind`, and `integration.bind` does not imply it. |

Viewing evidence on a request reuses the request page's access check (the same gate as `GET /requests/:id/gitops`). The seed migration adds the four permissions to the seeded `admin` role only. The drift test in `permissions.go` catches a missing constant.

## 10. Routes and audit

Machine routes (session-exempt prefix `/api/v1/gateways/`, `GatewayAuth` on the `:id` group, rate limited after auth): E1 to E7 in section 4. E1 is registered before the `:id` group.

Admin routes (session-gated):

| Route | Permission |
|---|---|
| `POST /admin/gateways`, `POST /admin/gateways/:id/enrollment-token`, `POST /admin/gateway-enrollment-tokens/:id/revoke` | `gateway.mint` |
| `POST /admin/gateways/:id/revoke`, `PUT /admin/gateways/:id/enabled` | `gateway.revoke` |
| `GET /admin/gateways`, `GET /admin/gateways/:id`, `GET /admin/gateways/:id/tasks` | `gateway.list` |
| `POST /admin/gateways/:id/connectors/:cid/approve`, `POST/GET/DELETE /admin/gateway-bindings`, `PUT /admin/environments/:id/observation-source` | `gateway.bind` |
| `GET /requests/:id/observations` | request page access |

Audit events (metadata only; actor `gateway:<id>` for machine calls, `system:gateway-observation` for the starter, the session actor for admin calls, the sweeper name for sweeps; correlation id is the task's `correlation_id` where a task is involved):

| Action | When |
|---|---|
| `gateway.create`, `gateway.enrollment_token.create`, `gateway.enrollment_token.revoke` | admin |
| `gateway.enroll` (success, or failure with reason invalid, expired, consumed, revoked, already_enrolled) | E1 |
| `gateway.auth.rejected` | rolled up per (id, reason) |
| `gateway.revoke`, `gateway.disable`, `gateway.stale`, `gateway.replica_limit` | admin, sweeper, E2 |
| `gateway.catalog.updated`, `gateway.connector.approved`, `gateway.connector.missing` | E3, admin |
| `gateway.binding.create`, `gateway.binding.delete`, `environment.observation_source.update` | admin |
| `request.observation_skipped` (reason) | starter |
| `observation.task.created`, `observation.task.superseded`, `observation.task.cancelled` | starter, reconcile, admin |
| `observation.task.claimed` | first claim per task; later claims counted in metrics |
| `observation.evidence.accepted` (stages, outcomes, linkage) | E7 |
| `observation.evidence.rejected` (reason: foreign_task, stale_attempt, unknown_attempt, lease_expired, task_closed, result_conflict, schema_violation, scope, evidence_out_of_window) | E7 |
| `gateway.evidence.outcome_mismatch` | E7, when the CP outcome differs from the reported one |
| `observation.task.lease_expired`, `observation.task.timed_out`, `observation.task.dead` | sweepers |
| `observation.task.verdict` (verdict, reason) | when the verdict leaves `pending` |

## 11. Agent change: report the provider version

What exists:

- `core/providers/provider.go`: `PutValue(...) (SecretVersion, error)` with `SecretVersion{ID string; CreatedAt time.Time}`.
- `core/providers/awssecretsmanager`: `ID` from `PutSecretValueOutput.VersionId` or `CreateSecretOutput.VersionId`; `CreatedAt` is `time.Now().UTC()` on the agent.
- `core/providers/vault`: `versionFromWrite` sets `ID` with `fmt.Sprintf("%v", v)` from `data.version` and `CreatedAt` from `created_time`. KV v1 writes return no version, so `ID` is `""`.
- `agent/internal/executor/patch.go`: `if _, err := provider.PutValue(...)` discards the version.
- `agent/internal/client/jobs.go` `JobOutcome` and `api/internal/handlers/jobs.go` `CompleteRequest` have only `status` and `error`.

Proposed (additive, backward compatible):

- Agent: `JobOutcome` gains `Result *JobResult \`json:"result,omitempty"\`` with `ProviderVersion *struct{ ID string; CreatedAt time.Time }`. `PatchExecutor` keeps the returned `SecretVersion`. No new dependency, no call to the Gateway.
- API: `CompleteRequest` and the service input gain the same optional field. `SyncJobs.Complete` writes it to `sync_jobs.result` in the same `UPDATE`, only for `status = 'succeeded'` and `job_type = 'patch'`. Validation: `id` matches `^[A-Za-z0-9-]{1,64}$`, else stored as null; an empty `id` is stored as null; `created_at` within a sane window of `now()`.
- Older agents produce tasks with `version_source = none`, which cannot be `verified` (reason `no_provider_version`, verdict at best `partially_observed`).

Later option, not MVP: for AWS SM, `PutOptions.IfMatch` maps to `ClientRequestToken`, which AWS uses as the new `VersionId`. The CP could choose the version id before the write and stop trusting the agent's report. It changes agent retry semantics and needs its own review.

## 12. UI

Request detail (`ui/src/pages/RequestDetail.tsx`, next to `GitOpsCard` in `ui/src/pages/request/GitOps.tsx`): a "Rollout evidence" card fed by `GET /requests/:id/observations`.

```
Secret updated     done       AWS SM version a1b2c3d4-..., 09:58:02 (reported by agent)
ESO sync           observed   ExternalSecret payments/payments-env Ready=True SecretSynced,
                              refreshed 09:59:01 (time-ordered: after the write)
Rollout            observed   Deployment payments/api 3/3 updated and available, new ReplicaSet 09:59:20
App health         Healthy    ArgoCD payments-api Synced/Healthy (context only)
------------------------------------------------------------------------------
Verified by time order    observed by Gateway tenant-a-uat-gw, replica 5b1d..., attempt 3
```

- Each stage has its own pill using the existing `StatusPill` variants (`approved`, `pending`, `warning`, `rejected`). A `failed` stage uses `rejected`.
- The verdict line uses the five verdicts with plain reasons ("the agent did not report a version", "pods will not pick up the change until restarted").
- Every Gateway-sourced line says "observed by Gateway <name>".
- The ArgoCD line is labelled "context only" and never colours the verdict.
- A stale Gateway shows a banner that says observation is waiting and that this does not mean the deployment failed.
- When a request has several tasks, the card shows the request rollup first, then one block per task.

Admin pages: Gateways list (status, version, replicas seen, last seen, open tasks), Gateway detail (token mint with copy-once display, catalog with approve buttons, bindings, recent tasks with attempts), and the environment observation source setting.

## 13. Tests owned by this track

- Two Gateways, 20 tasks: no task is returned to the wrong Gateway, and a result for the other Gateway's task returns 404.
- 2 replicas, then 100 replicas, against 20 tasks: at most one live lease per task at any time (overlap query on `observation_task_attempts`), soft caps within the documented bound.
- Kill a replica mid-attempt: lease expires, another replica claims, the late result gets 409 `attempt_superseded`. Same replica, no re-claim, posting after expiry: 409 `lease_expired`.
- Retry after a lost 200 with the same body: 200 `duplicate`. Same attempt, different body: 409 `result_conflict`.
- Result after the deadline: 409 `task_closed` and the task is `timed_out`.
- Evidence with an unknown field, a `data` key, a free-text caveat or an oversized string: 422, nothing stored.
- Older agent without `result`: task created, `version_source = none`, final verdict at best `partially_observed` with `no_provider_version`.
- Vault KV v1 write (empty id): stored as null.
- `observation_source`: a request in a `gateway` environment never gets a `gitops_observations` row, and the reverse.
- `observation_evidence` UPDATE and DELETE raise.
- API restart between job completion and task creation: the reconcile sweeper creates the task.
- Five rolling restarts with releases during one window: the task is not `dead`.
- Revoke with leased tasks: tasks back to `queued` in the same transaction.
- Second write to the same secret while a task is open: the older task is `cancelled` with `superseded_by_later_write`.
- No Gateway task or evidence query selects `secrets.checksum`.
- Claim with an unsupported contract version: 409 `contract_version_unsupported`.
