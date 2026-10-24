# Gateway: discovery wire contract

Status: contract for review. Nothing here is implemented. It fixes the wire contract for ADR 0002 slices S3 (Gateway, gateway#23) and S4 (api, secrets-bridge/api#308) so both sides can be built against it in parallel, and it gives S5 (ui#173) and S6 (charts#54) the shapes they consume. Where this document and ADR 0002 disagree, the ADR wins and this document is a bug. Choices the ADR leaves open are listed in section 12 for review.

Sources read on `main`: ADR 0002 (skills, revision under review on skills#111), the implementation review and owner decision on skills#110 and skills#111, the demo-first direction on gateway#25 (2026-10-24), gateway `internal/contract/{catalog,identity,result}.go`, `internal/client/{client,errors}.go`, `internal/connectors/argocd/{settings,client}.go`, `schemas/*.json`, api `internal/handlers/gateways.go`, `internal/services/{gateway_wire,observation_wire,gateways}.go`, `internal/auth/scope_projects.go`, `pkg/storage/{environments,observation_tasks}.go`, `cmd/api/{main,routes}.go`.

Schemas added by this contract, all closed (`additionalProperties: false` on every object), with valid and invalid examples under `internal/contract/testdata/examples/<schema>/`:

| Schema | Body |
|---|---|
| `schemas/gateway-heartbeat.schema.json` | E2 request, contract 1 and 2 |
| `schemas/gateway-heartbeat-response.schema.json` | E2 200 response, contract 1 and 2 |
| `schemas/gateway-discovery-catalog.schema.json` | E8 request (`gateway.discovery-catalog/v1`) |
| `schemas/gateway-discovery-result.schema.json` | E8 200 response |
| `schemas/gateway-discovery-snapshot.schema.json` | E9 200 response (`gateway.discovery-snapshot/v1`) |
| `schemas/gateway-snapshot-plaintext.schema.json` | The sealed plaintext (never in the clear on the wire) |
| `schemas/gateway-discovery-error.schema.json` | E8 and E9 error bodies |
| `schemas/gateway-catalog-read.schema.json` | `GET /api/v1/gateway-catalog` 200 response (console) |
| `schemas/gateway-project-teams.schema.json` | AppProject to team mapping, admin PUT and GET |

`internal/contract/discovery_contract_test.go` checks every example against its schema, checks that the new schemas are closed, and checks the known-answer vectors in `internal/contract/testdata/discovery-kat.json`.

## 1. Summary

| Id | Route | Direction | Purpose |
|---|---|---|---|
| E2 | `POST /api/v1/gateways/{id}/heartbeat` | Gateway to CP | Gains `scope_digest`, `discovery_enabled`, `discovery_interval_seconds` per Argo CD connector and `bound_targets_version`. The response gains `discovery_leases`, `snapshot_generations`, `bound_targets_version` and `bound_targets`. |
| E8 | `PUT /api/v1/gateways/{id}/connectors/{connector_id}/discovery` | Gateway to CP | The lease holder uploads the sanitized catalog and the sealed snapshot. |
| E9 | `GET /api/v1/gateways/{id}/connectors/{connector_id}/snapshot` | Gateway to CP | Any replica fetches the latest sealed snapshot. |
| A1 | `GET /api/v1/gateway-catalog` | Console to CP | Team-filtered, cursor-paged catalog read (D7). |
| A2 | `GET` and `PUT /api/v1/admin/gateways/{id}/connectors/{cid}/project-teams` | Console to CP | AppProject to team mapping (C4). |
| A3 | `POST /api/v1/admin/gateways/{id}/connectors/{cid}/approve` | Console to CP | Gains a body with the approved `scope_digest` (C6). |
| A4 | `POST /api/v1/admin/gateway-bindings` | Console to CP | Same body; new rules for team scope and production (C4, C5, D1). |

E1 and E3 to E7 do not change, except that E7 gains one refusal reason (section 7.2). Tasks still carry only `{connector_id, target_id, stage}` and their schema does not change.

## 2. E2 heartbeat additions

### 2.1 Negotiation and version skew

**The api decodes heartbeats strictly.** `Heartbeat` in api `internal/handlers/gateways.go` decodes with `decodeStrict` (`DisallowUnknownFields`, and trailing data is refused) and answers 400 `invalid_request` for any field it does not know. So a Gateway must never send a contract 2 field to an api that has not said it understands contract 2. The api's `validate` accepts any `contract_versions` entry that matches `^[0-9]{1,4}$` and today always answers `contract_version: "1"` (`gatewayContractVersion`). Claims check that the Gateway's list contains `"1"` (`pkg/storage/observation_tasks.go`), so listing `"2"` as well does not change task handling.

**The Gateway decodes responses leniently.** `decodeJSON` in gateway `internal/client/client.go` uses `json.Unmarshal`, which ignores unknown fields, but it caps the E2 response at 16 KiB (`maxSmallResponse`) and fails the heartbeat above it.

The rules:

1. A Gateway built with this contract always sends `contract_versions: ["1", "2"]`.
2. An api built with this contract answers `contract_version: "2"` when the request lists `"2"`, and `"1"` otherwise. It sends the contract 2 response fields only when it answers `"2"`. The response schema enforces both directions.
3. The Gateway shapes each heartbeat by the `contract_version` of the previous response. Its first heartbeat after start is contract 1 shaped. After a `"2"` response it adds the contract 2 fields. A 400 `invalid_request` on a contract 2 shaped heartbeat (an old api replica during a rolling deploy) makes the next heartbeat contract 1 shaped again, until a later response answers `"2"`.
4. A contract 2 shaped heartbeat always carries `bound_targets_version` (the empty string when none is known), and every Argo CD connector in it carries `scope_digest` and `discovery_enabled`. The schema ties `bound_targets_version` to `"2"` being listed.
5. The E2 response cap on the Gateway rises from 16 KiB to 512 KiB for contract 2.

| Gateway | api | Behaviour |
|---|---|---|
| contract 1 (today) | contract 2 | The api answers `"1"` and sends no contract 2 field, so the old 16 KiB cap is never hit. No lease is granted, E8 and E9 are never called, static targets work as today. The connector has no scope digest, so C6 does not apply to it; the console shows the scope as unknown. |
| contract 2 | contract 1 (today) | Every response answers `"1"`, so the Gateway never sends a contract 2 field and never calls E8 or E9. A connector with `discovery.enabled: true` serves its static targets only, reports connector status `degraded`, and logs `discovery_unavailable` once per process with the reason `control_plane_contract_1`. It never falls back to discovery without a lease. |
| contract 2 | mixed replicas (rolling) | Rule 3. An E8 or E9 call that lands on an old replica gets a 404 from the router; the Gateway treats it as a transient failure, abandons that run, and keeps its last good snapshot until its maximum age. |
| contract 2 | contract 2 | This document. |

A Gateway that uses `target_snapshot_stale` (section 7.2) only does so for a discovered target, and discovered targets only exist after a contract 2 api accepted an E8 upload. So an old api never receives the new refusal reason.

### 2.2 `scope_digest` (C6)

Sent for every Argo CD connector, discovery on or off. It changes when the connector's base URL, allowed AppProjects, discovery switch or identity mode changes locally.

```
endpoint_digest = "sha256:" + hex(SHA-256(
    "sb-argocd-endpoint/v1"
    || uint32_be(len(gateway_id)) || gateway_id
    || uint32_be(len(connector_id)) || connector_id
    || normalized_base_url))

scope_digest = "sha256:" + hex(SHA-256(canonical_json({
    "v": "sb-argocd-scope/v1",
    "kind": "argocd",
    "endpoint_digest": endpoint_digest,
    "allowed_projects": sorted(allowed_projects),
    "discovery_enabled": discovery.enabled,
    "identity_mode": discovery.identity_mode     // "names" when discovery is off
})))
```

- `gateway_id` is the Gateway's UUID in lower case, `connector_id` the local connector name. Lengths are byte lengths.
- `normalized_base_url` is the base URL after `parseBaseURL` in `internal/connectors/argocd/client.go` accepted it, rendered as lower-case scheme, `://`, lower-case host, `:port` only when it is not the scheme's default (443 for https, 80 for http), then the path with trailing slashes removed. It has no user info, query or fragment, because `parseBaseURL` refuses those. Example: `HTTPS://ArgoCD.Example.com:443/` becomes `https://argocd.example.com`.
- `canonical_json` is: object keys sorted by byte value, no insignificant whitespace, strings with the minimal JSON escapes, integers without a fraction or exponent, `true` and `false`. Every value in this contract is ASCII from a fixed pattern, so this is the same as RFC 8785, and Go's `json.Encoder` with `SetEscapeHTML(false)` over a map produces it (minus the trailing newline).
- Opaque mode (deferred, section 10) adds `"label_key"` and `"project_aliases"` (an object from AppProject name to alias) to the canonical input. In names mode those keys are absent, not empty.
- The URL itself is never sent. The CP receives `endpoint_digest` in E8 so it can recompute `scope_digest` from the uploaded `allowed_projects` (section 3.2). The digest is salted with the Gateway and connector ids, so it cannot be looked up in a precomputed table or correlated across Gateways, but a CP that guesses the exact URL can confirm the guess. See decision S-2.

Known answer (from `testdata/discovery-kat.json`): gateway `123e4567-e89b-42d3-a456-426614174000`, connector `argocd-main`, URL `https://argocd.example.com`, projects `team-b-apps` and `team-a-apps`, discovery on, names mode:

```
endpoint_digest = sha256:9508006565bb8a9beb9bb68e3984a5350e7e0320f55945cad5aeddbdd71115ce
canonical       = {"allowed_projects":["team-a-apps","team-b-apps"],"discovery_enabled":true,"endpoint_digest":"sha256:9508006565bb8a9beb9bb68e3984a5350e7e0320f55945cad5aeddbdd71115ce","identity_mode":"names","kind":"argocd","v":"sb-argocd-scope/v1"}
scope_digest    = sha256:bf4357a6ba9936070285b4ac00d9d32ba1ad29922757fbd7556dc9f08c2784a7
```

### 2.3 Request fields (contract 2)

```json
{
  "replica_id": "7f3c9e2a-1b2c-4d5e-8f90-123456789abc",
  "gateway_version": "0.4.0",
  "contract_versions": ["1", "2"],
  "status": "ok",
  "in_flight": 1,
  "catalog_version": "sha256:aaaa...",
  "bound_targets_version": "",
  "connectors": [
    {"connector_id": "argocd-main", "kind": "argocd", "status": "ok",
     "scope_digest": "sha256:bf43...84a7", "discovery_enabled": true, "discovery_interval_seconds": 300},
    {"connector_id": "argocd-static", "kind": "argocd", "status": "ok",
     "scope_digest": "sha256:bbbb...", "discovery_enabled": false},
    {"connector_id": "eso-main", "kind": "eso", "status": "ok"}
  ]
}
```

| Field | Rule |
|---|---|
| `bound_targets_version` | The version of the last `bound_targets` this replica applied, or `""`. |
| `connectors[].scope_digest` | Argo CD only, required on Argo CD connectors in a contract 2 heartbeat, refused on `eso` and `rollout`. |
| `connectors[].discovery_enabled` | Argo CD only, sent together with `scope_digest`. |
| `connectors[].discovery_interval_seconds` | Required when `discovery_enabled` is true, refused otherwise. 60 to 1800 (the floor from C9; the ceiling because `snapshot_max_age` is at most 1 hour and at least twice the interval). |

The connector `status` enum does not change. A replica whose discovery connector cannot run (no snapshot yet, a failed run, a cap) still reports `ok` or `degraded` by the existing rules; the reason stays in the Gateway's logs and metrics.

### 2.4 Response fields (contract 2)

```json
{
  "status": "ok",
  "server_time": "2026-10-24T12:00:00.123456Z",
  "next_heartbeat_seconds": 30,
  "claim_poll_seconds": 5,
  "contract_version": "2",
  "catalog_version": "sha256:aaaa...",
  "discovery_leases": [
    {"connector_id": "argocd-main", "lease_id": "0b5e7c1a-3d2f-4e6a-9b8c-7d6e5f4a3b2c",
     "generation": 7, "expires_at": "2026-10-24T12:05:00Z"}
  ],
  "snapshot_generations": [{"connector_id": "argocd-main", "generation": 6}],
  "bound_targets_version": "sha256:cccc...",
  "bound_targets": [
    {"connector_id": "argocd-main", "target_ids": ["d-li3oyoq5xwjxe72ps7qqn5dikf"]},
    {"connector_id": "argocd-static", "target_ids": ["payments-api"]}
  ]
}
```

| Field | Rule |
|---|---|
| `discovery_leases` | Leases granted to this replica by this response. At most one per connector. Sent once; the replica keeps the lease until `expires_at` or until its upload is answered. Absent when none is granted. (C2, C9, section 4.2 of the ADR; an array instead of one object, decision E-1.) |
| `discovery_leases[].lease_id` | UUIDv4, unique per grant. |
| `discovery_leases[].generation` | Strictly greater than every generation granted before for the connector. An expired lease burns its generation, so gaps are allowed. |
| `discovery_leases[].expires_at` | CP clock, `grant time + lease_ttl` (decision E-3). The holder must have its upload answered before `expires_at - 15s`, using the clock offset from the `Date` header; otherwise it abandons the run. |
| `snapshot_generations` | The latest accepted generation per connector that has a stored snapshot. A replica fetches E9 when this is higher than the highest generation it has opened. |
| `bound_targets_version` | Always present in contract 2. Opaque digest of the bound target list (`""` when there are no bindings). |
| `bound_targets` | Present only when `bound_targets_version` differs from the request's. Full replace. Every Argo CD target, static or discovered, with at least one binding that is not deleted, whether suspended or not. At most 4096 target ids per Gateway (decision E-4). A replica treats a target as bound when it is in this list or received a task in the last 24 hours (C2); the list never makes the Gateway skip a probe. |

### 2.5 Lease grant (CP)

In the heartbeat transaction, with a row lock on the connector (`SELECT ... FOR UPDATE` on `gateway_connectors`), so the grant is single across api replicas. The CP grants a lease for connector C to the calling replica when all of these hold:

1. The request lists `"2"`, and C is an Argo CD connector in the request with `discovery_enabled: true`.
2. The replica status is `ok` or `degraded` and the connector status in the request is `ok` or `degraded` (never `over_privileged`, `not_ready`, `unauthorized`, `unreachable` or `shutting_down`).
3. Every live replica (inside `GatewayReplicaWindow`) that reports C reports the same `scope_digest` (C6). While they disagree, no lease.
4. No unexpired lease exists for C.
5. `now - last_lease_granted_at >= max(60s, discovery_interval_seconds)` (the C9 floor, enforced on the CP side too).
6. The Gateway is live (not revoked or disabled).

Connector approval is **not** a condition: the first upload must arrive before approval, because the approving admin needs the allowed AppProjects and the catalog (C6). Nothing in an unapproved connector's catalog can be bound or dispatched to, and only platform admins can read it (section 8.2).

### 2.6 Scope digest handling (CP, C6)

- The CP stores the digest each replica reports (per replica and connector) and, on the connector, `approved_scope_digest`.
- An accepted heartbeat whose digest for an approved connector differs from `approved_scope_digest`: connector status `advertised` with `status_reason: scope_changed`, dispatch stops, open tasks on its bindings go back to `queued` until approval or deadline, bindings get `suspended_reason: scope_changed`, and `gateway.connector.scope_changed` is audited with the old and new digests and, when an upload exists, the change in AppProject count. Re-approval (A3) with the new digest resumes those bindings.
- Live replicas that report different digests: connector `degraded` with `status_reason: scope_mismatch_between_replicas`, dispatch paused, no lease, until they agree.
- **First digest.** A connector approved before contract 2 has no `approved_scope_digest`. Its first digest is adopted without re-approval only when `discovery_enabled` is false, and audited as `gateway.connector.scope_changed` with `old_digest: null` and `adopted: true`. A first digest with `discovery_enabled: true` always needs approval (decision S-3).

## 3. E8 discovery upload

`PUT /api/v1/gateways/{id}/connectors/{connector_id}/discovery`, `X-Gateway-Secret` auth, rate limited after auth (60 per minute per Gateway), body limit 2 MiB answered as 413 `catalog_too_large` (not the generic `payload_too_large`). Contract `gateway.discovery-catalog/v1`, schema `schemas/gateway-discovery-catalog.schema.json`.

### 3.1 Request

```json
{
  "schema_version": "gateway.discovery-catalog/v1",
  "replica_id": "7f3c9e2a-1b2c-4d5e-8f90-123456789abc",
  "lease_id": "0b5e7c1a-3d2f-4e6a-9b8c-7d6e5f4a3b2c",
  "generation": 7,
  "discovered_at": "2026-10-24T12:00:00Z",
  "scope_digest": "sha256:bf4357a6ba9936070285b4ac00d9d32ba1ad29922757fbd7556dc9f08c2784a7",
  "endpoint_digest": "sha256:9508006565bb8a9beb9bb68e3984a5350e7e0320f55945cad5aeddbdd71115ce",
  "identity_mode": "names",
  "allowed_projects": ["team-a-apps", "team-b-apps"],
  "entries": [
    {"target_id": "d-li3oyoq5xwjxe72ps7qqn5dikf", "app_project": "team-a-apps", "namespace": "argocd", "name": "payments-api"},
    {"target_id": "d-zk5ykqqvtcwquubd3reviuzqrz", "app_project": "team-a-apps", "namespace": "argocd", "name": "billing-api"}
  ],
  "entries_rejected": 1,
  "entries_deferred": 0,
  "snapshot": {"alg": "A256GCM+HKDF-SHA256/v1", "nonce": "oKGio6Slpqeoqaqr", "ciphertext": "9PsIQ8x9..."}
}
```

| Field | Rule |
|---|---|
| `replica_id` | Must be the replica the lease was granted to. |
| `lease_id`, `generation` | From the lease (section 2.4). |
| `discovered_at` | Gateway clock at the start of the run, before the first list read. RFC 3339, UTC, whole seconds, `Z` (pattern in the schema). It is part of the associated data (section 5.4), so the CP stores it and returns it byte for byte; whole seconds keep it exact through a Postgres `timestamptz` (decision E-5). |
| `scope_digest` | Equal to the digest the replica sends in its heartbeat. |
| `endpoint_digest` | Section 2.2. Lets the CP recompute `scope_digest`. |
| `identity_mode` | `names` (MVP) or `opaque` (deferred; section 10). |
| `allowed_projects` | Names mode: the local list, sorted, unique, 1 to 64. Opaque mode sends `project_aliases` instead. |
| `entries[]` | Sorted by `target_id`, unique `target_id`. Names mode: `target_id`, `app_project`, `namespace`, `name`, all required, nothing else. Opaque mode: `target_id`, `project_alias`, optional `label`, and no `app_project`, `namespace` or `name`. |
| `entries[].target_id` | `d-` and 26 base32 characters, section 6. |
| `entries[].app_project` | AppProject pattern from `settings.go` (`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`), and in `allowed_projects`. |
| `entries[].namespace` | `connectors.ValidName` (DNS label). |
| `entries[].name` | `validAppName`: the Kubernetes object name pattern, at most 253, and no `..`. |
| `entries_rejected` | Items dropped by C5 validation or C3 (empty or malformed uid), plus items whose project is outside the allowlist. 0 to 10000. |
| `entries_deferred` | Valid new items left out because their C2 per-target probe could not finish before the lease deadline (decision S-4). They are in neither `entries` nor the snapshot, and the next run probes them first. 0 to 10000. |
| `snapshot` | Section 5. The entries and the sealed targets are the same set. |

The Gateway checks the body against the contract and its size before sending it, the same way `PutCatalog` calls `Catalog.Validate` today. A body that would be over 2 MiB is not sent; the run fails locally with `catalog_too_large` and the last good snapshot stays usable until its maximum age.

### 3.2 CP validation, in one transaction

The order matters, because the first failing step decides the code.

1. Parse: not exactly one JSON object, or trailing data: 400 `invalid_request`.
2. Size: body over 2 MiB: 413 `catalog_too_large`.
3. Schema: an unknown field, a missing field, a pattern, enum or count failure, unsorted or duplicate `entries`, an entry whose `app_project` is not in `allowed_projects`, or `identity_mode: opaque` before opaque mode ships (decision E-8): 422 `schema_violation`.
4. Connector: `connector_id` is not an Argo CD connector in the Gateway's current E3 catalog: 404 `connector_not_found`.
5. Lock the connector row.
6. Duplicate: same `lease_id` and `generation` as the last accepted upload and the same body SHA-256: 200 with `status: duplicate`, nothing changes.
7. Generation: `generation` less than or equal to the last accepted generation: 409 `discovery_generation_stale`.
8. Lease: `lease_id` is not the current lease, the lease has expired, `replica_id` is not the holder, or `generation` is not the lease's: 409 `lease_not_held`.
9. Scope: `scope_digest` differs from the holder's last heartbeat digest for the connector, or (names mode) differs from the digest the CP recomputes from `endpoint_digest`, `allowed_projects`, `identity_mode` and `discovery_enabled: true`: 409 `scope_digest_mismatch`.
10. Caps: more entries than the connector's cap (default 2000, set per Gateway by a platform admin, hard maximum 10000), or more than 10000 discovered targets on the Gateway after the replace: 413 `catalog_too_large`.
11. Replace: upsert every entry (new target: `first_seen_at = now`, `generation_first_seen = generation`; same target id with a new name or namespace: rename; a new AppProject: project move), mark every stored target that is not in `entries` as `missing`, store the snapshot blob and `discovered_at` (latest only, decision E-6), set `discovery_generation = generation`, `last_discovery_at = now`, and close the lease.
12. Lifecycle (ADR 4.4) in the same transaction: a target that went missing suspends its bindings with `target_missing` and cancels their open tasks with `target_missing`; a project move to an AppProject whose teams no longer cover a binding's project suspends it with `mapping_removed`.
13. Audit: one `gateway.discovery.catalog_replaced` event with the generation and the counts (present, new, missing, renamed, rejected, deferred) and no names; one `gateway.target.renamed` event per upload that renamed anything, with the target ids only (decision E-7).

The CP never truncates and never accepts part of an upload.

### 3.3 Responses

| Status | Body | When |
|---|---|---|
| 200 | `{"status": "accepted", "generation": 7, "targets_present": 2, "targets_new": 1, "targets_missing": 0, "targets_renamed": 1}` | Step 11 committed. |
| 200 | same, `"status": "duplicate"` | Step 6. |
| 400 | `{"error": "invalid_request"}` | Step 1. |
| 401 | `{"error": "unauthorized"}` | Gateway auth. |
| 404 | `{"error": "connector_not_found"}` | Step 4. |
| 409 | `{"error": "discovery_generation_stale"}` | Step 7. |
| 409 | `{"error": "lease_not_held"}` | Step 8. |
| 409 | `{"error": "scope_digest_mismatch"}` | Step 9. |
| 413 | `{"error": "catalog_too_large"}` | Steps 2 and 10. |
| 422 | `{"error": "schema_violation"}` | Step 3. |
| 429 | rate limited, `Retry-After` | After auth. |

Error bodies follow `schemas/gateway-discovery-error.schema.json`: one closed code, no field name, count or limit.

**Gateway handling.** The lease holder uses its own snapshot only after a 200 (`accepted` or `duplicate`), so every replica resolves targets from the same generation the CP validates bindings against. On 409 `lease_not_held` or `discovery_generation_stale` it drops the run and its snapshot and waits for `snapshot_generations`. On 409 `scope_digest_mismatch` it drops the run; its next heartbeat carries its current digest. On 413 or 422 it drops the run, logs the code and keeps the last good snapshot until its maximum age. On 5xx, 429 or a network error it may retry the same body while the lease is live, which is what step 6 makes safe.

### 3.4 Caps in one place

| Cap | Value | Where | Error |
|---|---|---|---|
| E8 body | 2 MiB | CP; Gateway before sending | 413 `catalog_too_large`; local `catalog_too_large` |
| Entries per connector | default 2000, per Gateway setting, hard maximum 10000 | CP; Gateway `discovery.max_applications` (C1) | 413 `catalog_too_large`; local `catalog_too_large` |
| Discovered targets per Gateway | 10000 | CP | 413 `catalog_too_large` |
| Allowed AppProjects per connector | 64 | Gateway settings; schema | settings refusal; 422 `schema_violation` |
| List response bytes | default 16 MiB, hard maximum 64 MiB (C1, D3) | Gateway | local `catalog_too_large` |
| Bound targets per Gateway | 4096 | CP at bind | 409 `gateway_bound_target_limit` |
| E2 response | 512 KiB (contract 2) | Gateway client | heartbeat fails, retried |
| E9 response | 3 MiB | Gateway client | fetch fails, no snapshot |

At the hard maximum name lengths (253 characters for the AppProject and the name) 2000 entries plus their sealed copy can pass 2 MiB. The byte cap then binds first, and the run fails with `catalog_too_large` rather than sending part of it. Typical names are far shorter.

## 4. E9 snapshot fetch

`GET /api/v1/gateways/{id}/connectors/{connector_id}/snapshot`, `X-Gateway-Secret` auth, no body, rate limited after auth (600 per minute per Gateway).

```json
{
  "schema_version": "gateway.discovery-snapshot/v1",
  "connector_id": "argocd-main",
  "generation": 7,
  "discovered_at": "2026-10-24T12:00:00Z",
  "snapshot": {"alg": "A256GCM+HKDF-SHA256/v1", "nonce": "oKGio6Slpqeoqaqr", "ciphertext": "9PsIQ8x9..."}
}
```

| Status | Body | When |
|---|---|---|
| 200 | above, `schemas/gateway-discovery-snapshot.schema.json` | The latest accepted snapshot, exactly as uploaded. |
| 404 | `{"error": "snapshot_not_found"}` | No accepted upload yet for this connector, the snapshot was deleted (credential revoked and re-created, section 4.2 step 8 of the ADR), or the connector is not one of this Gateway's Argo CD connectors. One code for all of them: a replica does the same thing in each case. |
| 401, 429 | as E8 | |

**When a replica fetches.** When `snapshot_generations` in a heartbeat response is higher than the highest generation it has opened, and once when a task arrives for a discovered target while it has no usable snapshot. It does not poll otherwise.

**What it does with the body** is section 5.5. A 404 leaves the replica with no snapshot, and tasks for discovered targets are refused (section 7.2).

## 5. Snapshot sealing

### 5.1 `snapshot_key`

32 random bytes, standard base64 in the Gateway identity Secret next to the Gateway secret, generated at enroll with `openssl rand -base64 32`, mounted as a file and never as an environment variable (review section 3, S6). Required when any connector has discovery on; a missing key, or one that does not decode to exactly 32 bytes, refuses startup with `snapshot_key_invalid`. It is never sent to the CP, and nothing derived from it is sent except sealed blobs. In particular there is no key id or key fingerprint on the wire (decision S-5).

### 5.2 Seal key

```
seal_key = HKDF-SHA256(IKM = snapshot_key, salt = empty, info = "sb-gateway-snapshot-seal/v1", L = 32)
```

`salt = empty` means the RFC 5869 default (32 zero bytes). The IKM is already uniformly random, so a salt adds nothing; binding to the Gateway and connector happens in the associated data (decision S-1). The info label is used by no other derivation.

### 5.3 Cipher and nonce

AES-256-GCM, 12-byte nonce from `crypto/rand` for every seal, 16-byte tag appended to the ciphertext (Go `cipher.AEAD.Seal` output). `alg` is the constant `A256GCM+HKDF-SHA256/v1`; any other value is refused. `nonce` is standard base64 (16 characters). `ciphertext` is standard base64 of ciphertext plus tag.

One seal per run, so the number of seals under one key stays far below the random-nonce limit for GCM.

### 5.4 Associated data and plaintext

The associated data is not sent. Both the sealing replica and every opening replica build it:

```
aad = canonical_json({
  "v": "sb-gateway-snapshot-aad/v1",
  "gateway_id": <this Gateway's id, from its own identity, never from a response>,
  "connector_id": <the connector the replica asked about, never from a response>,
  "generation": <generation>,
  "discovered_at": <discovered_at, the exact string>
})
```

`generation` and `discovered_at` are taken from the E9 response (or, for the sealer, the lease and the run). A CP that changes either one, or serves one connector's blob for another, or another Gateway's blob, makes the open fail.

The plaintext, `schemas/gateway-snapshot-plaintext.schema.json`:

```
plaintext = canonical_json({
  "v": "sb-gateway-snapshot/v1",
  "targets": [ {"target_id", "app_project", "namespace", "name", "uid"}, ... ]   // sorted by target_id
})
```

The plaintext holds real names and the raw uid in both identity modes. It is never logged.

### 5.5 Opening rules (every replica, fail closed)

A replica accepts a fetched snapshot only when all of these hold. Any failure means "no usable snapshot": tasks for discovered targets are refused with `target_snapshot_stale` and the replica never falls back to a name lookup or to an older blob.

1. `alg` is the constant, `nonce` decodes to 12 bytes, and GCM open with the rebuilt associated data succeeds. After a `snapshot_key` rotation old blobs fail here, as the ADR requires.
2. The plaintext matches its schema.
3. For every target, `target_id == TargetIdentityDigest(connector_id, uid)` and `app_project` is in the local `allowed_projects`.
4. `generation` is not lower than the highest generation this process has opened for the connector.
5. `now - discovered_at <= discovery.snapshot_max_age` on the Gateway clock, and `discovered_at` is not more than 60 seconds in the future.

Rule 5 is checked again for every task, before any read (C7). Replay of an older valid blob to a fresh replica is bounded by rule 5 and by the per-task uid and project checks, as ADR section 4.2 step 7 accepts.

### 5.6 Known answer

From `internal/contract/testdata/discovery-kat.json`, computed with Go (`crypto/hkdf`, `crypto/aes`, `crypto/cipher`) and checked independently with Python `cryptography` 48.0.0 (`HKDF`, `AESGCM`). Test values only.

```
snapshot_key (base64) = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=     (bytes 00..1f)
seal_key (hex)        = e881a329ca030cc144947556b33c5fa21b319cf386614b9545f65ddb75d4c522
nonce (base64)        = oKGio6Slpqeoqaqr                                   (bytes a0..ab)
aad                   = {"connector_id":"argocd-main","discovered_at":"2026-10-24T12:00:00Z","gateway_id":"123e4567-e89b-42d3-a456-426614174000","generation":7,"v":"sb-gateway-snapshot-aad/v1"}
plaintext             = {"targets":[{"app_project":"team-a-apps","name":"payments-api","namespace":"argocd","target_id":"d-li3oyoq5xwjxe72ps7qqn5dikf","uid":"6f1c2c1e-0000-4000-8000-0000000000a1"},{"app_project":"team-a-apps","name":"billing-api","namespace":"argocd","target_id":"d-zk5ykqqvtcwquubd3reviuzqrz","uid":"6f1c2c1e-0000-4000-8000-0000000000b2"}],"v":"sb-gateway-snapshot/v1"}
ciphertext (base64)   = 9PsIQ8x9PHIxtoJLMc1EpRInCgZVl/noeGRP7EQHVmbNlI6YAhWH/zQC/uOOoCP8IplIPU+VA3KghSSiMdseGqEW0WV9atr6BHRaX4morwA4cO7VA8c7SYLjZTUso4X62h4v9LJNAeqWgJuoIrnqh7C+NVX/pl+jiBR4taNycD/1xQ27jSLb9IcG3jsOBoFmsKXWk+ZUXhhzevnJKXc6NVeuQ1eIPIsKQSfzyp+qqLaH+TDDnyXKKDvuCOUWTd+AQlauQ4RgvGWldXWnKxgsM1h6Yky//m0tgeQqhTThW3YPkIOShYL3QACIzUB6ULs4GEMt78aG9jYdW7Y7zqGT13+wtr2GBTlT24zLGVHuLj6fx7iy3iLrhK8bZyEop2qVHPJUdowZI3pOVmGOkJ9j6nVnIaFzYQ6fxhr7nPtrWg6LiFURNzJqPmBKeTekkqMPpdoqcdTkLqxeshb4HMVAG+dBYUm/+y358BLZCe8P62JXcUzxbE1Ny6t7bg==
```

`TestSnapshotSeal_KnownAnswer` rebuilds every line from the inputs, opens the blob, and checks that a changed generation, `discovered_at`, connector id, Gateway id, ciphertext byte, a rotated key, and a key derived from a Gateway secret all fail to open.

## 6. Target id

A discovered target id is `contract.TargetIdentityDigest(connector_id, metadata.uid)` in `internal/contract/identity.go`, unchanged: `d-` and the first 130 bits of `SHA-256("sb-argocd-target/v1" || uint32_be(len(connector_id)) || connector_id || uid)` in lower-case base32, 28 characters, a DNS label. It is the same value as a static target's `identity` (E3) and the evidence `resource.identity_digest`, so a static and a discovered target for the same object compare equal (the basis for the deferred migration, ADR Q7). Known answers are in `identity_test.go`, for example `argocd-main` with uid `6f1c2c1e-0000-4000-8000-0000000000a1` gives `d-li3oyoq5xwjxe72ps7qqn5dikf`.

With discovery on, a static target id may not start with `d-` (ADR C3); `decodeSettings` refuses it and the chart render guard refuses it.

## 7. Error codes, refusal reasons and states

### 7.1 Machine routes (E2, E8, E9)

| Code | Status | Route |
|---|---|---|
| `invalid_request` | 400 | E2 (unchanged), E8 |
| `unauthorized` | 401 | all |
| `connector_not_found` | 404 | E8 |
| `snapshot_not_found` | 404 | E9 |
| `discovery_generation_stale` | 409 | E8 |
| `lease_not_held` | 409 | E8 |
| `scope_digest_mismatch` | 409 | E8 |
| `catalog_too_large` | 413 | E8 |
| `schema_violation` | 422 | E8 |

The Gateway client maps each to a sentinel in `internal/client/errors.go`, as it does for the E4 to E7 codes.

### 7.2 New refusal reason: `target_snapshot_stale`

Added to the closed `refusal_reason` set of `gateway.evidence-result/v1` (E7), next to `unknown_connector`, `unbound_target`, `stage_not_supported_by_connector`, `scope_mismatch`, `schema_violation`, `unsupported_schema_version` and `deadline_passed`. It stays v1, additive, the same way `target_identity_changed` was added (D2), because only a contract 2 Gateway sends it and only for discovered targets.

A replica refuses a task for a discovered target (id starts with `d-` on a connector with discovery on) with `target_snapshot_stale`, before any read, when it has no usable snapshot: none fetched, the last fetch was a 404, the blob failed any rule in section 5.5 (including a rotated `snapshot_key`), or the snapshot is older than `discovery.snapshot_max_age`. A task for a `d-` id that is not in a usable snapshot is refused with the existing `unbound_target`.

The enum change in `schemas/evidence-result.schema.json`, `RefusalTargetSnapshotStale` in `internal/contract/result.go`, and the matching entry in api `obsRefusalReasons` (`internal/services/observation_wire.go`) land together in the S3 and S4 PRs, not in this one, so the Go validator and the schema never disagree on `main`.

The CP side: a refused result with `target_snapshot_stale` closes the attempt as refused, like the other reasons, and does not count as a failure of the binding. The connector shows `degraded` with `status_reason: snapshot_stale` while the stored snapshot is older than the largest `snapshot_max_age` the CP knows of (ADR 4.4, last row). The CP learns nothing about the Gateway's maximum age from the wire, so it uses 1 hour, the hard maximum.

Unchanged on the per-task GET (C7): a uid that does not match the target id answers `error` with `target_identity_changed`; a project outside the allowlist answers `unverifiable`.

### 7.3 Gateway-local codes (logs and metrics, not on the wire)

| Code | Meaning |
|---|---|
| `snapshot_key_invalid` | Startup refused: discovery on and `snapshot_key` missing or not 32 bytes. |
| `catalog_too_large` | Run refused: a C1 or C9 cap, or the E8 body would be over 2 MiB. No partial catalog. |
| `discovery_unavailable` | The CP answered contract 1; discovery connectors serve static targets only. |

### 7.4 Console and admin routes

| Code | Status | Route |
|---|---|---|
| `production_binding_platform_only` | 403 | A4: a caller without global `gateway.bind` and an environment that is platform-only (section 8.4) |
| `target_team_mismatch` | 403 | A4: the target is visible, but its AppProject's teams do not cover the binding project's team |
| `target_not_found` | 404 | A4: unknown target, or not visible to the caller (the same answer for both, C4) |
| `target_missing` | 409 | A4: visible but `missing` |
| `connector_not_approved` | 409 | A4 (existing), also when the approved digest is not the current one |
| `gateway_bound_target_limit` | 409 | A4: the Gateway already has 4096 bound targets |
| `scope_digest_changed` | 409 | A3: the digest in the body is not the one the replicas report now |
| `project_mapping_incomplete` | 409 | A3, A2: approving, or saving a mapping on an approved connector, would leave an allowed AppProject with no team |
| `unknown_app_project` | 422 | A2: a mapping for an AppProject not in the latest upload |
| `team_not_found` | 404 | A2 |
| `invalid_query` | 400 | A1: an unknown or malformed query parameter |
| `invalid_cursor` | 400 | A1: a cursor that does not decode or was made with other filters |

### 7.5 States, reasons and audit events

- Connector `status_reason`: `scope_changed`, `scope_mismatch_between_replicas`, `snapshot_stale`.
- Discovered target `status`: `present`, `missing`. Static target identity: `pinned`, `identity_changed` (api#312, unchanged).
- Binding `suspended_reason`: `target_missing`, `identity_changed`, `mapping_removed`, `scope_changed`.
- Task cancel reasons: `target_missing`, `binding_suspended`.
- Audit events (metadata only, ids and counts, never names, digests of values or uids): `gateway.connector.scope_changed`, `gateway.connector.project_mapping_changed`, `gateway.target.renamed`, `gateway.target.identity_changed` (exists), `gateway.binding.identity_confirmed` (exists), `gateway.discovery.catalog_replaced`. Denied binds, approvals and mapping writes are audited as denied, as api#312 does for binds today.

## 8. Control plane catalog read, team mapping and bind rules (S4, S5)

### 8.1 A1: `GET /api/v1/gateway-catalog`

Readable by a caller with global `gateway.list`, global `gateway.bind`, or `gateway.bind` scoped by `team_id`. Anyone else gets 403. It is not under `/admin` because team-scoped admins use it (D7). It replaces nothing: `GET /admin/gateways/:id` stays as it is, global only.

Query parameters, all optional:

| Parameter | Format | Filter |
|---|---|---|
| `gateway_id` | UUID | one Gateway |
| `connector_uuid` | UUID | one connector row (the `:cid` of the admin routes) |
| `app_project` | AppProject pattern | exact |
| `namespace` | DNS label | exact |
| `q` | 1 to 63 of `[a-z0-9.-]` | substring of `name` |
| `source` | `discovered` or `static` | |
| `status` | `present`, `missing`, `stale`, `identity_changed` | |
| `bound` | `true` or `false` | has a binding that is not deleted |
| `new` | `true` or `false` | first seen in the last 24 hours |
| `team_id` | UUID | AppProject mapped to this team; outside the caller's teams it matches nothing |
| `limit` | 1 to 200, default 50 | page size |
| `cursor` | from `next_cursor` | |

Response, `schemas/gateway-catalog-read.schema.json`:

```json
{
  "items": [
    {
      "gateway_id": "123e4567-e89b-42d3-a456-426614174000",
      "connector_uuid": "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
      "connector_id": "argocd-main",
      "target_id": "d-zk5ykqqvtcwquubd3reviuzqrz",
      "source": "discovered",
      "status": "present",
      "app_project": "team-a-apps",
      "namespace": "argocd",
      "name": "billing-api",
      "first_seen_at": "2026-10-24T12:00:03Z",
      "last_seen_at": "2026-10-24T12:00:03Z",
      "is_new": true,
      "look_alike": false,
      "binding_count": 0,
      "team_ids": ["5d6e7f80-1a2b-4c3d-8e9f-0a1b2c3d4e5f"]
    }
  ],
  "next_cursor": "eyJrIjoiZC16azV5In0"
}
```

- Sort order: `gateway_id`, `connector_uuid`, `app_project`, `namespace`, `name`, `target_id` (static targets sort with an empty AppProject first). Keyset paging on that tuple; `next_cursor` is absent on the last page. The cursor is opaque base64url, carries the last item's sort key and a hash of the filters, and is refused with `invalid_cursor` under other filters.
- `first_seen_at` is the CP time the first upload holding the target was accepted (C5). `is_new` is `first_seen_at` within 24 hours.
- `look_alike` is true when another target **visible to the same caller** on the same Gateway has the same `name` with a different `app_project` or `namespace` (decision S-6).
- Static targets carry `namespace` and `name` from E3, `status` `present`, `stale` or `identity_changed`, and never `app_project`, `team_ids` or any identity digest.
- The response never carries a uid, a snapshot, `endpoint_digest`, `scope_digest` or a URL.

### 8.2 Team filtering

The filter is applied in the query, before paging, so a page never has holes and counts never leak.

| Caller | Sees |
|---|---|
| Global `gateway.list` or global `gateway.bind` | Every target of every Gateway: static, discovered, unapproved connectors, unmapped AppProjects, missing. |
| `gateway.bind` scoped to team T | Discovered targets on **approved** connectors whose AppProject is mapped to a team in T's subtree (`TeamScopeResolver.DescendantTeamIDs`), `present` or `missing`. No static target, nothing on an unapproved connector, nothing in an unmapped AppProject. `team_ids` lists only teams in the caller's subtrees. |
| `gateway.bind` scoped by `project_id` | Ignored for the catalog and for binding (decision S-7): it reads as no grant. |

Every other gateway admin route (`GET /admin/gateways`, `/admin/gateways/:id`, `/admin/gateway-bindings`, `/admin/gateways/:id/tasks`) stays global-only in the MVP, so a team-scoped admin cannot read another team's names through them (C4). Opening them to team scope later needs the same filter.

### 8.3 A2 and A3: team mapping and approval

**A2.** `GET /api/v1/admin/gateways/{id}/connectors/{cid}/project-teams` (global `gateway.list`) and `PUT` on the same path (global `gateway.bind`, fresh second factor). Body and GET response: `schemas/gateway-project-teams.schema.json`.

```json
{"mappings": [
  {"app_project": "team-a-apps", "team_ids": ["5d6e7f80-1a2b-4c3d-8e9f-0a1b2c3d4e5f"]},
  {"app_project": "team-b-apps", "team_ids": ["6e7f8091-2b3c-4d4e-9f0a-1b2c3d4e5f60"]}
]}
```

- Full replace. 1 to 16 teams per AppProject. The GET adds `allowed_projects` (from the latest accepted upload) and `complete`.
- An `app_project` that is not in the latest upload's `allowed_projects`: 422 `unknown_app_project`. An unknown team: 404 `team_not_found`.
- On an approved connector the result must map every allowed AppProject: 409 `project_mapping_incomplete` (decision S-8). So an approved connector never has an unmapped AppProject.
- A change that leaves a binding's project outside the teams of its target's AppProject suspends that binding with `mapping_removed` and cancels its open tasks with `binding_suspended`.
- Audited as `gateway.connector.project_mapping_changed` with team ids and AppProject counts.

**A3.** `POST /api/v1/admin/gateways/{id}/connectors/{cid}/approve` keeps its gate (global `gateway.bind`, fresh second factor). For a connector that reports a scope digest it now takes a body:

```json
{"scope_digest": "sha256:bf4357a6ba9936070285b4ac00d9d32ba1ad29922757fbd7556dc9f08c2784a7"}
```

- Required when the live replicas report a digest; an empty body stays valid for contract 1 Gateways.
- It must equal the digest every live replica reports now, or 409 `scope_digest_changed`. The admin approves the scope they were shown, not a later one.
- With discovery on, the mapping must already be complete, or 409 `project_mapping_incomplete`.
- On success: `approved_scope_digest` is stored, `status_reason` is cleared, bindings suspended with `scope_changed` resume.

### 8.4 A4: bind rules

`POST /api/v1/admin/gateway-bindings` keeps its body (`argocd_target_id` may now be a `d-` id) and its fresh second factor. Its gate becomes "global or team-scoped `gateway.bind`". Checks, in order; the first failure answers:

1. The target exists and is visible to the caller (section 8.2), or 404 `target_not_found`. A team-scoped caller never gets a different answer for a target of another team.
2. A discovered target is `present` in the current generation, or 409 `target_missing`. A static target keeps the api#312 checks (`target_stale`, `target_identity_changed`).
3. The environment, and the project, are in the caller's `EffectiveProjectAccess` for `gateway.bind`, or 404 `environment_not_found`.
4. **Production guard (D1).** A caller without global `gateway.bind` may bind only into an environment whose type is `dev`, `staging` or `uat` **and** whose kind is `non_prod`. Type `prod` or `other`, or kind `prod` (an environment with type `staging` can carry kind `prod`, `pkg/storage/environments.go`), answers 403 `production_binding_platform_only`. This applies to static and discovered targets, so the guard holds whatever kind of target is bound.
5. **Team relation (C4).** For a discovered target, the binding project's team is in the subtree of at least one team its AppProject maps to, or 403 `target_team_mismatch`. This applies to platform admins too (decision S-8): every binding of a discovered target has a team that owns it, and the dispatch check below can be uniform.
6. The connector is approved and `approved_scope_digest` equals the digest the replicas report, or 409 `connector_not_approved`.
7. The Gateway has fewer than 4096 bound targets, or 409 `gateway_bound_target_limit`.
8. Existing checks (kind, environment in project, the Gateway's pinned environment, `binding_exists`).

Every allow and deny is audited; a deny carries path ids and the error code only.

`DELETE /admin/gateway-bindings/:id` follows rules 1 and 3 for a team-scoped caller (404 otherwise).

### 8.5 Dispatch re-check

In the task creation and claim transactions, a binding of a discovered target dispatches only while: the connector is approved with the current digest, no live replica disagrees on the digest, no live replica reports the connector `over_privileged` (Phase 0), the target is `present`, the binding is not suspended, and the target's AppProject still maps to a team that covers the binding project. Otherwise the binding is suspended with the matching reason, or the task stays queued for a digest mismatch between replicas.

## 9. Sequences

### 9.1 Lease, run, upload

```mermaid
sequenceDiagram
  autonumber
  participant R1 as Gateway replica 1
  participant CP as api (any replica)
  participant DB as Postgres
  participant AC as Argo CD
  R1->>CP: E2 heartbeat (contract 2, scope_digest, discovery_enabled, interval)
  CP->>DB: lock connector row; digests agree, no live lease, floor passed
  DB-->>CP: generation 7 reserved, lease L7 stored
  CP-->>R1: 200 contract_version 2, discovery_leases [L7, gen 7, expires_at]
  Note over R1: discovered_at = now (whole seconds)
  R1->>AC: can-i project-wide probes (C2), unless a recheck is still fresh
  loop each allowed AppProject
    R1->>AC: GET /api/v1/applications?projects=P&fields=... (C1)
  end
  R1->>R1: stream-decode, validate names (C5), require uid (C3), derive d- ids
  loop each new target, until expires_at minus 15s
    R1->>AC: can-i per-target probes (C2); a yes stops the replica
  end
  R1->>R1: entries + sealed snapshot (seal_key, fresh nonce, aad)
  R1->>CP: E8 PUT .../discovery (lease L7, gen 7, entries, snapshot)
  CP->>DB: lease, generation, scope, caps; replace targets; store blob
  CP-->>R1: 200 accepted
  Note over R1: uses its own snapshot only now
```

### 9.2 Another replica fetches the snapshot

```mermaid
sequenceDiagram
  autonumber
  participant R2 as Gateway replica 2
  participant CP as api
  R2->>CP: E2 heartbeat (contract 2)
  CP-->>R2: 200 snapshot_generations [argocd-main: 7]
  Note over R2: highest opened generation is 6
  R2->>CP: E9 GET .../connectors/argocd-main/snapshot
  CP-->>R2: 200 generation 7, discovered_at, snapshot
  R2->>R2: rebuild aad from own gateway_id, argocd-main, 7, discovered_at
  R2->>R2: open (GCM), schema, id derivation, allowlist, generation >= 6, age
  alt every check passes
    R2->>R2: snapshot 7 becomes current
  else any check fails
    R2->>R2: no usable snapshot; tasks for d- targets refused target_snapshot_stale
  end
```

### 9.3 A task resolves a discovered target

```mermaid
sequenceDiagram
  autonumber
  participant UI as Console
  participant CP as api
  participant R as Gateway replica
  participant AC as Argo CD
  UI->>CP: A1 catalog read (filtered to the caller's teams)
  UI->>CP: A4 bind d-li3o... to project and environment (MFA)
  CP->>CP: visible, present, env access, production guard, team relation, approved digest
  CP-->>UI: 201 binding
  Note over CP: a request reaches executed; task created
  R->>CP: E4 claim
  CP-->>R: task {connector_id argocd-main, target_id d-li3o..., stage}
  R->>R: snapshot usable and younger than snapshot_max_age?
  alt no
    R->>CP: E7 refused, target_snapshot_stale
  else yes
    R->>R: per-target probe older than recheck interval? probe first (C2)
    R->>AC: GET /api/v1/applications/payments-api?appNamespace=argocd
    R->>R: uid matches target id? project in allowlist? (C7)
    R->>CP: E7 evidence, argocd_context, identity_digest, context_only
  end
```

## 10. MVP for the demo

The owner's demo (gateway#25, 2026-10-24) needs: discovery with `allowed_projects` and no static list; a sanitized, team-filtered catalog with opaque uid-derived ids; a team-scoped bind that works, a cross-team read and bind that fail, and a team-scoped `prod` bind that fails; read-only, context-only observation; and visible fail-closed results for a recreated Application, an over-privileged token, a scope change, and a stale snapshot.

**In the MVP, unchanged from this document:**

| Condition | What the demo exercises |
|---|---|
| C1 | The list route only with discovery on, one allowed project per request, fixed `fields`, streaming decode, byte and count caps. |
| C2 | Project-wide probes at start and every recheck (5 minutes, 1 minute floor, D4); the read probe; per-target probes for every new discovered target before it enters a snapshot, for static targets, for bound targets at each recheck, and before a task when the last probe is older than the recheck interval. A failed per-target probe keeps demoting the whole connector (D10). |
| C3 | Derived `d-` ids, uid required, uid and project checked on every task GET, no raw uid on the wire. |
| C4 | AppProject to team mapping (A2), mapping required to approve, team-scoped `gateway.bind`, server-side filter (A1), 404 for other teams, dispatch re-check. |
| C5 | Name validation on both sides; picker fields (AppProject, namespace, name, first seen, id, new, look-alike); production guard (D1). |
| C6 | `scope_digest` in every contract 2 heartbeat, re-approval with the digest (A3), dispatch pause, replica disagreement. |
| C7 | One GET per task, snapshot maximum age, `target_snapshot_stale`. |
| C8 | Names mode only, with the data that leaves the boundary stated in the operations docs. |
| C9 | All caps on both sides, interval floor on both sides, single flight through the lease, generation check. |
| Section 4.2 | `snapshot_key`, seal, fetch, open rules, rotation fails closed. |

**Deferred, and why that is safe for the demo:**

| Deferred | Why it can wait | What stays true without it |
|---|---|---|
| Opaque mode (C8 optional part) | The ADR allows it to ship after names mode. The schemas already carry its shape so it needs no new contract version. | The CP refuses `identity_mode: opaque` with 422 `schema_violation` until it ships (decision E-8). |
| Daily full sweep and `argocd.probe_rate` (C2) | The per-new-target probe stays, and so do the bound-target recheck and the probe before a task. | An app-specific write grant added on an **unbound** target after its first probe is not found until the target is bound and rechecked, or a task arrives. The Gateway never observes an unbound target, so no data is read through such a grant. This gap must be listed in the demo report. |
| Static to discovered migration (ADR Q7) | The demo uses a fresh discovery connector. | Bindings never move between targets. |
| Resuming a binding suspended for `target_missing` or `mapping_removed` | The demo shows the suspension, not a resume. | Delete and bind again. No binding resumes on its own. |
| Opening the other admin reads to team scope | Not needed to show C4. | They stay global-only (section 8.2). |
| Per-Gateway `discovery_allowed` switch on the CP (ADR Q8) | The integrator switch is enough for an isolated demo. | Nothing is bindable before approval and mapping. |

## 11. Implementation notes

**Gateway (S3).**
- `internal/client`: `do` admits only POST and PUT; E9 needs GET with no body. Extend `allowedPath` with `connectors/<localId>/(discovery|snapshot)`, keep every other rule, and give E8 a 2 MiB request cap, E9 a 3 MiB response cap and E2 a 512 KiB response cap under contract 2.
- Add the closed Go types for the new bodies in `internal/contract` with `Validate` methods and the field-by-schema test that `catalog_test.go` uses (`TestCatalog_FieldsMatchSchema`).
- `snapshot_key` is read from a file path, decoded once, and kept out of every log, error string, metric label and request.

**api (S4).**
- The E8 route needs a body limit of 2 MiB that answers `catalog_too_large`, not the shared `BodyLimit` code, and the server-wide fiber body limit must allow it.
- Strict decoding stays for every new body. Contract 2 heartbeat fields must only be accepted from a request that lists `"2"`.
- Migrations (owner approval required): `gateway_discovered_targets`, `gateway_connector_project_teams`, and the `gateway_connectors` and `gateway_connector_bindings` columns of ADR 4.3, plus per-replica, per-connector `scope_digest` and the stored blob, `discovered_at` and last upload digest.

**UI (S5).** A1 is the only list the picker uses. `hasPermission` must become scope-aware, so a team-scoped admin is not offered actions the API refuses.

**Charts (S6).** `snapshot_key` from the identity Secret as a mounted file, discovery values off by default, the guards in charts#54, and refusal to render discovery without `snapshot_key`.

## 12. Decisions for review

Tagged [sec] for @hatmast2r and [eng] for @daedmaet187. Each is the option this contract uses; a reviewer can change it before S3 or S4 merges.

| # | Tag | Decision | Alternative |
|---|---|---|---|
| S-1 | [sec] | HKDF salt is empty; Gateway and connector binding is in the associated data, which is rebuilt locally and never taken from a response. | Salt with the Gateway id, which adds per-Gateway keys but nothing the AAD does not already give. |
| S-2 | [sec] | `endpoint_digest` is a salted SHA-256 of the normalized URL. A CP that guesses the exact URL can confirm the guess, as it already could from the ADR's digest because every other digest input is known to the CP. | An HMAC under a key derived from `snapshot_key`, which hides the URL fully but leaves static-only connectors (no `snapshot_key`) without a digest, or makes `snapshot_key` required for them too. |
| S-3 | [sec] | The first digest of an already approved, discovery-off connector is adopted and audited; a first digest with discovery on always needs approval. | Re-approve every connector on the first contract 2 heartbeat, which pauses every static connector on upgrade. |
| S-4 | [sec] [eng] | New targets whose per-target probes do not finish before the lease deadline are left out (`entries_deferred`) and probed first in the next run. Lease TTL default 300 seconds. | Renewable leases, or a longer TTL, so a large first run finishes in one lease. |
| S-5 | [sec] | No key id or key fingerprint on the wire. After a rotation, a replica learns the blob is unusable only by failing to open it. | A key id derived from `snapshot_key`, which the ADR forbids (no derived value leaves the boundary). |
| S-6 | [sec] | `look_alike` is computed over the targets visible to the caller, so it never reveals that a name exists in another team. | Over the whole Gateway, which flags more look-alikes but leaks one bit per name across teams. |
| S-7 | [sec] | A `project_id`-scoped `gateway.bind` grant reads as no grant for the catalog and for binding. Only global and `team_id` scopes count. | Resolve the project to its team. |
| S-8 | [sec] | An approved connector can never have an unmapped AppProject (A2, A3 refuse it), and the team relation (rule 5) applies to platform admins too. | Let platform admins bind targets in any AppProject, with the dispatch re-check only for team-scoped bindings. |
| S-9 | [sec] | Platform-only environments are type `prod` or `other`, or kind `prod` (D1 plus the existing kind field). | Type only, as D1 is worded. |
| S-10 | [sec] | A replica with no usable snapshot (never fetched, 404, failed open, rotated key, too old) refuses with `target_snapshot_stale`; a `d-` id missing from a usable snapshot refuses with `unbound_target`. | A separate `target_snapshot_missing` reason. |
| E-1 | [eng] | `discovery_leases` is an array (one lease per connector, several connectors per response). | One `discovery_lease` object per response, which slows lease spread with many connectors. |
| E-2 | [eng] | Contract version `"2"` in the existing `contract_versions` negotiation gates every new field and route (D2). | A separate feature list in the heartbeat. |
| E-3 | [eng] | Lease TTL is a CP setting, default 300 seconds, 60 to 900. | Derived from the interval. |
| E-4 | [eng] | Bound targets ride on the heartbeat response, versioned, at most 4096 per Gateway, with a 512 KiB response cap. | A separate E10 route for the bound list. |
| E-5 | [eng] | `discovered_at` has whole-second precision so it survives a `timestamptz` round trip byte for byte. | Store it as text. |
| E-6 | [eng] | The CP keeps only the latest snapshot per connector (ADR Q5). Revoking the Gateway credential deletes them. | Keep the last N generations. |
| E-7 | [eng] | Per upload, one `gateway.discovery.catalog_replaced` event with counts, and one `gateway.target.renamed` event with target ids, instead of one audit row per target. | One row per added, removed and renamed target. |
| E-8 | [eng] | The schemas carry opaque mode now; the CP refuses it with 422 until it ships. | Leave opaque mode out of v1 and add it as v2 of the upload. |
| E-9 | [eng] | E9 uses one 404 code, `snapshot_not_found`, for "no snapshot" and "not your connector". | Separate codes. |
| E-10 | [eng] | The `target_snapshot_stale` enum change lands with the S3 and S4 code, not in this contract PR, so the Go validator and the schema never disagree on `main`. | Change the schema now and the validators in a follow-up. |
| E-11 | [eng] | A1 is `/api/v1/gateway-catalog` (outside `/admin`), sorted by Gateway, connector, AppProject, namespace, name and id, keyset cursor bound to the filters. | `first_seen_at` descending, which puts new targets first but needs a second index. |
