# PROFILE-agent-v1: Bounded Autonomous Agent Tasks, Tool Execution, Isolated Sessions, and Guardian Intake

- **Version:** `1.0.0-draft.2`
- **Service Type:** `agent-session` (`registry/service-types.json`)
- **Status:** `draft` (normative profile rules `decided`)
- **Evidence / Maturity:** `vectors` (`vectors/trace-03-delegation-pool-single-use.json`, `vectors/trace-04-agent-guardian-intake.json`, `vectors/refusal-coverage-matrix.json`)
- **Requires:** `SPEC-01`, `SPEC-02`, `SPEC-03`, `SPEC-04`, `SPEC-05`, `SPEC-06`, `SPEC-07`
- **Schemas:** `schemas/profile-agent.schema.json`

---

## 1. Purpose

This profile defines normative SealLink authorization for autonomous software agents operating on local or hosted stations (including external isolation runtimes such as Swarma Runtime). It separates four distinct operational boundaries:

1. **Cognitive work delegation (`agent/brief`):** Authorizes an agent run to perform bounded reasoning or drafting work, where prose `terms_text` is permitted strictly as cognitive guidance.
2. **Mechanical host tool execution (`agent/tool`):** Authorizes concrete typed tool calls (filesystem read/write, repository operations, sandboxed commands) where `terms_text` is strictly forbidden.
3. **Contract-bound isolated sessions (`agent/session`):** Authorizes starting, checkpointing, or halting a long-lived agent session bound to a bilateral contract and verified `config_sha256`.
4. **Guardian-verified instruction intake (`agent/guardian-message`):** Normatively specifies how an agent runtime's host boundary verifies guardian-authorized instructions for a `ward` agent against its read-only pinned `seallink-origin/1` and live guardianship slots (`vectors/trace-04-agent-guardian-intake.json`).

---

## 2. Manifest Declarations and Mutual Authentication (`SL-AGNT-001`, `decided`)

1. An agent host station `id/station-a` declares in its `seallink-manifest/1` `service`:
   - `service_type`: `"agent-session"`
   - `actions`: subset of `["agent/brief", "agent/tool", "agent/session", "agent/guardian-message"]`
   - `receipt_key`: pinned BIP-340 `receipt` key
   - `endpoint`: HTTPS or mutually authenticated local Unix/TLS endpoint
   - `tls_spki_sha256` (for remote endpoints): pinned TLS SPKI hash (or signed `transport-binding` statement in `certs`).
2. **Concrete executor required:** Because agent sessions, tool invocations, and guardian instruction delivery carry stateful quotas, sandboxes, and authority boundaries, `executor_ref` is FORBIDDEN across all `agent/*` actions (`GRANT_EXECUTOR_REF_FORBIDDEN`).

---

## 3. Orthogonal Action Properties Table

| Action | Kind | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `requires_contract` | `require_seal` | Risk Class |
| --- | --- | :-: | :-: | :-: | :-: | :-: | :-: | --- |
| `agent/brief` | Cognitive work (`terms_text` allowed) | `false` | `false` | `true` (`seallink/count` `starts`) | `false` | `false` | `false` *(root `window_only` allowed by policy)* | Class 2 (90m) |
| `agent/tool` | Mechanical effect (`GRANT_TEXT_FORBIDDEN`) | `true` | `true` | `true` (`seallink/count` `calls`) | `false` | `false` | `true` *(or `single_use`)* | Class 1 (60m) |
| `agent/session` | Mechanical effect (`GRANT_TEXT_FORBIDDEN`) | `true` | `false` | `true` (`seallink/count` `starts`) | `false` | `true` (`config_sha256` mandatory) | `true` | Class 1 (60m) |
| `agent/guardian-message` | Mechanical effect (`GRANT_TEXT_FORBIDDEN`) | `false` | `false` | `false` | `false` | `false` | `true` *(live grant + slot seals; `event_class = "effect_grant"`)* | Class 1 (60m) |

---

## 4. Target, Closed Schemas, Arguments, and `result_sha256` (`SL-AGNT-002`, `decided`)

- **Target grammar:**
  - `agent/brief`, `agent/tool`, `agent/session`: `station:<host_name>:<workspace_or_slot>` (e.g., `station:id/station-a:repo-seallink`).
  - `agent/guardian-message`: `ward:<origin_id_64hex>`.
- **Closed schemas:** All `invocation.arguments` and returned result objects MUST validate strictly against `schemas/profile-agent.schema.json`:
  - `agent/brief`: `AgentBriefArgs` -> `AgentBriefResult`
  - `agent/tool`: `AgentToolArgs` -> `AgentToolResult`
  - `agent/session`: `AgentSessionArgs` -> `AgentSessionResult`
  - `agent/guardian-message`: `AgentGuardianMessageArgs` -> `AgentGuardianMessageResult`
- **Normative `result_sha256` (`SL-AGNT-003`, `decided`):** For every `outcome = "executed"` receipt, `receipt.payload.result_sha256` MUST equal `SHA256(canonical_JCS(result_object))`.
- **Replay semantics:** Duplicate `invocation_id` for `agent/brief`, `agent/tool`, `agent/session`, or `agent/guardian-message` MUST NOT spawn a second run, second tool execution, or duplicate Authority Frame delivery; the host returns the stored signed receipt (including `outcome = "uncertain"` if a crash interrupted execution inside the external-effect window before receipt persistence).

### 4.1 Constrained Arguments and Predicates

| Action | Argument | Schema Type | Supported `where` Predicates |
| --- | --- | --- | --- |
| `agent/brief` | `task_id` | `string` | `eq`, `prefix` |
| `agent/brief` | `brief_sha256` | `hex64` | `hash_eq` |
| `agent/brief` | `max_duration_sec` | `uint64_str` | `range` |
| `agent/tool` | `tool_name` | `string` | `eq`, `in`, `not_in` |
| `agent/tool` | `input_sha256` | `hex64` | `hash_eq` |
| `agent/tool` | `resource_path` | `string` | `eq`, `prefix` |
| `agent/tool` | `max_output_bytes` | `uint64_str` | `range` |
| `agent/session` | `op` | `string` (`start \| checkpoint \| halt`) | `eq`, `in` |
| `agent/session` | `session_slot` | `string` | `eq`, `prefix` |
| `agent/session` | `config_sha256` | `hex64` | `hash_eq` |
| `agent/session` | `max_wall_sec` | `uint64_str` | `range` |
| `agent/guardian-message` | `origin_id` | `hex64` | `eq` |
| `agent/guardian-message` | `subject_ward_name` | `NameStr` | `eq` |
| `agent/guardian-message` | `message_sha256` | `hex64` | `hash_eq` |
| `agent/guardian-message` | `channel` | `string` | `eq`, `in` |
| `agent/guardian-message` | `delivery_mode` | `string` (`strict_drop \| untrusted_fallback`) | `eq` |

---

## 5. Normative Guardian Message Verification (`SL-AGNT-004`, `decided`)

An agent host or Bridge mediating incoming guardian messages for a `ward` agent (`origin_class = "agent"`, `guardian_policy` present) MUST distinguish between **guardian grant authorization** (the ward's `seallink-grant/1` carrying `guardian_context` and `guardian_approvals[]`) and **invocation delivery** (the signed `seallink-invocation/1` signed by the grant's recipient — either the guardian's own delivery key or an authorized Bridge relay key — carrying `AgentGuardianMessageArgs`), and MUST execute the following deterministic check before delivering any privileged instruction into an agent session's Authority Frame:

1. **Read-only origin pin:** Load the agent's locally pinned `seallink-origin/1` and `(network, genesis)` from read-only host storage outside agent write reach (`SPEC-03 §6`).
2. **Event class assignment (`effect_grant`):** Because guardian messages direct privileged agent behavior, `agent/guardian-message` MUST be classified as **`event_class = "effect_grant"`** (NEVER `routine_read`; `SPEC-04 §3.1`). A ward grant claiming `event_class = "routine_read"` for `agent/guardian-message` MUST refuse with `GUARDIAN_QUORUM_UNMET`.
3. **Full admission pipeline & ward checks:** Execute `SPEC-06 §4` on the `seallink-invocation/1` and its ward `seallink-grant/1`:
   - Confirm `status_seal` is unspent (`ORIGIN_STATUS_INCOMPLETE`, `SUBJECT_ENDED`, `GUARDIAN_TRANSFER_PENDING`) and the latest effective `roster_seal` revision matches both `grant.payload.guardian_context.revision` and `arguments.revision` (`ORIGIN_STATUS_INCOMPLETE`, `GUARDIAN_QUORUM_UNMET`).
   - Verify `grant.guardian_approvals[]` per `SL-WIRE-013` and `SL-ORIG-006`: every cited slot seal is `active` and unspent on the host's Tier 1 node (`GUARDIAN_INACTIVE`), every `guardian_approvals[i].signatures` matches that guardian's live `link.grant` policy (`WIRE_SIGNATURE`), all approving slots belong to distinct `(name, registration)` guardians, and the count meets `required("effect_grant")` against `revision_size` (`GUARDIAN_QUORUM_UNMET`).
   - Confirm `invocation.target == "ward:" + origin_id`, `arguments.origin_id == origin_id`, `arguments.subject_ward_name == ward_name`, and `SHA256(raw_message_bytes) == arguments.message_sha256` (and satisfies any `where.message_sha256` `hash_eq` predicate when the grant pins one exact message) (`INVOKE_CONSTRAINT_FAILED`).
4. **Normative default `delivery_mode = "strict_drop"`:** For ward agents, **`strict_drop` is the normative default** (`AgentGuardianMessageArgs.delivery_mode`): any unauthenticated, malformed, or refused external message MUST be dropped at the Bridge/host boundary before entering the model context. Hosts MAY permit `untrusted_fallback` ONLY when explicitly enabled by local administrator policy and strictly isolated outside the Authority Frame.
5. **Authority Frame & receipt:** Only after steps 1–3 succeed MAY the host wrap the verified message (`message_sha256`) inside a structured read-only Authority Frame, compute `frame_sha256`, and emit `AgentGuardianMessageResult` (`delivered = true`, `verified_slots`, `verified_guardians`, `message_sha256`, `frame_sha256`, `recorded_at`) + signed `seallink-receipt/1` (`vectors/trace-04-agent-guardian-intake.json`).

---

## 6. Contract-Bound Sessions, Quotas, and `config_sha256` (`SL-AGNT-005`, `decided`)

1. **`agent/session` contract requirement:** Every `agent/session` grant MUST bind `contract_id` (`GRANT_CONTRACT_REQUIRED`), and the bound `seallink-contract/1` MUST carry `config_sha256` (`SL-CONT-006`). Before executing `op = "start"`, the host MUST compute the hash of the assembled runtime profile, skills, and tool allowlist and require exact equality with both `contract.config_sha256` and `arguments.config_sha256` (`CONTRACT_CONFIG_MISMATCH`).
2. **Quota reservation:**
   - `agent/brief` and `agent/session` (`op = "start"`) reserve `1` unit from `{"kind":"seallink/count","resource":"<target>","unit":"starts"}`.
   - `agent/tool` reserves `1` unit from `{"kind":"seallink/count","resource":"<target>","unit":"calls"}` (plus any `seallink/cost` or `seallink/tokens` quotas declared on the capability).
   - For delegated child grants, reservations debit both the child's `own` account and the parent's `row` account (`SPEC-06 §2.2`), bounded across all sibling rows by R8.5 (`SPEC-06 §3`).
3. **Bearer sessions:** An admitted `agent/session` MAY open a short-lived (`<= 3600s`) `seallink-session-open/1` bearer slot for non-signing model SDKs (`SPEC-06 §5`), restricted strictly to compute/tool quotas inside the session ceiling; irreversible financial transfers MUST NOT use bearer sessions.

---

## 7. Export Boundary (`SPEC-07 §2`)

An `agent-session` migration manifest (`seallink-migration/1`) exports workspace files, conversation transcripts, checkpoint artifacts, signed receipts, and accounting evidence (settled starts/calls/costs + uncertain reservations). It NEVER exports host signing keys, Keyholder private keys, upstream API tokens, TLS private keys, or active bearer session tokens.
