# SPEC-06: Universal Grants, Invocations, Re-Delegation, Sessions, and Anti-Rollback Journals

- **Version:** `1.0.0-draft.6`
- **Status:** `draft` (normative rules `decided`; external CAS witness transport protocol tracked `open` in `OPEN-QUESTIONS.md`)
- **Evidence / Maturity:** `vectors` (`vectors/trace-01-mail-offline-revoke.json`, `vectors/trace-03-delegation-pool-single-use.json`, `vectors/trace-04-agent-guardian-intake.json`, `vectors/refusal-coverage-matrix.json`)
- **Registries:** `registry/object-types.json`, `registry/constraints.json`, `registry/opreturn-actions.json`, `registry/refusal-codes.json`
- **Schemas:** `schemas/grant.schema.json`, `schemas/invocation.schema.json`

---

## 1. Universal Grant Model (`seallink-grant/1`)

A `seallink-grant/1` (`<= 65536` bytes, `schemas/grant.schema.json`) is the universal authorization instrument across people, organizations, services, and agents (`SL-GRNT-001`, `decided`). Every grant carries **exactly one** of `issuer` (root grant) or `parent` (depth-2 child grant).

### 1.1 Unilateral Base and Optional Contract Binding

- **Unilateral base:** An autonomous root grant requires ONLY the issuer's valid `SignatureSet` matching `issuer.role_policy` (pinned on chain in `link.grant` per `SL-IDEN-003`). A root grant issued on behalf of a `ward` omits `issuer.role_policy`, sets `payload.guardian_context`, and carries top-level `guardian_approvals[]` satisfying `required(derived_event_class)` (`SL-WIRE-013`, `SL-ORIG-006`). Neither form requires recipient assent or imposes obligations on the recipient.
- **Contract-bound grants:** Setting optional `contract_id` binds the grant to a `seallink-contract/1` (`SPEC-05`): the grant's window MUST nest inside the contract (and any framework contract), all `machine_clause_indices` MUST be disclosed and match the grant's capabilities, and spending the contract or framework seal terminates the grant (`SEAL_SPENT`). Action profiles with `requires_contract = true` refuse unilateral grants (`GRANT_CONTRACT_REQUIRED`).

### 1.2 Recipient Modes (`SL-GRNT-002`, `decided`)

Every grant selects **exactly one** recipient mode:
1. **By Key (`mode = "key"`):** Names one `xonly_64hex` public key (suitable for ephemeral key-only workers and hardware keys). Ledger name resolution is skipped for the recipient.
2. **By Name (`mode = "name"`):** Names `(name, owner_policy)`. At invocation, the verifier resolves `name`, confirms its current live output matches `owner_policy` (`NAME_OWNER_MISMATCH`), and accepts signatures from the name's current authorized `nostr`/request key, permitting same-owner key rotation and name renewal without reissuing the grant.
3. **By Group (`mode = "group"`):** Names a `ThresholdPolicy` (`m-of-n` distinct keys), authorizing execution ONLY when `>= m` distinct co-recipients sign `seallink-invocation/1` (`SignatureSet`).

### 1.3 Concrete `executor` vs. Stateless `executor_ref` (`SL-GRNT-003`, `decided`)

Every action leaf in a service profile declares four orthogonal boolean properties (`SPEC-07 §4.1`): `external_mutation`, `discloses_data`, `quota_consuming`, and `allows_executor_ref`. Every grant carries **exactly one** of:
- **Concrete `executor: {name, key}`:** Pins one specific service identity and receipt key. **MANDATORY** whenever ANY capability in `capabilities[]` has `external_mutation = true`, `quota_consuming = true`, carries `quotas`, uses `single_use` revocation, or includes `delegate`.
- **Dynamic `executor_ref: {provider_of, service_type, label}`:** Resolves at verification time against `provider_of`'s current confirmed `seallink-manifest/1` `providers[]` entry (`NamePin` + service manifest `receipt_key`) matching `(service_type, label)`. **STRICTLY FORBIDDEN** if the grant carries any `quotas`, uses `single_use` revocation, includes `delegate`, or includes any action with `external_mutation = true` or `allows_executor_ref = false` (`GRANT_EXECUTOR_REF_FORBIDDEN`).

> **Rationale:** Stateless data-read actions (e.g., `mail/read` without quotas) have `discloses_data = true` and `external_mutation = false`, so resolving the current pinned provider via `executor_ref` cannot double-spend quotas or cause duplicate side effects.

### 1.4 Validity Window and Revocation Modes (`SL-GRNT-004`, `decided`)

- **Half-open block window:** `[not_before_height, not_after_height)` with `recent_block_height <= not_before_height < not_after_height` and `not_after_height <= issuer_name_expiry_at_issuance` for sealed grants. Admission at `tip == not_after_height` refuses `GRANT_WINDOW_CLOSED`. Optional `min_depth` (`1..144`, defaults to `1`) specifies the issuer's minimum required anchor/seal confirmation depth.
- **Two revocation modes:**
  1. **`revocation.mode = "seal"` (Standard Default):** Names `construction ("W" | "L")`, `kind ("revocable" | "single_use")`, and confirmed `seal: {txid, vout, script_policy}`. Anchored via `OP_RETURN 0x01` (or Merkle batch `0x02` with `MerkleProof`) committing `typed_digest(seallink-issuance/1)` (`loc = 0x00` default). Spending a `revocable` seal closes the grant at mempool speed (`SEAL_SPENT`). A `single_use` seal MUST use `ScriptPolicy` template `single_use_1_of_2` and follows the branch-aware state machine in `SPEC-02 §6.2`.
  2. **`revocation.mode = "window_only"` (Root-Only Zero-Tx Ephemeral Mode):** Strictly permitted ONLY on **root** grants without `delegate` (`parent` and `delegate` MUST be absent), with `not_after_height - not_before_height <= 12` blocks. Requires zero ledger transactions. **Executors MUST refuse `window_only` by default (`GRANT_SEAL_REQUIRED`)** unless local executor policy explicitly opts in for that action and budget tier. Emergency rotation/removal of the issuer's `link.grant` (`NAME_ROLE_CHANGED`) still terminates all live `window_only` grants immediately.

### 1.5 Text-vs-Effect Invariant (`SL-GRNT-005`, `decided`)

A grant MAY carry optional `terms_text` solely to guide cognitive work (e.g., `agent/brief`). Any mechanical effect executor (`mail/*`, `agent/tool`, `agent/session`, wallets, locks, name updaters, blob stores) **MUST** refuse any grant containing `terms_text` (`GRANT_TEXT_FORBIDDEN`).

---

## 2. Invocations (`seallink-invocation/1`) and Signed Receipts (`seallink-receipt/1`)

### 2.1 Signed Invocation and Acyclic Single-Use Delivery (`SL-GRNT-006`, `decided`)

Every execution request is a canonical JCS `seallink-invocation/1` (`<= 1 MiB`) signed by the final grant's recipient (`SignatureSet`):

- Binds `network`, `genesis`, concrete `executor {name, key}`, exact `action`, `target`, closed typed `arguments` (validated against the owning profile schema), optional `content_salt` (`SPEC-05 §3`), `proof_path` (1 entry for root grant, 2 entries `[parent, child]` for delegated child grant, each optionally carrying `issuance_txid` and `batch_proof`), 32-byte CSPRNG `nonce`, and wall-clock half-open window `[iat, exp)` (`iat <= now < exp`, no grace, `INVOKE_TIME_INVALID`).
- **Acyclic single-use consumption (`0x11`):** `seallink-invocation/1` NEVER embeds `use_txid`. For a `single_use` grant:
  1. The grantee constructs and signs `seallink-invocation/1`, computing `invocation_content_addr = SHA256(canonical_JCS(invocation))`.
  2. The grantee broadcasts `T_use` spending the `single_use_1_of_2` seal via branch `0` (`grantee`, `SIGHASH_ALL`) with `OP_RETURN 0x11` (`SINGLE_USE_CONSUMPTION`) committing `invocation_content_addr`.
  3. The grantee delivers `(seallink-invocation/1, use_txid = txid(T_use))` in the transport envelope alongside inline grant/contract/manifest bytes. The executor verifies `T_use` on its own chain view (`SPEC-02 §6.2`).
- **Signed arguments are sole authority:** The executor MUST derive effect parameters strictly from `payload.arguments` (never from transport headers or unsigned wrapper fields) and evaluate every `where` predicate (`SL-WIRE-016`) against `payload.arguments` (`INVOKE_CONSTRAINT_FAILED`).

### 2.2 Quota Accounting, Reservation, and Settlement (`SL-GRNT-007`, `decided`)

1. **Reserve before effect (atomic dual-account multi-quota batch):** Before executing any effect, the executor MUST compute the profile-defined maximum debit for every quota key consumed by the action (exact integer/rational arithmetic, never binary64) and atomically check and reserve across **both** accounts for a delegated child grant — the child grant's `own` account keyed by `(account="own", grant_id=child_grant_id, quota_kind, resource, unit, window, bucket_id)` **and** the parent's per-row `row` account keyed by `(account="row", grant_id=parent_grant_id, row_ordinal=child.parent.ordinal, quota_kind, resource, unit, window, bucket_id)` (bounded by the group template row ceiling — strictly isolated per `row_ordinal` so sibling rows sharing one executor never collide, and never charging the parent's `own` account) — plus operator ceilings (`QUOTA_EXCEEDED`). Both `account` and (when `account = "row"`) `row_ordinal` MUST be persisted in `FencedJournal` `reservation` and `settlement` entries and restored identically on replay. If ANY quota key or account in the batch fails, the entire reservation batch MUST abort leaving all balances and the journal unchanged. A zero ceiling authorizes nothing; missing required quota refuses.
2. **Window modes:**
   - `term`: cumulative across `[not_before_height, not_after_height)`.
   - `blocks:<N>`: half-open block buckets `[not_before_height + k*N, not_before_height + (k+1)*N)`.
   - `seconds:<S>`: UTC epoch-aligned buckets `[floor(now/S)*S, (floor(now/S)+1)*S)` guarded by a durable per-key monotonic clock watermark (`QUOTA_CLOCK_REGRESSION`).
3. **Settlement (Actual Charge and Release):** Once an effect completes with a known actual debit, the executor writes a `settlement` journal entry per reserved `(account, [row_ordinal], quota_key, bucket_id)` charging the exact actual debit (exact integer/rational arithmetic rounded upward once per request, zero binary64) and releasing the unused reservation difference (`reserved = settled + released`). On restart replay, every reservation lacking a matching settlement remains unsettled until reconciled.
4. **Uncertain outcomes:** If an effect outcome is uncertain (timeout, crash, network split), the full reservation MUST be retained until operator/protocol reconciliation; the executor reports `outcome = "uncertain"` and MUST NOT silently refund or allow replay.
5. **Idempotency and Replay:** Request identity is `invocation_id = SHA256(canonical_JCS(invocation.payload))` (excluding `signatures`). A repeated identical `invocation_id` MUST perform no second effect; the executor returns its stored signed receipt or refuses `INVOKE_REPLAY` per profile. A reused `nonce` with a different payload MUST refuse `INVOKE_REPLAY`.

### 2.3 Signed Receipt (`SL-GRNT-008`, `decided`)

Every executor answers with a `seallink-receipt/1` (`<= 65536` bytes, `schemas/invocation.schema.json`) signed by its pinned `receipt` key (`executor.key`), recording `invocation_id`, `grant_id`, `action`, `outcome ("executed" | "refused" | "uncertain")`, optional `refusal_code`, `settlements[]`, optional `result_sha256`, and observation `(tip_height, tip_hash, recorded_at)`. Each entry in `settlements[]` (`maxItems: 64`, supporting full lossless reporting of up to 32 capability quotas across both `own` and `row` accounts within the 64 KiB envelope ceiling) MUST specify `account ("own" | "row" | "session")`, `row_ordinal` (REQUIRED iff `account = "row"`, FORBIDDEN otherwise), `kind`, `resource`, `unit`, `window`, `reserved`, `settled`, and `released`. Callers MUST verify receipts solely against their pinned `executor.key`.

---

## 3. Bounded Depth-2 Re-Delegation

A root `seallink-grant/1` MAY authorize bounded child grants by including `delegate` (`SL-GRNT-009`, `decided`). Maximum authority path depth is **2** (root -> child; children MUST NOT carry `delegate` and MUST use `revocation.mode = "seal"` bound to `delegate.child_seal_key`, `GRANT_NOT_DELEGABLE`).

1. **Separated delegation and child-seal keys:**
   - `delegate.key` (`xonly_64hex`) signs child grants ONLY (disjoint from issuer, recipient, and messaging keys; held in an isolated delegation signing service enforcing at-most-one signature per row, `guides/GUIDE-01-custody-and-signers.md`).
   - `delegate.child_seal_key` (`compressed_66hex`) controls the issuer revocation branch of every child grant's seal (held outside the delegation signer so the delegator can revoke children even if the delegation signer is compromised).
2. **Grouped rows, row coins, and pairwise disjointness (`R8.6`):**
   - `delegate.groups` holds `1..16` groups; each group pairs a `template` (concrete `executor`, closed `recipient_rule` (`exact_key | exact_name | member_class`), `capabilities[]`, and `notary_mode`) with `1..16` `ranges` of `1..4096` pre-confirmed P2WPKH row coins (confirmed `<= parent.recent_block`).
   - **Disjoint coin ranges (`R8.6`):** Every `(txid, vout)` across ALL row ranges and ALL stop-coin ranges across ALL groups in `delegate.groups`, as well as the parent's own `seal` and linkage output, MUST be pairwise disjoint (`GRANT_ROW_INVALID`).
   - Global 1-based `ordinal` enumerates rows in signed group/range order. A child naming `parent: {grant_id, ordinal}` MUST have its issuance anchor (`0x01` or `0x02`) spend the exact row coin for `ordinal` (`GRANT_ROW_INVALID`), enforcing on chain that at most one child per row exists.
3. **Whole-parent aggregate budget (`R8.5`) and mechanical child narrowing (`SL-GRNT-010`, `decided`):**
   Every verifier MUST check BOTH the whole parent allocation AND the individual child:
   - **Whole-parent budget sum (`R8.5`):** For every quota key `q = (kind, resource, unit, window)` appearing in any group template's `capabilities[].quotas`, let `rows(g) = sum(r.count for r in g.ranges)` and `cap(g, q)` be the maximum ceiling for `q` in group `g`'s template (summed across capabilities in `g` that share `q`). Using exact integer arithmetic (overflow -> `GRANT_CHILD_WIDER`), the verifier MUST confirm a matching pool entry `pool_max(q)` exists in `delegate.pools` and:
     ```text
     sum over all groups g of (rows(g) * cap(g, q)) <= pool_max(q)
     ```
     Failure refuses `GRANT_CHILD_WIDER`. *(This invariant prevents sibling rows at different executors from exceeding the parent's total budget.)*
   - **Child-within-parent check:**
     - `C.genesis == P.genesis`, `C.contract_id == P.contract_id` (if present), `C.executor == template.executor`, and `C.revocation.mode == "seal"` with issuer branch controlled by `P.delegate.child_seal_key`;
     - `[C.not_before_height, C.not_after_height) ⊆ [P.not_before_height, P.not_after_height)`;
     - Every capability in `C.capabilities` mechanically narrows a capability in `template.capabilities` under the 7-predicate Constraint Algebra (`SL-WIRE-017`), and every child quota `<=` the template's row cap;
     - `C.recipient` satisfies `template.recipient_rule` (`exact_key` matches `mode="key"`; `exact_name` matches `mode="name"` with equal `name` and `owner_policy`; `member_class` checks live unspent membership of `C.recipient` in at least one pinned operator's confirmed `seallink-members-list/1`).
4. **Optional notary and stop coins (`SL-GRNT-011`, `decided`):**
   - `"none"` (default): mechanical narrowing under `SL-GRNT-010` requires no notary.
   - `"optional_stop"`: range specifies confirmed P2WPKH stop coins controlled by a pinned notary; spending a stop coin permanently closes that row for cause across all verifiers (`GRANT_ROW_STOPPED`).
   - `"required_act"`: additionally requires a verified `seallink-notary/1` (`act_kind = "child-within-parent"`) act (`NOTARY_REQUIRED`).

---

## 4. Deterministic Admission Order (Invocation Pipeline)

An executor MUST evaluate an incoming `seallink-invocation/1` in this exact 12-step order, returning the **first** failure (`SL-GRNT-012`, `decided`). Early recipient authentication runs strictly **before** cached-receipt lookup and blockchain RPCs to prevent unauthenticated DoS, cached-receipt harvesting, and state-oracle leakage:

1. **Invocation wire check (`SPEC-01 §7`):** Parse and verify `seallink-invocation/1` syntax, JCS, closed schema, profile argument schema, keys, and self-consistent `SignatureSet` -> `WIRE_*`
2. **Early local request checks (pre-chain):**
   - 2a. Wall-clock half-open window `iat <= now < exp` -> `INVOKE_TIME_INVALID`
   - 2b. `invocation.executor` equals this executor's pinned `(name, receipt_key)` -> `GRANT_EXECUTOR_MISMATCH`
3. **Presented bundle wire, early recipient authentication, and replay check (pre-chain):**
   - 3a. Wire pipeline on presented grant(s), optional contract(s), and optional manifest(s) -> `WIRE_*`
   - 3b. If leaf grant uses `recipient.mode = "key"` or `"group"`, verify `invocation.signatures.policy` equals `grant.recipient` immediately -> `WIRE_SIGNATURE` *(runs before any cached-receipt lookup so forged callers cannot probe or retrieve cached receipts)*
   - 3c. For `key` and `group` recipients (whose authentication succeeded in Step 3b): check local journal replay/nonce table. If `invocation_id` already has a stored terminal receipt, return that cached receipt (or `INVOKE_REPLAY` if profile forbids cached return). If `invocation_id` has an unsettled `reservation` (crash inside the external-effect window before receipt persistence), return `outcome = "uncertain"` while retaining the reservation and executing zero second effect. If `nonce` was already used for a different `invocation_id`, refuse `INVOKE_REPLAY`. *(For `recipient.mode = "name"`, this identical replay/crash-recovery check runs immediately after Step 11a once the recipient's on-chain key is verified.)*
4. **Consistent chain observation (`SPEC-02 §4`):** Check in strict order:
   - 4a. Chain/genesis pin -> `CHAIN_MISMATCH`
   - 4b. Reading node health (`!IBD`, `txindex=1`, header lag `<= LAG`) -> `CHAIN_UNHEALTHY`
   - 4c. Independent comparison peer veto -> `CHAIN_NODE_DISAGREEMENT`
   - 4d. Monotonic UTC clock watermark and header future bound `S` -> `CHAIN_CLOCK_ERROR`
   - 4e. Action risk-class tip freshness (`tip_age`) -> `CHAIN_TIP_STALE`
5. **Journal continuity (`§6`):** Check external CAS witness readability, local store readability, and `journal_id` match (`JOURNAL_LOST`), then active `write_token` (`JOURNAL_FENCED`), then position/commitment continuity (`JOURNAL_LOST`)
6. **Durable closure check:** Check local closure journal for every grant ID, contract ID, framework ID, issuer role, and row in `proof_path`, in strict order:
   - 6a. Closed grant or ancestor grant -> `INVOKE_REPLAY` if closed specifically by `SINGLE_USE_CONSUMED` (for a new `invocation_id`), else `GRANT_CLOSED`
   - 6b. Stopped row -> `GRANT_ROW_STOPPED`
   - 6c. Closed issuer role -> `NAME_ROLE_CHANGED`
   - 6d. Closed seal -> `SEAL_SPENT`
7. **Issuer identity, origin, and guardianship (`SPEC-03`, `SPEC-04`):**
   - 7a. Resolve root issuer name (`NAME_NOT_FOUND`), liveness (`NAME_EXPIRED`), history walk availability (`NAME_HISTORY_UNAVAILABLE`), `SIGHASH_ALL` writer check (`NAME_WRITER_UNVERIFIED`), `owner_policy` match (`NAME_OWNER_MISMATCH`), 520B name value grammar (`NAME_VALUE_INVALID`). For autonomous issuers (no verified ward origin): verify `link.grant` continuity (`NAME_ROLE_CHANGED`), verify `issuer.role_policy` matches `link.grant` and equals `root_grant.signatures.policy` (`WIRE_SIGNATURE`).
   - 7b. If origin-certified (`link.origin` or pinned origin): check in strict order: `origin/1` validity & trust (`ORIGIN_UNVERIFIED`), `name-binding/1` validity (`ORIGIN_BINDING_INVALID`), `status_seal` and `roster_seal` completeness (`ORIGIN_STATUS_INCOMPLETE`), subject end (`SUBJECT_ENDED`), pending emancipation transfer (`GUARDIAN_TRANSFER_PENDING`), calendar majority time boundary (`GUARDIAN_TIME_BOUNDARY`); if `ward`, enforce `SL-ORIG-006` order (`WARD_AUTONOMOUS_FORBIDDEN`, then `GUARDIAN_INACTIVE`, then `WIRE_SIGNATURE`, then `GUARDIAN_QUORUM_UNMET`).
8. **Contract and framework checks (`SPEC-05`):** Check in strict order: action requires contract (`GRANT_CONTRACT_REQUIRED`); if `contract_id` present: presentation (`CONTRACT_NOT_PRESENTED`), ID recomputation (`CONTRACT_ID_MISMATCH`), party assents (`CONTRACT_ASSENT_INVALID`), confirmed seal presence & `ScriptPolicy` match (`CONTRACT_SEAL_MISSING`), seal spend (`SEAL_SPENT`) or inconclusive seal (`SEAL_UNAVAILABLE`), disclosed `machine_clause_indices` & window nesting (`CONTRACT_TERMS_MISMATCH`), runtime `config_sha256` if required (`CONTRACT_CONFIG_MISMATCH`).
9. **Re-delegation checks (depth 2, `§3`):** Check in strict order: parent delegation rights & depth `<= 2` (`GRANT_NOT_DELEGABLE`), whole-parent R8.5 aggregate pool sum (`GRANT_CHILD_WIDER`), R8.6 disjointness & ordinal row coin spend (`GRANT_ROW_INVALID`), stop coin live (`GRANT_ROW_STOPPED`), optional notary act (`NOTARY_REQUIRED`), child `signatures.policy` equals `parent.delegate.key` (`WIRE_SIGNATURE`), mechanical child narrowing against group template (`GRANT_CHILD_WIDER`).
10. **Grant window, revocation / single-use seal, and executor binding:**
    - 10a. Grant height window `[not_before_height, not_after_height)` -> `GRANT_WINDOW_CLOSED`
    - 10b. If `revocation.mode = "window_only"`: enforce `not_after_height - not_before_height <= 12` (`WIRE_INTEGER`), then executor opt-in policy (`GRANT_SEAL_REQUIRED`)
    - 10c. If `revocation.mode = "seal"`: verify issuance `0x01`/`0x02` frame & Merkle proof (`CHAIN_FRAME_INVALID`), `recent_block` recency (`CHAIN_RECENCY_INVALID`), Witness `W` construction (`CHAIN_TX_CONSTRUCTION`), anchor depth (`CHAIN_DEPTH_INSUFFICIENT`); then evaluate seal:
      - `revocable` (`SPEC-02 §6.1`): `revoked` -> write closure + `SEAL_SPENT`; `unavailable` -> `SEAL_UNAVAILABLE`
      - `single_use` (`SPEC-02 §6.2`): `awaiting_spend` -> `SEAL_UNAVAILABLE`; `revoked` -> write closure + `SEAL_SPENT`; `pending_confirm` -> `CHAIN_DEPTH_INSUFFICIENT`; `consumed` with distinct `invocation_id` -> `INVOKE_REPLAY`
    - 10d. Verify `executor` or resolve `executor_ref`: forbid `executor_ref` if the grant includes `delegate`, uses `single_use`, carries any `quotas`, or declares any capability in `grant.capabilities[]` with `external_mutation = true` or `allows_executor_ref = false` (`GRANT_EXECUTOR_REF_FORBIDDEN`; evaluated strictly against `grant.capabilities[]` so unauthorized `invocation.action` values reach Step 11b `INVOKE_ACTION_DENIED`); verify holder's confirmed manifest (`MANIFEST_UNAVAILABLE`, then `MANIFEST_MISMATCH`, then `MANIFEST_ROLLBACK`), confirm provider `NamePin` binding (`SERVICE_PROVIDER_UNBOUND`) and provider `owner_policy` (`NAME_OWNER_MISMATCH`), confirm resolved `(name, receipt_key)` matches this executor (`GRANT_EXECUTOR_MISMATCH`)
11. **Named recipient, action, text ban, and constraints:**
    - 11a. If leaf grant uses `recipient.mode = "name"`, resolve recipient name (`NAME_NOT_FOUND`), check liveness (`NAME_EXPIRED`), check `owner_policy` (`NAME_OWNER_MISMATCH`), verify `invocation.signatures.policy` against its authorized request key (`WIRE_SIGNATURE`), and then execute the Step 3c local journal replay / crash-recovery check (`INVOKE_REPLAY`, cached receipt, or `uncertain`)
    - 11b. Action supported and present in `grant.capabilities` (`INVOKE_ACTION_DENIED`)
    - 11c. Mechanical effect text ban (`GRANT_TEXT_FORBIDDEN`)
    - 11d. Target match and 7-predicate `where` evaluation against `invocation.arguments` (`INVOKE_CONSTRAINT_FAILED`)
12. **Pre-effect recheck and atomic reservation:** Re-bracket chain tip (`CHAIN_OBSERVATION_VOID`, then `CHAIN_TIP_STALE`) and re-check live seals (`SEAL_SPENT`), verify seconds-window monotonic clock (`QUOTA_CLOCK_REGRESSION`), atomically write `nonce` + `reservation` entries to fenced journal (`QUOTA_EXCEEDED`, then `JOURNAL_FENCED`, then `JOURNAL_LOST`)

---

## 5. Bearer Sessions for Non-Signing Clients (`seallink-session-open/1`)

When a client harness cannot sign per-request invocations (e.g., an SDK accepting only a base URL and bearer token), an executor MAY support short-lived sessions (`SL-GRNT-013`, `decided`):

1. Recipient's key holder sends a signed `seallink-session-open/1` (`<= 16384` bytes, `op = "open" | "extend" | "close"`) with `slot_binding`, bounded `quotas <= grant.quotas`, and `exp <= now + 3600` (at most 1 hour ahead).
2. Executor runs the full admission pipeline (`§4`), binds a 32-byte CSPRNG bearer token (storing ONLY `SHA256(token)` in its journal), and returns the token once over a local socket or mutually authenticated encrypted channel.
3. **Every unsigned in-session request** MUST re-run live chain observation, seal checks, and recipient channel-key checks before reserving from `(grant, row, session)` accounts (`SESSION_INVALID` on mismatch, expiry, or any link closure).
4. Unsigned in-session requests lack per-request non-repudiation and retry idempotency; executors MUST NOT enable bearer sessions for wallets, name updates, or irreversible financial transfers.

---

## 6. Anti-Rollback Fenced Journals (`seallink-journal-entry/1`)

Every stateful SealLink verifier/executor (tracking closures, single-use consumption, quota reservations, nonces, and manifest heads) MUST guard against backup-restore and equal-position forks using a hash-chained journal + external CAS witness (`SL-GRNT-014`, `decided` state machine / `open` witness wire transport in `OPEN-QUESTIONS.md`):

1. **Hash chain:** Random 32-byte `journal_id`; commitment `c(0) = H_tag("seallink-journal/1", journal_id)`, `c(n) = H_tag("seallink-journal/1", c(n-1) || canonical_JCS(entry_n))`. Every `entry_n` MUST validate against the closed discriminated `JournalEntry` schema (`schemas/invocation.schema.json`) with `entry_n.pos == n` and `entry_n.prev_commitment == c(n-1)`.
2. **External witness:** An append-only CAS register stored strictly outside the local store's backup domain, holding `(journal_id, pos, commitment, write_token)`. Only `advance(journal_id, token, pos, from_commit, to_commit)` mutates it; fencing strictly increments `write_token`.
3. **Write order:** Check continuity -> durably write local entry -> `advance` external witness -> execute effect.
4. **Continuity precedence:** (1) witness readable, (2) local store readable, (3) matching `journal_id` -> else `JOURNAL_LOST`; (4) active `write_token` held -> else `JOURNAL_FENCED` (checked before position comparison so partitioned replicas fence cleanly); (5) `store.pos == witness.pos` and equal commitment (`Intact`), or `store.pos == witness.pos + 1` with matching `prev_commitment` (`Pending` completion), else `JOURNAL_LOST`.
5. **Attended recovery (start anew):** Record `recovery` entry with `fenced_at`, wait for a confirmed ledger block `boundary` whose `header_time > fenced_at + 7200s` (exceeding Namecoin's +2h future-header consensus bound to prove the block was accepted after fencing), and conservatively treat all pre-fencing uncertain reservations as consumed.
6. **Restart state reconstruction:** Every completed non-single-use invocation that promises a cached terminal receipt on idempotent retry (including quota-free invocations such as `agent/guardian-message` or `executor_ref` reads) MUST commit a terminal `settlement` journal entry (`settled: "0"`, `released: "0"`, `outcome`, `receipt_sha256`, `recorded_at`, omitting optional quota fields when no quota was reserved) alongside its `nonce` entry; single-use invocations record `receipt_sha256` on `single-use-consumed`. Replaying committed journal entries after a restart MUST deterministically restore not only the hash-chain commitment, closures, nonces, and per-account (`own` / per-`row_ordinal` `row`) quota balances, but also: (a) monotonic per-quota clock watermarks (`quota_watermarks[qkey] = max(recorded_at)`) from committed `reservation` and `settlement` entries for every `seconds:*` window so post-restart clock rollbacks still refuse `QUOTA_CLOCK_REGRESSION`; and (b) the idempotent cached receipt index (`invocation_id -> receipt`) for both quota-bearing and quota-free invocations by resolving `settlement.receipt_sha256` and `single-use-consumed.receipt_sha256` against the executor's durable content-addressed receipt store (verifying `content_addr(blob) == receipt_sha256`).

---

## 7. Security Considerations

- **No cross-executor quota sharing:** Two independent executors MUST NEVER spend from one apparent grant quota; split budgets across separate concrete-executor grants or parent row groups verified under R8.5.
- **Closure write failure:** If writing a newly observed `SEAL_SPENT` closure to the journal fails, the verifier MUST refuse admission and halt further admission for that seal until durable storage recovers.
- **`window_only` containment:** Executors opting into root `window_only` MUST enforce low per-grant and global operator ceilings so a compromised `grant` key's damage is bounded even before an emergency name update propagates.

---

## 8. References

- **Normative:** [RFC8785], [BIP-340], [BIP-141], [JSON-SCHEMA-2020-12].
- **Informative:** [RFC8448].
