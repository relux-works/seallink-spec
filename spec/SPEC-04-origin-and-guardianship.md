# SPEC-04: Origin Certificates, Legal Capacity, and Multi-Guardian Quorums

- **Version:** `1.0.0-draft.7`
- **Status:** `draft` (core model and acyclic transitions `decided`; trusted calendar time-interval oracle profile remains `open` in `OPEN-QUESTIONS.md`)
- **Evidence / Maturity:** `vectors` (`vectors/trace-02-guardian-succession-assent.json`, `vectors/trace-04-agent-guardian-intake.json`, `vectors/refusal-coverage-matrix.json`)
- **Registries:** `registry/object-types.json`, `registry/opreturn-actions.json`, `registry/refusal-codes.json`
- **Schemas:** `schemas/origin.schema.json`, `schemas/guardian.schema.json`, `schemas/contract.schema.json`

---

## 1. The Three-Record Separation Model and Authenticated Status Spines

A single "who owns whom" record fails when a parent loses parental rights or an agent changes guardians, because a verifier must independently establish: (1) the origin certificate remains permanently authentic; (2) the ledger name still belongs to the subject; (3) the subject has neither emancipated nor ended; and (4) the presenting guardian(s) currently hold live slots meeting the event quorum.

SealLink therefore separates origin, status, binding, roster, and per-slot guardianship into cleanly linked UTXO-backed lines (`SL-ORIG-001`, `decided`):

| Record | Object Type | Anchor / UTXO Spine | Question Answered |
| --- | --- | --- | --- |
| **1. Origin Certificate** | `seallink-origin/1` | Eternal anchor `0x09` + declares `binding_seal`, `status_seal`, and optional `roster_seal` (`disposer_pk`, `arbiter_pk`, `challenger_pk`) | Who certified immutable `origin_class` (`person \| agent \| organization`), salted initial guardians, quorum policy, and `name_recovery`? |
| **2. Status Spine** | `seallink-capacity/1`, `seallink-end/1` | Spends `status_seal` with `0x09` (`capacity/1` continues spine via `next_status_vout`; `end/1` is terminal) | While `status_seal` is unspent, proves **neither emancipation nor subject end has occurred** without global chain scanning. |
| **3. Name Binding** | `seallink-name-binding/1` | Spends `binding_seal` (or `recovery_seal`, continuing via `next_recovery_vout`) with `0x0c` | Which ledger registration `(name, registration_outpoint)` and `owner_policy` belong to `origin_id`? |
| **4. Roster Revision** | `seallink-guardian-roster/1` | Spends `roster_seal` (`both_of_2(disposer_pk, arbiter_pk)`) with `0x0f` | What is the current approved `revision`, `revision_size`, role keys (`disposer_pk`, `arbiter_pk`, `challenger_pk`), and valid slot set (including recovery of burned slots)? |
| **5. Slot Guardianship** | `seallink-guardian/1` | Per-slot UTXO chain (`0x12` direct initial activation OR `0x0d` Stage 1 pending -> `0x0e` Stage 2 active) | Who occupies slot `i`, under what term, and is that slot active? |

**Identity permanence:** Identity rests on the eternal `origin_id` and its verifiable UTXO spines, not on the mutable ledger name string.

---

## 2. Origin Certificates, Privacy Commitments, and Status Spine (`seallink-origin/1`)

### 2.1 Origin-Certified Class and Private Commitments (`SL-ORIG-002`, `decided`)

1. Subject class (`person`, `agent`, `organization`) is established **solely** by a verified `seallink-origin/1` signed by an issuer `cred` policy trusted under local verifier policy.
2. Self-declared `seallink-card/1` fields prove nothing; if a card is present for a verified origin, `card.kind` MUST match `origin_class` (`ORIGIN_UNVERIFIED` on mismatch).
3. Two conflicting trusted origin certificates for one registration MUST refuse (`ORIGIN_UNVERIFIED`). Absence of an origin certificate yields class `unverified`. An `organization` origin MUST NOT declare `guardian_policy` (`WIRE_MEMBER`). Whenever `guardian_policy` is present, `name_recovery.mode` MUST be `"dual_party_delayed"` (`WIRE_MEMBER`), ensuring guardian key loss or refusal at majority can never permanently lock a ward's identity.
4. **Pre-registration issuance:** `seallink-origin/1` is signed and anchored *before* name registration (`h_origin < h_firstupdate`), identifying the subject by `subject_initial_key` and committing `claims.intended_name` and `claims.intended_owner_policy`. All seals declared in `origin/1` (`binding_seal`, `status_seal`, optional `roster_seal`, optional `recovery_seal`, and every `guardian_policy.slots[i].vacant_utxo`) MUST have pairwise-distinct outpoints, MUST be confirmed on the active chain, and MUST match their compiled `ScriptPolicy` (`ORIGIN_UNVERIFIED` / `CHAIN_SCRIPT_UNSUPPORTED` / `ORIGIN_STATUS_INCOMPLETE` otherwise).
5. **Privacy of birth and initial guardians:** `seallink-origin/1` MUST NOT store plaintext `majority_unix` or plaintext initial guardian names:
   - `claims.majority_commitment` *(REQUIRED for `origin_class = "person"` with `guardian_policy`; optional otherwise)* commits to `{"majority_unix": T}` using salted selective disclosure with an independent 32-byte CSPRNG salt (`SL-WIRE-014`). Whenever `claims.majority_commitment` is present in `origin/1`, verifiers MUST require off-chain disclosure `(salt, {"majority_unix": T})` matching the commitment before admitting any guardian action (`ORIGIN_STATUS_INCOMPLETE` if withheld or mismatched), so guardians cannot conceal majority by withholding the preimage.
   - Each `guardian_policy.slots[i].initial_guardian_commitment` commits to the initial guardian's complete `NamePin` (`{name, registration, owner_policy}`) using salted selective disclosure with its own independent 32-byte CSPRNG salt (`SL-WIRE-014`). Initial activation (`0x12`) opens `(salt_i, initial_guardian_NamePin)` and verifies exact commitment equality.
6. **Authenticated status discovery, exact authority pins, and continuation (`status_seal`):** `seallink-origin/1` MUST pin a confirmed `status_seal` whose controlling `ScriptPolicy` keys belong exclusively to the designated `capacity_authority` / `end_authority` (defaulting to `origin.issuer` when omitted). Every status-spine and guardianship record MUST match its authorized `NamePin` (`name`, `registration`, `owner_policy`) **exactly**:
   - `seallink-capacity/1` `issuer` MUST equal `origin.capacity_authority` (or `origin.issuer` if `capacity_authority` is omitted);
   - `seallink-end/1` `issuer` MUST equal `origin.end_authority` (or `origin.capacity_authority` if `end_authority` is omitted, or `origin.issuer` if both are omitted);
   - `seallink-guardian/1` and `seallink-guardian-roster/1` `issuer` MUST equal `origin.issuer` (or `origin.capacity_authority` when present).
   Any verifier checking current status walks the status spine from `origin.status_seal` on its own node (with bounded walk depth, default `256`, failing closed with `ORIGIN_STATUS_INCOMPLETE` if exhausted), verifying signatures against the authorized issuer's `link.cred` policy resolved at anchor height (bounded by `0x0b` `h_c`):

| Current Spine State | Observed Spend of Current `status_seal` | Next Spine State | Verifier Action |
| --- | --- | --- | --- |
| `initial` | Unspent at tip and no valid spend in mempool. | `initial` (`ward` if `guardian_policy` present, else `autonomous`) | Continue verification. |
| `initial` | Confirmed `0x09` (`>= required_depth`) matching presented `seallink-capacity/1` (exact authority `NamePin` verified at anchor height) creating `next_status_policy` at `next_status_vout`. | `emancipated` (successor `status_seal = (T_cap, next_status_vout)`) | Continue walking from `(T_cap, next_status_vout)`; require confirmed handover transfer (`SL-ORIG-011`). |
| `initial` or `emancipated` | Confirmed `0x09` (`>= required_depth`) matching presented `seallink-end/1` (exact authority `NamePin` verified at anchor height). | `ended` (terminal; no successor seal) | Durably close all guardianship slots and refuse `SUBJECT_ENDED`. |
| `initial` or `emancipated` | Spent in mempool or block (or `absent_from_utxo`) without matching presented `capacity/1` or `end/1`, or malformed `next_status_vout` / unauthorized issuer. | `incomplete` | Fail closed with `ORIGIN_STATUS_INCOMPLETE`. |

7. **Eternal validity & compromise cutoff:** Verified against `issuer.role_policy` (`link.cred`) **at `h_origin`**, surviving routine key rotation and name expiry, provided `h_origin < h_c` under any `0x0b` compromise break (`CRED_ISSUER_CLOSED`). Issuer services MUST enforce durable idempotency by `request_sha256`.

### 2.2 Single-Use Name Binding and History-Based Origin Detection (`SL-ORIG-003`, `decided`)

1. `seallink-origin/1` names a pre-created confirmed single-use `binding_seal` matching its compiled `ScriptPolicy`.
2. After `OP_NAME_FIRSTUPDATE` for `registration` confirms at `h_firstupdate > h_origin` with trailing output script matching `claims.intended_owner_policy`, the registrar spends `binding_seal` (`SIGHASH_ALL`) in a confirmed `OP_RETURN 0x0c` transaction (`>= required_depth`) committing `id(seallink-name-binding/1)` with `seq = 1`, `origin_id = id(origin/1)`, `network`/`genesis` matching local pin, `name == claims.intended_name`, `owner_policy == claims.intended_owner_policy`, and active `registration` (`ORIGIN_BINDING_INVALID` on any mismatch or unspent/malformed `binding_seal`).
3. The subject's name value writes `"link": {"origin": "<origin_id_64hex>"}` (`SL-IDEN-003`). **History-based permanent origin detection:** Verifiers MUST scan the entire confirmed update history of `registration` (from `OP_NAME_FIRSTUPDATE` through tip) for any `link.origin` pin — NEVER solely the tip name value. Removing or altering `link.origin` in a later update NEVER unbinds an already confirmed registration and MUST NOT allow a ward to bypass guardianship by erasing `link.origin` (`WARD_AUTONOMOUS_FORBIDDEN` / `ORIGIN_UNVERIFIED`).
4. **Reverse uniqueness:** A registration already bound to one `origin_id` MUST refuse any second initial binding (`ORIGIN_BINDING_INVALID`).

---

## 3. Multi-Guardian Slots, Closed Event Classes, and Slot Transitions

### 3.1 Revision-Denominated Quorums and Verifier-Derived `event_class` (`SL-ORIG-004`, `SL-ORIG-005`, `decided`)

1. `origin.guardian_policy` initializes `revision = 1`, `revision_size = N` (`1 <= N <= 32`), explicit **`BranchKeySpec`** institutional signers **`disposer_pk`**, independent **`arbiter_pk`** (`arbiter_pk != disposer_pk`, disjoint key sets), and pre-activation **`challenger_pk`** (each either a single `CompressedPubkey66` or a compact native `P2WSH` `m-of-n` multisig with `2 <= n <= 5`, `SPEC-02 §3.1`), `roster_seal` (`both_of_2(disposer_pk, arbiter_pk)`), `appointment_delay_blocks`, a closed 4-class `QuorumMap`, and `slots[1..N]` (each beginning in `initial_vacant` with `vacant_utxo` locked by `both_of_2(disposer_pk, arbiter_pk)`).
2. **Closed 4-class linear `GuardianEventClass` (verifier-derived — NEVER signer-chosen):** ONLY objects carrying `payload.guardian_context` (`seallink-grant/1` and `seallink-assent/1`) map to `GuardianEventClass`. The four classes form a strict linear order `routine_read < effect_grant < contract_assent < custody_change`. The verifier deterministically derives the required class from the object type, target, and capabilities (taking the highest matching class across all capabilities in a grant) and MUST verify `payload.guardian_context.event_class == derived_class` (`GUARDIAN_QUORUM_UNMET` on mismatch):

| `GuardianEventClass` | Normative Carrier Objects & Scope (Highest Matching Class Applies) |
| --- | --- |
| `routine_read` | Stateless read-only `seallink-grant/1` (`external_mutation = false`, no `quotas`, no `delegate`, not `single_use`, no `contract_id`, and NOT `agent/guardian-message`). |
| `effect_grant` | Unilateral `seallink-grant/1` (no `delegate`, no `contract_id`) with `quotas`, `external_mutation = true`, `single_use` revocation, OR action `agent/guardian-message` (`PROFILE-agent-v1`). |
| `contract_assent` | `seallink-assent/1` with `target_type = "seallink-contract/1"`, OR any contract-bound `seallink-grant/1` (`contract_id` present, without `delegate`). |
| `custody_change` | Delegating `seallink-grant/1` (`delegate` present), OR `seallink-assent/1` with `target_type = "seallink-migration/1"`. |

   *(Roster transitions `0x0f`, emancipation `seallink-capacity/1`, subject end `seallink-end/1`, and dual-party name recovery `0x0c` are governed directly by their dedicated on-chain seals and `issuer.role_policy` — never by `guardian_approvals[]` — so a deadlocked or burned guardian quorum never blocks institutional governance.)*
3. **Revision-denominated threshold (`SL-ORIG-005`):** For derived class `E` with quorum `{num, den, min}` from the active roster revision, required distinct valid guardian slots MUST be computed strictly against **`revision_size`** (NEVER against transient active slot count):
   ```text
   required(E) = max(min, ceil(num * revision_size / den))
   ```
4. **Distinct guardian rule:** Only an `autonomous` actor MAY hold a guardianship slot. Two slots MAY NOT simultaneously be held by the same `(name, registration)`. Each approving slot supplies its own independent `SignatureSet` inside `guardian_approvals[]` matching that guardian's resolved `link.grant` policy (`SL-WIRE-013`), so a multi-key guardian satisfies its own threshold independently and counts as at most one slot.

### 3.2 Guardianship Consistency Invariants (`SL-ORIG-016`, `decided`)

Every verifier validating `seallink-origin/1`, `seallink-guardian-roster/1`, or `seallink-guardian/1` MUST enforce these mechanical invariants:

1. **Rational quorum bounds & monotonicity:** For every entry `{num, den, min}` in `quorums`, `1 <= num <= den <= 32` and `1 <= min <= revision_size` MUST hold, AND derived thresholds MUST be monotonically non-decreasing across the linear class order: `required(routine_read) <= required(effect_grant) <= required(contract_assent) <= required(custody_change)` (`WIRE_INTEGER` on violation). *(Note: signed ward envelopes remain subject to per-type `max_bytes` — `65536`B for `seallink-grant/1` and `32768`B for `seallink-assent/1` — so deployments combining high `revision_size` with large per-guardian `ThresholdPolicy` sets MUST budget envelope size accordingly.)*
2. **Exact slot coverage & distinct outpoints:** `len(slots) == revision_size`, all `slot` numbers MUST be distinct, and the set of slot numbers MUST equal `{1, ..., revision_size}` (`WIRE_INTEGER` on violation). All seal outpoints declared across an origin certificate (`binding_seal`, `status_seal`, `roster_seal`, `recovery_seal`, and every `slots[i].vacant_utxo`) MUST be pairwise distinct (`ORIGIN_UNVERIFIED` on duplicate outpoint).
3. **Key independence, script binding, and delay floor:** `disposer_pk != arbiter_pk` (distinct canonical `BranchKeySpec` and disjoint compressed key sets) MUST hold on BOTH `guardian_policy` and `name_recovery` (`ORIGIN_UNVERIFIED` on violation). `roster_seal.script_policy`, `next_roster_policy`, and every `vacant_utxo` / `new_vacant_policy` MUST compile to `both_of_2(disposer_pk, arbiter_pk)`. Whenever a `seallink-guardian-roster/1` transition changes `disposer_pk` or `arbiter_pk` relative to the previous roster revision, `retain_active` and `retain_vacant` are **FORBIDDEN** — every slot in the new revision MUST use `new_vacant` locked to `both_of_2(new_disposer_pk, new_arbiter_pk)` (`CHAIN_SCRIPT_UNSUPPORTED` on violation). Every `seallink-guardian-roster/1` MUST satisfy `effective_delay_blocks >= origin.guardian_policy.appointment_delay_blocks` (`GUARDIAN_INACTIVE` / `ORIGIN_STATUS_INCOMPLETE` on shortfall), and no `0x0d` appointment spending a `new_vacant` output from a `0x0f` transition is valid before the roster takes effect (`h_app >= h_roster + effective_delay_blocks`, else `GUARDIAN_INACTIVE`). Every Stage 1 `pending_policy` MUST compile to `guardian_slot_pending` with `disposer == active_roster.disposer_pk`, `challenger == active_roster.challenger_pk`, `guardian == guardian_seal_pk`, and `delay_blocks == effective_delay_blocks >= origin.guardian_policy.appointment_delay_blocks` (`CHAIN_SCRIPT_UNSUPPORTED` on script/key mismatch; `GUARDIAN_INACTIVE` on delay shortfall). Every `active_policy` MUST compile to `either_of_2(guardian_seal_pk, active_roster.disposer_pk)`.
4. **Term ceiling against majority:** For a human ward (`origin_class = "person"`) whose `claims.majority_commitment` is opened to `{"majority_unix": T}`, every `seallink-guardian/1` carrying a `calendar` term MUST satisfy `term.not_after_unix <= T` (`GUARDIAN_INACTIVE` on violation).

### 3.3 Protocol-Level Ward Non-Autonomy (`SL-ORIG-006`, `decided`)

While a subject is in `ward` status (verified `origin/1` with `guardian_policy` present and no completed emancipation), every verifier evaluating a `seallink-grant/1` or `seallink-assent/1` for that subject MUST enforce this single canonical refusal precedence:

1. Missing `payload.guardian_context` or carrying top-level `signatures` instead of `guardian_approvals[]` -> **`WARD_AUTONOMOUS_FORBIDDEN`**
2. `payload.guardian_context.origin_id` or `ward_name` mismatch -> **`ORIGIN_UNVERIFIED`**
3. `payload.guardian_context.revision` mismatch with latest effective roster revision, OR any `guardian_approvals[i].revision != payload.guardian_context.revision` -> **`GUARDIAN_QUORUM_UNMET`**
4. For each entry in `guardian_approvals[]` (strictly ascending `slot`, checked at wire step -> `WIRE_SIGNATURE`): slot not in active roster, slot state != `active`, active guardian name != `entry.guardian_name`, calendar/ceiling term expired, approving guardian's own `(name, registration, owner_policy)` expired or failing writer-verified history, or two approving slots resolve to the same `(name, registration)` -> **`GUARDIAN_INACTIVE`**
5. Approving guardian's `entry.signatures.policy` does not equal that guardian's resolved `link.grant` policy at tip, or BIP-340 verification fails -> **`WIRE_SIGNATURE`**
6. `payload.guardian_context.event_class != derived_class`, OR count of distinct satisfied slots `< required(derived_class)` -> **`GUARDIAN_QUORUM_UNMET`**

**Intentional fail-safe halt on roster or guardian key change:** Live ward `seallink-grant/1` objects are evaluated against the **latest effective roster revision** and each approving guardian's **live `link.grant` policy at tip**. Consequently, any effective `0x0f` roster transition or rotation of an approving guardian's `link.grant` immediately halts prior ward grants (refusing `GUARDIAN_QUORUM_UNMET` or `WIRE_SIGNATURE`) and requires the new roster / updated guardian keys to reissue active operational grants. Concluded historical `seallink-contract/1` agreements remain governed by their contract seal and contract-assent policy (`SPEC-05 §2`).

### 3.4 Initial Activation (`0x12`), Acyclic Two-Stage Appointment (`0x0d`/`0x0e`), and Slot State Machine (`SL-ORIG-007`, `decided`)

To eliminate `txid <-> hash` cycles, preserve privacy of initial guardians, and eliminate indefinite challenger vetoes, slot activation supports two explicit modes in `seallink-guardian/1` (`activation_mode`):

1. **Initial Slot Activation (`activation_mode = "initial"`, `0x12`):**
   - Each slot declared in `origin.guardian_policy.slots[i]` begins in state **`initial_vacant`** at `vacant_utxo` (`both_of_2(disposer_pk, arbiter_pk)`).
   - To activate initial guardian `G_init` without delay: the presenter opens `(salt_i, initial_guardian_NamePin)` verifying `commit(salt_i, initial_guardian_NamePin) == origin.guardian_policy.slots[i].initial_guardian_commitment` (`SL-WIRE-014`); `G_init` signs `seallink-assent/1` (`target_type = "seallink-guardian/1"`); and `issuer` signs `seallink-guardian/1` with `activation_mode = "initial"`, `revision = 1`, `prev_outpoint = vacant_utxo`, `active_vout`, and `active_policy = either_of_2(guardian_seal_pk, disposer_pk)`.
   - Both `disposer_pk` and `arbiter_pk` co-sign one PSBT spending `vacant_utxo` (`both_of_2`), creating `active_policy` at `active_vout`, and anchoring `content_addr(seallink-guardian/1)` in `OP_RETURN 0x12` (`GUARDIAN_INITIAL_ACTIVATION`).
   - Once confirmed at `h_init` (`>= required_depth`) with txid `T_init` (verifying `prev_outpoint == slot.vacant_utxo` and `T_init` spends `prev_outpoint`), the live active slot seal is deterministically **`(T_init, active_vout)`**. `activation_mode = "initial"` is permitted ONLY from `initial_vacant` at `revision = 1`; appointing ANY successor MUST use `activation_mode = "appointed"` below.
2. **Stage 1 — Successor Appointment (`activation_mode = "appointed"`, `0x0d`, creates `pending_delay`):**
   - Incoming guardian `G_new` signs `seallink-assent/1` (`target_type = "seallink-guardian/1"`).
   - Appointing authority (`issuer.role_policy`, verified against `link.cred` at `h_app` with exact authority `NamePin` match) signs the **acyclic** `seallink-guardian/1` with `activation_mode = "appointed"`, committing `prev_outpoint` (MUST strictly equal the slot's current `vacant` or `initial_vacant` outpoint), `pending_vout`, `pending_policy` (`guardian_slot_pending` with `{disposer: active_roster.disposer_pk, challenger: active_roster.challenger_pk, guardian: guardian_seal_pk}` and `delay_blocks = effective_delay_blocks`), and `active_policy` (`either_of_2(guardian_seal_pk, active_roster.disposer_pk)`).
   - Both `disposer_pk` and `arbiter_pk` co-sign one PSBT spending `prev_outpoint` (`both_of_2`), creating `pending_policy` at `pending_vout`, and anchoring `content_addr(seallink-guardian/1)` in `OP_RETURN 0x0d`. If `prev_outpoint` originated as a `new_vacant` output of a `0x0f` roster transition at `h_roster`, `h_app >= h_roster + effective_delay_blocks` MUST hold (`GUARDIAN_INACTIVE` if premature).
   - Once confirmed at `h_app` (`>= required_depth`) with txid `T_app`, the pending slot outpoint is deterministically **`(T_app, pending_vout)`**. During `[h_app, h_app + delay_blocks)`, the slot has zero authority; `disposer_pk` or `challenger_pk` MAY spend `(T_app, pending_vout)` to veto the appointment.
3. **Stage 2 — Activation (`0x0e`, removes challenger veto permanently):**
   - At height `h_act >= h_app + delay_blocks`, `G_new` spends `(T_app, pending_vout)` via the CSV-unlocked `<guardian>` branch (`SIGHASH_ALL`, BIP-68 `nSequence >= delay_blocks`, with BOTH `OP_IF` witness selectors evaluating FALSE under Bitcoin Script `CastToBool` — rejecting disposer or challenger veto spends that masquerade as `0x0e`), creating `active_policy` (`either_of_2(guardian_seal_pk, active_roster.disposer_pk)`) at output `vout = 0`, and anchoring `id(seallink-guardian/1)` in `OP_RETURN 0x0e`.
   - Once confirmed at `h_act` (`>= required_depth`) with txid `T_act`, the live active slot seal is deterministically **`(T_act, 0)`**. `challenger_pk` is absent from `active_policy` and has zero power once activated.
4. **Fast Halt (1 party, mempool speed):** Either `guardian` resigns OR `disposer_pk` halts immediately by spending the active slot seal (`either_of_2`) to a fresh `vacant` UTXO locked by `both_of_2(disposer_pk, arbiter_pk)` (optionally carrying `0x0a` for-cause withdrawal, which bars re-appointment without a new ruling). First observation in mempool permanently terminates that guardian's authority (`GUARDIAN_INACTIVE` on ward actions; `SEAL_SPENT` on direct seal check).

#### Complete Slot State Transition Table

Because Namecoin lacks output covenants, a malicious spender could spend a slot UTXO to an invalid output script ("burning" the slot). Every possible spend is handled deterministically:

| Current State | Observed Spend / Event | Next State | Guardian Authority | Recovery Path |
| --- | --- | --- | :-: | --- |
| `initial_vacant` | Valid `0x12` tx (`both_of_2`) for disclosed `initial_guardian_commitment` + guardian assent creating `active_policy` at `active_vout`. | `active` (outpoint `(T_init, active_vout)`) | **Active** | Normal operation. |
| `initial_vacant` | Valid `0x0d` tx (`both_of_2`, `activation_mode = "appointed"`) creating `pending_policy` at `pending_vout`. | `pending_delay` (outpoint `(T_app, pending_vout)`) | None | Stage 2 after `delay_blocks`. |
| `initial_vacant` | Any other spend of `vacant_utxo`. | `contested_burned` | None | `seallink-guardian-roster/1` (`0x0f`). |
| `vacant` | Valid `0x0d` tx (`both_of_2`, `activation_mode = "appointed"`) creating `pending_policy` at `pending_vout`. | `pending_delay` (outpoint `(T_app, pending_vout)`) | None | Stage 2 after `delay_blocks`. |
| `vacant` | Any other spend (including `0x12`) of `vacant_utxo`. | `contested_burned` | None | `seallink-guardian-roster/1` (`0x0f`). |
| `pending_delay` | Spend by `disposer_pk` or `challenger_pk` before Stage 2. | `vetoed` (if recreated as `both_of_2` at `vout = 0` -> `vacant`, else `contested_burned`) | None | New `0x0d` or `0x0f` roster transition. |
| `pending_delay` | Valid `0x0e` tx (`<guardian>` CSV branch) creating `active_policy` at `vout = 0`. | `active` (outpoint `(T_act, 0)`) | **Active** | Normal operation. |
| `pending_delay` | Any malformed spend of `(T_app, pending_vout)`. | `contested_burned` | None | `seallink-guardian-roster/1` (`0x0f`). |
| `active` | Spend of active seal creating valid `both_of_2(disposer_pk, arbiter_pk)` at `vout = 0` (with optional `0x0a`). | `vacant` | **Ended** | New `0x0d` appointment. |
| `active` | Spend of active seal to ANY other script ("slot burn"). | `contested_burned` | **Ended** | `seallink-guardian-roster/1` (`0x0f`). |
| Any | `seallink-capacity/1` transfer completed OR `seallink-end/1` verified. | `closed` | **Ended** | Terminal. |

### 3.5 Roster Revision Transitions (`seallink-guardian-roster/1`, `0x0f`, `SL-ORIG-015`, `decided`)

To change approved `revision_size` (e.g., reducing `2 -> 1` when one parent loses parental rights, adding a slot, rotating `disposer_pk`/`arbiter_pk`/`challenger_pk`, updating `quorums`, or re-anchoring a `contested_burned` slot):

1. **Authorization without old-roster quorum:** Roster transitions are authorized strictly by `disposer_pk + arbiter_pk` co-signing a PSBT spending the current `roster_seal` (`both_of_2(disposer_pk, arbiter_pk)`), combined with `issuer.role_policy` (`link.cred`) signing `seallink-guardian-roster/1` and waiting `effective_delay_blocks`. They NEVER require signatures from the old guardian roster, ensuring deadlocked or burned rosters remain recoverable.
2. The `0x0f` transaction creates `next_roster_policy` (`both_of_2(new_disposer_pk, new_arbiter_pk)`) at `next_roster_vout`, creates any `new_vacant` slot UTXOs at their declared `new_vacant_vout` indices, and anchors `content_addr(seallink-guardian-roster/1)` via `OP_RETURN 0x0f`. Each slot entry in `slots[]` specifies one of three transition actions (each carried-forward outpoint from the immediately preceding revision MAY be referenced at most once, allowing deterministic slot renumbering when shrinking `revision_size`):
   - **`retain_active`:** Carries forward an unspent active slot outpoint `(active_outpoint, guardian_id)` that existed as an active slot in the immediately preceding revision (FORBIDDEN if `disposer_pk` or `arbiter_pk` changed, because the existing `either_of_2` output would still reference the retired `disposer_pk`).
   - **`retain_vacant`:** Carries forward an unspent vacant slot outpoint (`vacant_outpoint`) that existed as a vacant or initial-vacant slot in the immediately preceding revision (never an arbitrary UTXO; FORBIDDEN if `disposer_pk` or `arbiter_pk` changed, because the existing `both_of_2` output would still reference retired keys).
   - **`new_vacant`:** Creates a fresh `both_of_2(new_disposer_pk, new_arbiter_pk)` vacant slot UTXO at `(txid_0x0f, new_vacant_vout)` (REQUIRED for every slot whenever `disposer_pk` or `arbiter_pk` changes, and used to recover `contested_burned` slots or add new slots). **Operational consequence:** because rotating `disposer_pk` or `arbiter_pk` recreates all slots as `new_vacant`, the ward remains without active guardians (fail-closed) for at least one appointment delay window (`appointment_delay_blocks`) until successor appointments complete `0x0d -> 0x0e`.
3. `payload.revision` MUST equal `prev_revision + 1`, `payload.prev_roster_outpoint` MUST equal the spent previous roster outpoint, and `payload` MUST satisfy all `SL-ORIG-016` invariants (`len(slots) == revision_size`, `1 <= num <= den`, `1 <= min <= revision_size`, monotonic `QuorumMap`, `disposer_pk != arbiter_pk`, `effective_delay_blocks >= origin.guardian_policy.appointment_delay_blocks`, and no `retain_active` / `retain_vacant` when `disposer_pk` or `arbiter_pk` changes -> `CHAIN_SCRIPT_UNSUPPORTED`).
4. The new roster takes effect after `effective_delay_blocks` confirmations (`>= origin.guardian_policy.appointment_delay_blocks`). While `roster_seal` is spent and `seallink-guardian-roster/1` is not presented (or fails verification, or walk depth exceeds `256`), verifiers fail closed with `ORIGIN_STATUS_INCOMPLETE`.
5. **Issuer-key survival (`SL-ORIG-008`, `decided`):** Both `seallink-guardian/1` and `seallink-guardian-roster/1` verify `issuer.role_policy` (`link.cred`) **at their confirmed anchor height**, bounded by `0x0b` (`h_c`), so routine issuer key rotation never orphans wards.

---

## 4. Guardianship Terms: Indefinite vs. Calendar Time

| Subject / Mode | `term` Form | Termination Rule (`SL-ORIG-009`, `decided`) |
| --- | --- | --- |
| **Agent / Indefinite** | `{"mode":"indefinite"}` | Lives until slot seal spend, verified `seallink-capacity/1`, verified `seallink-end/1`, or compromise cutoff `h_c`. |
| **Human Minor / Calendar** | `{"mode":"calendar","not_after_unix":T,"ceiling_height":H_max}` | Guardianship ends automatically at calendar majority `T` (bounded by `T <= opened majority_unix` per `SL-ORIG-016`, and never exceeding `H_max`, which is a failsafe ceiling and never extends past `T`). |

**Asymmetric Safety Rule at Majority Boundary (`SL-ORIG-010`, `open` time-interval oracle profile; safety rule `decided`):**
Block intervals drift by weeks over 18 years; chain median time past (MTP) is an auxiliary necessary constraint (`tip.median_time_past < T` MUST hold for guardian admission), never sufficient alone.
- Guardian admission is allowed ONLY if the entire credible UTC interval `[t_low, t_high]` lies strictly below `T`, `tip.median_time_past < T`, `claims.majority_commitment` (when present) has been opened to `T`, and tip is fresh under `SPEC-02`.
- Independent adult admission on Path A requires `t_low >= T` plus confirmed emancipation handover (`SL-ORIG-011`).
- If `[t_low, t_high]` straddles `T`, `tip.median_time_past >= T` while `t_low < T`, tip is stale, or the credible interval cannot be established, admission pauses for BOTH sides (`GUARDIAN_TIME_BOUNDARY`). *(The normative trusted time-interval oracle profile is tracked in `OPEN-QUESTIONS.md`.)*

---

## 5. Ward Admission State Machine, Emancipation, and Subject End

### 5.1 Four Ward Admission States and Two Emancipation Paths (`SL-ORIG-011`, `decided`)

A verifier evaluating any action for an origin-certified actor walks `origin/1`, `status_seal`, `roster_seal`, `binding_seal`, and active slot seals:

| State | Condition | Permitted Admission |
| --- | --- | --- |
| **1. Under Guardianship** | `status_seal` unspent (no `capacity/1` or `end/1`); `majority_commitment` opened and `t_high < T` and `MTP < T` (if present); active slot(s) at latest effective roster `revision` satisfy `required(derived_event_class)` via `guardian_approvals[]`; confirmed name binding matches current `owner_policy`. | Actions authorized by guardian quorum (and separate service grant where required). |
| **2. Guardianship Halted** | Not emancipated, but active slots cannot meet `required(derived_event_class)` (halted, vacant, pending, or `contested_burned`). | None (`GUARDIAN_INACTIVE` if cited slot is inactive; `GUARDIAN_QUORUM_UNMET` if valid active slots fall below `required`). |
| **3. Transfer Pending** | Emancipation trigger reached — either **(Path A)** calendar majority `t_low >= T` for `person`, OR **(Path B)** verified `seallink-capacity/1` spent `status_seal` — but the name output has NOT yet been confirmed-transferred to a fresh subject `ScriptPolicy` (distinct from the prior guardian `owner_policy`, and equal to `capacity.subject_new_owner_policy` on Path B) with a confirmed subject-authored `SIGHASH_ALL` `OP_NAME_UPDATE`. | None for either side (`GUARDIAN_TRANSFER_PENDING`). Name renewal, revocation, handover transfer, and `dual_party_delayed` recovery (`0x0c`) remain allowed; **former guardians lose `0x10` recovery-cancel veto immediately upon entering State 3** so a hostile guardian cannot block handover recovery. |
| **4. Autonomous** | Either **(Path A)** `person` with opened `majority_commitment`, `t_low >= T`, confirmed transfer to fresh subject `ScriptPolicy` (distinct from ward `owner_policy`), and confirmed subject-authored `SIGHASH_ALL` update (NO `seallink-capacity/1` required); **OR (Path B)** confirmed `seallink-capacity/1` verified against `capacity_authority`/`issuer`, confirmed transfer to `subject_new_owner_policy`, and confirmed subject-authored `SIGHASH_ALL` update (or confirmed `dual_party_delayed` recovery to a fresh subject registration). | Full autonomous protocol admission; guardianship slots permanently `closed`. |

- **Emancipation rule:** Transferring a ward's name upon majority/emancipation MUST move the name UTXO to a fresh `ScriptPolicy` generated by the subject (strictly distinct from the ward's guardian `owner_policy`) — never hand guardians' old shared key shares to the subject.
- **Subject End (`SL-ORIG-012`, `decided`):** An eternal `seallink-end/1` record spending `status_seal` terminally (`0x09`, creating no successor `status_seal`) permanently closes all guardianship slots and refuses all future admission (`SUBJECT_ENDED`). Silence or lost keys NEVER constitute proof of end.

---

## 6. Dual-Mode Name Recovery (`name_recovery`) and Seal Continuation

`seallink-origin/1` immutably declares one of two recovery policies at issuance (`SL-ORIG-013`, `decided`):

1. **`"mode": "none"` (Irreversible Binding — autonomous/organization origins ONLY):** FORBIDDEN whenever `guardian_policy` is present (`WIRE_MEMBER`). No third party can ever re-bind `origin_id` to a new ledger name. Attempting recovery refuses `RECOVERY_FORBIDDEN`.
2. **`"mode": "dual_party_delayed"` (Governed Recovery):**
   - `origin/1` pins `disposer_pk`, independent `arbiter_pk` (`BranchKeySpec`, `disposer_pk != arbiter_pk`), `delay_blocks >= 144` (recommended `>= 1008`), and a `both_of_2(disposer_pk, arbiter_pk)` `recovery_seal`.
   - To recover after catastrophic key loss (or refusal by former guardians to execute a Path A / Path B emancipation handover), both `disposer_pk` and `arbiter_pk` co-sign a transaction `T_rec` spending the live `recovery_seal` with `OP_RETURN 0x0c` committing a new `seallink-name-binding/1` (`seq = prev_binding.seq + 1`, naming the new confirmed registration, new `owner_policy`, `supersedes_binding_id = id(prev_binding)`, AND continuation `next_recovery_vout` + `next_recovery_policy = both_of_2(disposer_pk, arbiter_pk)`).
   - Once `T_rec` confirms at `h_rec`, the live recovery seal advances to `(T_rec, next_recovery_vout)`. During `[h_rec, h_rec + delay_blocks)`, the previous binding stops admitting and the new binding sits in `pending_delay` (`RECOVERY_FORBIDDEN` for both bindings).
   - **Live-owner cancellation veto (`SL-ORIG-014`, `decided`):** At any block strictly prior to `h_rec + delay_blocks` — PROVIDED the origin is NOT in State 3 (`transfer_pending`) with former guardians locked out — the live binding `B_k`'s exact `(name, registration, owner_policy)` MAY broadcast an owner-authored (`SIGHASH_ALL`) `OP_NAME_UPDATE` containing `OP_RETURN 0x10` (`RECOVERY_CANCEL`) committing `id(pending_name_binding/1)`. Verifiers look up `0x10` strictly on `B_k.registration` (never an unrelated re-registration of the same spelling). Observing confirmed `0x10` cryptographically proves the old keys are alive, permanently aborts the pending recovery (`RECOVERY_FORBIDDEN` for the cancelled binding), **immediately restores admission under `B_k`**, and preserves the continued `recovery_seal` at `(T_rec, next_recovery_vout)` for any genuine future recovery.
   - Old grants bound to the old name/key NEVER carry over to a recovered name.

#### Recovery Seal State Transition Table

| Current State | Observed Chain Event | Next State | Admitted Binding |
| --- | --- | --- | --- |
| `active_binding(B_k)` | `recovery_seal` unspent. | `active_binding(B_k)` | `B_k` |
| `active_binding(B_k)` | Valid `0x0c` spend (`T_rec` at `h_rec`, `seq = k + 1`, `supersedes_binding_id = id(B_k)`) creating `next_recovery_policy` at `next_recovery_vout` committing `B_{k+1}`. | `pending_recovery(B_{k+1})` (successor seal `(T_rec, next_recovery_vout)`) | None (`RECOVERY_FORBIDDEN` during delay). |
| `pending_recovery(B_{k+1})` | Owner-authored `SIGHASH_ALL` `OP_NAME_UPDATE` of `B_k.registration` (not locked out by State 3 emancipation trigger) with `0x10` committing `id(B_{k+1})` confirmed at `< h_rec + delay_blocks`. | `active_binding(B_k)` (successor seal `(T_rec, next_recovery_vout)`) | **`B_k` restored immediately**; `B_{k+1}` permanently aborted (`RECOVERY_FORBIDDEN`). |
| `pending_recovery(B_{k+1})` | Tip reaches `H >= h_rec + delay_blocks` with no valid `0x10` cancel. | `active_binding(B_{k+1})` | **`B_{k+1}` active**; `B_k` permanently superseded (`ORIGIN_BINDING_INVALID`). |
| `active_binding(B_k)` | Malformed spend of `recovery_seal` (missing valid `0x0c` or missing valid `next_recovery_vout`), or `recovery_seal` absent from UTXO without valid `0x0c` record. | `recovery_burned` (active binding `B_k` preserved; no future recovery possible) | **`B_k` continues admitting normally**; any future recovery attempt refuses `RECOVERY_FORBIDDEN`. *(Prevents a malformed recovery spend from serving as an unvetoable kill switch against a live identity.)* |

---

## 7. Security Considerations

- **Three-place key custody limit:** A `2-of-3` child name (`Parent A`, `Parent B`, `Notary`) survives any 1 lost share, but any 2 colluding holders can spend the name UTXO. Preventing both single-point loss and 2-party collusion requires `3-of-4` with an independent 4th custodian.
- **Name renewal obligation:** Over an 18-year childhood on Namecoin (`D = 36000`), guardians execute ~27–30 renewals. Off-chain agreements SHOULD define when the 3rd custodian co-signs renewals while keeping the on-chain script at full threshold (`SL-LDGR-006`).
- **Compromised issuer key:** Independent `arbiter_pk` requirements (`SL-ORIG-007`, `SL-ORIG-013`, `SL-ORIG-015`) prevent unilateral appointment, roster takeover, or name recovery; institutional authorities SHOULD configure `BranchKeySpec` native `m-of-n` (`2 <= n <= 5`) or qualified threshold ECDSA for `disposer_pk`, `arbiter_pk`, `challenger_pk`, and cold multisig `owner_policy`.
- **Institutional DoS boundary on `status_seal`:** Because a non-`0x09` or malformed spend of `status_seal` transitions the status spine to terminal `incomplete`, a malicious or misconfigured holder of the `status_seal` key (`capacity_authority` / `end_authority`) can cause an institutional denial of service that fails safely closed (`ORIGIN_STATUS_INCOMPLETE`), halting future admission for that origin without enabling forged emancipation or forged subject end. Conversely, a malformed spend of `recovery_seal` burns only future recovery (`recovery_burned`) without killing the active binding `B_k`. Institutional authorities SHOULD guard `status_seal` keys with cold native `P2WSH` multisig or qualified threshold ECDSA custody.

---

## 8. References

- **Normative:** [BIP-112], [BIP-141], [BIP-174], [BIP-340], [RFC8785].
- **Informative:** [RFC8448], [NC28].
