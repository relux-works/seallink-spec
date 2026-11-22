# SPEC-04: Origin Certificates, Legal Capacity, and Multi-Guardian Quorums

- **Version:** `1.0.0-draft.2`
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
3. Two conflicting trusted origin certificates for one registration MUST refuse (`ORIGIN_UNVERIFIED`). Absence of an origin certificate yields class `unverified`.
4. **Pre-registration issuance:** `seallink-origin/1` is signed and anchored *before* name registration (`h_origin < h_firstupdate`), identifying the subject by `subject_initial_key` and committing `claims.intended_name` and `claims.intended_owner_policy`.
5. **Privacy of birth and initial guardians:** `seallink-origin/1` MUST NOT store plaintext `majority_unix` or plaintext initial guardian names:
   - `claims.majority_commitment` *(optional)* commits to `{"majority_unix": T}` using salted selective disclosure with an independent 32-byte CSPRNG salt (`SL-WIRE-014`).
   - Each `guardian_policy.slots[i].initial_guardian_commitment` commits to the initial guardian's complete `NamePin` (`{name, registration, owner_policy}`) using salted selective disclosure with its own independent 32-byte CSPRNG salt (`SL-WIRE-014`). Initial activation (`0x12`) opens `(salt_i, initial_guardian_NamePin)` and verifies exact commitment equality.
6. **Authenticated status discovery and continuation (`status_seal`):** `seallink-origin/1` MUST pin a confirmed `status_seal` (controlled by `capacity_authority` / end authority). Any verifier checking current status walks the status spine from `origin.status_seal` on its own node:

| Current Spine State | Observed Spend of Current `status_seal` | Next Spine State | Verifier Action |
| --- | --- | --- | --- |
| `initial` | Unspent at tip and no valid spend in mempool. | `initial` (`ward` if `guardian_policy` present, else `autonomous`) | Continue verification. |
| `initial` | Confirmed `0x09` matching presented `seallink-capacity/1` (`issuer` verified at anchor height) creating `next_status_policy` at `next_status_vout`. | `emancipated` (successor `status_seal = (T_cap, next_status_vout)`) | Continue walking from `(T_cap, next_status_vout)`; require confirmed handover transfer (`SL-ORIG-011`). |
| `initial` or `emancipated` | Confirmed `0x09` matching presented `seallink-end/1` (`issuer` verified at anchor height). | `ended` (terminal; no successor seal) | Durably close all guardianship slots and refuse `SUBJECT_ENDED`. |
| `initial` or `emancipated` | Spent in mempool or block without matching presented `capacity/1` or `end/1`, or malformed `next_status_vout` / invalid issuer. | `incomplete` | Fail closed with `ORIGIN_STATUS_INCOMPLETE`. |

7. **Eternal validity & compromise cutoff:** Verified against `issuer.role_policy` (`link.cred`) **at `h_origin`**, surviving routine key rotation and name expiry, provided `h_origin < h_c` under any `0x0b` compromise break (`CRED_ISSUER_CLOSED`). Issuer services MUST enforce durable idempotency by `request_sha256`.

### 2.2 Single-Use Name Binding (`SL-ORIG-003`, `decided`)

1. `seallink-origin/1` names a pre-created single-use `binding_seal`.
2. After `OP_NAME_FIRSTUPDATE` confirms at `h_firstupdate > h_origin` with output matching `intended_owner_policy`, the registrar spends `binding_seal` (`SIGHASH_ALL`) with `OP_RETURN 0x0c` committing `id(seallink-name-binding/1)` naming `(origin_id, seq=1, name, registration, owner_policy)`.
3. The subject's name value writes `"link": {"origin": "<origin_id_64hex>"}` (`SL-IDEN-003`). Removing or altering `link.origin` in a later update NEVER unbinds an already confirmed registration.
4. **Reverse uniqueness:** A registration already bound to one `origin_id` MUST refuse any second initial binding (`ORIGIN_BINDING_INVALID`).

---

## 3. Multi-Guardian Slots, Closed Event Classes, and Slot Transitions

### 3.1 Revision-Denominated Quorums and Verifier-Derived `event_class` (`SL-ORIG-004`, `SL-ORIG-005`, `decided`)

1. `origin.guardian_policy` initializes `revision = 1`, `revision_size = N` (`1 <= N <= 32`), explicit compressed secp256k1 ECDSA keys **`disposer_pk`**, independent **`arbiter_pk`** (`arbiter_pk != disposer_pk`), and pre-activation **`challenger_pk`** (`CompressedPubkey66`; institutional multi-custodian roles use threshold ECDSA tracked under `OQ-007`), `roster_seal` (`both_of_2(disposer_pk, arbiter_pk)`), `appointment_delay_blocks`, a closed 4-class `QuorumMap`, and `slots[1..N]` (each beginning in `initial_vacant` with `vacant_utxo` locked by `both_of_2(disposer_pk, arbiter_pk)`).
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

1. **Rational quorum bounds:** For every entry `{num, den, min}` in `quorums`, `1 <= num <= den <= 32` and `1 <= min <= revision_size` MUST hold (`WIRE_INTEGER` on violation).
2. **Exact slot coverage:** `len(slots) == revision_size`, all `slot` numbers MUST be distinct, and the set of slot numbers MUST equal `{1, ..., revision_size}` (`WIRE_INTEGER` on violation).
3. **Key independence and script binding:** `disposer_pk != arbiter_pk` MUST hold (`ORIGIN_UNVERIFIED` on violation). `roster_seal.script_policy` and every `vacant_utxo` / `new_vacant_policy` MUST compile to `both_of_2(disposer_pk, arbiter_pk)`. Every Stage 1 `pending_policy` MUST compile to `guardian_slot_pending` with `disposer == active_roster.disposer_pk`, `challenger == active_roster.challenger_pk`, `guardian == guardian_seal_pk`, and `delay_blocks == effective_delay_blocks >= origin.guardian_policy.appointment_delay_blocks` (`CHAIN_SCRIPT_UNSUPPORTED` on script/key mismatch; `GUARDIAN_INACTIVE` on delay shortfall). Every `active_policy` MUST compile to `either_of_2(guardian_seal_pk, active_roster.disposer_pk)`.
4. **Term ceiling against majority:** For a human ward (`origin_class = "person"`) whose `claims.majority_commitment` is opened to `{"majority_unix": T}`, every `seallink-guardian/1` carrying a `calendar` term MUST satisfy `term.not_after_unix <= T` (`GUARDIAN_INACTIVE` on violation).

### 3.3 Protocol-Level Ward Non-Autonomy (`SL-ORIG-006`, `decided`)

While a subject is in `ward` status (verified `origin/1` with `guardian_policy` present and no completed emancipation), every verifier evaluating a `seallink-grant/1` or `seallink-assent/1` for that subject MUST enforce this exact refusal precedence:

1. Missing `payload.guardian_context` or carrying top-level `signatures` instead of `guardian_approvals[]` -> **`WARD_AUTONOMOUS_FORBIDDEN`**
2. `payload.guardian_context.origin_id` or `ward_name` mismatch -> **`ORIGIN_UNVERIFIED`**
3. `payload.guardian_context.revision` mismatch with latest effective roster revision, OR any `guardian_approvals[i].revision != payload.guardian_context.revision` -> **`GUARDIAN_QUORUM_UNMET`**
4. For each entry in `guardian_approvals[]` (strictly ascending `slot`, checked at wire step -> `WIRE_SIGNATURE`): slot not in active roster, slot state != `active`, active guardian name != `entry.guardian_name`, calendar/ceiling term expired, or two approving slots resolve to the same `(name, registration)` -> **`GUARDIAN_INACTIVE`**
5. Approving guardian's `entry.signatures.policy` does not equal that guardian's resolved `link.grant` policy at tip, or BIP-340 verification fails -> **`WIRE_SIGNATURE`**
6. `payload.guardian_context.event_class != derived_class`, OR count of distinct satisfied slots `< required(derived_class)` -> **`GUARDIAN_QUORUM_UNMET`**

### 3.4 Initial Activation (`0x12`), Acyclic Two-Stage Appointment (`0x0d`/`0x0e`), and Slot State Machine (`SL-ORIG-007`, `decided`)

To eliminate `txid <-> hash` cycles, preserve privacy of initial guardians, and eliminate indefinite challenger vetoes, slot activation supports two explicit modes in `seallink-guardian/1` (`activation_mode`):

1. **Initial Slot Activation (`activation_mode = "initial"`, `0x12`):**
   - Each slot declared in `origin.guardian_policy.slots[i]` begins in state **`initial_vacant`** at `vacant_utxo` (`both_of_2(disposer_pk, arbiter_pk)`).
   - To activate initial guardian `G_init` without delay: the presenter opens `(salt_i, initial_guardian_NamePin)` verifying `commit(salt_i, initial_guardian_NamePin) == origin.guardian_policy.slots[i].initial_guardian_commitment` (`SL-WIRE-014`); `G_init` signs `seallink-assent/1` (`target_type = "seallink-guardian/1"`); and `issuer` signs `seallink-guardian/1` with `activation_mode = "initial"`, `revision = 1`, `prev_outpoint = vacant_utxo`, `active_vout`, and `active_policy = either_of_2(guardian_seal_pk, disposer_pk)`.
   - Both `disposer_pk` and `arbiter_pk` co-sign one PSBT spending `vacant_utxo` (`both_of_2`), creating `active_policy` at `active_vout`, and anchoring `content_addr(seallink-guardian/1)` in `OP_RETURN 0x12` (`GUARDIAN_INITIAL_ACTIVATION`).
   - Once confirmed at `h_init` (`T_init`), the live active slot seal is deterministically **`(T_init, active_vout)`**. `activation_mode = "initial"` is permitted ONLY from `initial_vacant` at `revision = 1`; appointing ANY successor MUST use `activation_mode = "appointed"` below.
2. **Stage 1 — Successor Appointment (`activation_mode = "appointed"`, `0x0d`, creates `pending_delay`):**
   - Incoming guardian `G_new` signs `seallink-assent/1` (`target_type = "seallink-guardian/1"`).
   - Appointing authority (`issuer.role_policy`, verified against `link.cred` at `h_app`) signs the **acyclic** `seallink-guardian/1` with `activation_mode = "appointed"`, committing `prev_outpoint` (the `vacant` or `initial_vacant` UTXO), `pending_vout`, `pending_policy` (`guardian_slot_pending` with `{disposer: active_roster.disposer_pk, challenger: active_roster.challenger_pk, guardian: guardian_seal_pk}` and `delay_blocks = effective_delay_blocks`), and `active_policy` (`either_of_2(guardian_seal_pk, active_roster.disposer_pk)`).
   - Both `disposer_pk` and `arbiter_pk` co-sign one PSBT spending `prev_outpoint` (`both_of_2`), creating `pending_policy` at `pending_vout`, and anchoring `content_addr(seallink-guardian/1)` in `OP_RETURN 0x0d`.
   - Once confirmed at `h_app` with txid `T_app`, the pending slot outpoint is deterministically **`(T_app, pending_vout)`**. During `[h_app, h_app + delay_blocks)`, the slot has zero authority; `disposer_pk` or `challenger_pk` MAY spend `(T_app, pending_vout)` to veto the appointment.
3. **Stage 2 — Activation (`0x0e`, removes challenger veto permanently):**
   - At height `H >= h_app + delay_blocks`, `G_new` spends `(T_app, pending_vout)` via the CSV-unlocked `<guardian>` branch (`SIGHASH_ALL`), creating `active_policy` (`either_of_2(guardian_seal_pk, active_roster.disposer_pk)`) at output `vout = 0`, and anchoring `id(seallink-guardian/1)` in `OP_RETURN 0x0e`.
   - Once confirmed at `h_act` with txid `T_act`, the live active slot seal is deterministically **`(T_act, 0)`**. `challenger_pk` is absent from `active_policy` and has zero power once activated.
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
2. The `0x0f` transaction creates `next_roster_policy` (`both_of_2(new_disposer_pk, new_arbiter_pk)`) at `next_roster_vout`, creates any `new_vacant` slot UTXOs at their declared `new_vacant_vout` indices, and anchors `content_addr(seallink-guardian-roster/1)` via `OP_RETURN 0x0f`.
3. `payload.revision` MUST equal `prev_revision + 1`, and `payload` MUST satisfy all `SL-ORIG-016` invariants (`len(slots) == revision_size`, `1 <= num <= den`, `1 <= min <= revision_size`, `disposer_pk != arbiter_pk`).
4. The new roster takes effect after `effective_delay_blocks` confirmations (`>= origin.guardian_policy.appointment_delay_blocks`). While `roster_seal` is spent and `seallink-guardian-roster/1` is not presented (or fails verification), verifiers fail closed with `ORIGIN_STATUS_INCOMPLETE`.
5. **Issuer-key survival (`SL-ORIG-008`, `decided`):** Both `seallink-guardian/1` and `seallink-guardian-roster/1` verify `issuer.role_policy` (`link.cred`) **at their confirmed anchor height**, bounded by `0x0b` (`h_c`), so routine issuer key rotation never orphans wards.

---

## 4. Guardianship Terms: Indefinite vs. Calendar Time

| Subject / Mode | `term` Form | Termination Rule (`SL-ORIG-009`, `decided`) |
| --- | --- | --- |
| **Agent / Indefinite** | `{"mode":"indefinite"}` | Lives until slot seal spend, verified `seallink-capacity/1`, verified `seallink-end/1`, or compromise cutoff `h_c`. |
| **Human Minor / Calendar** | `{"mode":"calendar","not_after_unix":T,"ceiling_height":H_max}` | Guardianship ends automatically at calendar majority `T` (bounded by `T <= opened majority_unix` per `SL-ORIG-016`, and never exceeding `H_max`, which is a failsafe ceiling and never extends past `T`). |

**Asymmetric Safety Rule at Majority Boundary (`SL-ORIG-010`, `open` time-interval oracle profile; safety rule `decided`):**
Block intervals drift by weeks over 18 years; chain median time past (MTP) is an auxiliary necessary constraint (`MTP < T` for guardian admission), never sufficient alone.
- Guardian admission is allowed ONLY if the entire credible UTC interval `[t_low, t_high]` lies strictly below `T` (and tip is fresh under `SPEC-02`).
- Independent adult admission requires `t_low >= T` plus confirmed emancipation transfer (`SL-ORIG-011`).
- If `[t_low, t_high]` straddles `T`, tip is stale, or the credible interval cannot be established, admission pauses for BOTH sides (`GUARDIAN_TIME_BOUNDARY`). *(The normative trusted time-interval oracle profile is tracked in `OPEN-QUESTIONS.md`.)*

---

## 5. Ward Admission State Machine, Emancipation, and Subject End

### 5.1 Four Ward Admission States (`SL-ORIG-011`, `decided`)

A verifier evaluating any action for an origin-certified actor walks `origin/1`, `status_seal`, `roster_seal`, `binding_seal`, and active slot seals:

| State | Condition | Permitted Admission |
| --- | --- | --- |
| **1. Under Guardianship** | `status_seal` unspent (no `capacity/1` or `end/1`); unexpired; active slot(s) at latest effective roster `revision` satisfy `required(derived_event_class)` via `guardian_approvals[]`; confirmed name binding matches current `owner_policy`. | Actions authorized by guardian quorum (and separate service grant where required). |
| **2. Guardianship Halted** | Not emancipated, but active slots cannot meet `required(derived_event_class)` (halted, vacant, pending, or `contested_burned`). | None (`GUARDIAN_INACTIVE` if cited slot is inactive; `GUARDIAN_QUORUM_UNMET` if valid active slots fall below `required`). |
| **3. Transfer Pending** | Calendar `T` reached OR verified `seallink-capacity/1` spent `status_seal`, but name output has NOT yet been confirmed-transferred to `subject_new_owner_policy` with subject's own `SIGHASH_ALL` name update. | None for either side (`GUARDIAN_TRANSFER_PENDING`). Name renewal, revocation, and handover transfer remain allowed. |
| **4. Autonomous** | `capacity/1` (+ `t_low >= T` for human) verified, confirmed name transfer to `subject_new_owner_policy`, confirmed subject-authored update, and binding line updated. | Full autonomous protocol admission; guardianship slots permanently `closed`. |

- **Emancipation rule:** Transferring a ward's name upon majority/emancipation MUST move the name UTXO to a fresh `ScriptPolicy` generated by the subject — never hand guardians' old shared key shares to the subject.
- **Subject End (`SL-ORIG-012`, `decided`):** An eternal `seallink-end/1` record spending `status_seal` terminally (`0x09`, creating no successor `status_seal`) permanently closes all guardianship slots and refuses all future admission (`SUBJECT_ENDED`). Silence or lost keys NEVER constitute proof of end.

---

## 6. Dual-Mode Name Recovery (`name_recovery`) and Seal Continuation

`seallink-origin/1` immutably declares one of two recovery policies at issuance (`SL-ORIG-013`, `decided`):

1. **`"mode": "none"` (Irreversible Binding):** No third party can ever re-bind `origin_id` to a new ledger name. Attempting recovery refuses `RECOVERY_FORBIDDEN`.
2. **`"mode": "dual_party_delayed"` (Governed Recovery):**
   - `origin/1` pins `disposer_pk`, independent `arbiter_pk` (`disposer_pk != arbiter_pk`), `delay_blocks >= 144` (recommended `>= 1008`), and a `both_of_2(disposer_pk, arbiter_pk)` `recovery_seal`.
   - To recover after catastrophic key loss, both `disposer_pk` and `arbiter_pk` co-sign a transaction `T_rec` spending the live `recovery_seal` with `OP_RETURN 0x0c` committing a new `seallink-name-binding/1` (`seq = prev_seq + 1`, naming the new confirmed registration, new `owner_policy`, `supersedes_binding_id`, AND continuation `next_recovery_vout` + `next_recovery_policy = both_of_2(disposer_pk, arbiter_pk)`).
   - Once `T_rec` confirms at `h_rec`, the live recovery seal advances to `(T_rec, next_recovery_vout)`. During `[h_rec, h_rec + delay_blocks)`, the previous binding stops admitting and the new binding sits in `pending_delay` (`RECOVERY_FORBIDDEN` for both bindings).
   - **Live-owner cancellation veto (`SL-ORIG-014`, `decided`):** At any block strictly prior to `h_rec + delay_blocks`, the existing name's current `owner_policy` MAY broadcast an owner-authored (`SIGHASH_ALL`) `OP_NAME_UPDATE` containing `OP_RETURN 0x10` (`RECOVERY_CANCEL`) committing `id(pending_name_binding/1)`. Observing confirmed `0x10` cryptographically proves the old keys are alive, permanently aborts the pending recovery (`RECOVERY_FORBIDDEN` for the cancelled binding), **immediately restores admission under the prior `NameBinding`**, and preserves the continued `recovery_seal` at `(T_rec, next_recovery_vout)` for any genuine future recovery.
   - Old grants bound to the old name/key NEVER carry over to a recovered name.

#### Recovery Seal State Transition Table

| Current State | Observed Chain Event | Next State | Admitted Binding |
| --- | --- | --- | --- |
| `active_binding(B_k)` | `recovery_seal` unspent. | `active_binding(B_k)` | `B_k` |
| `active_binding(B_k)` | Valid `0x0c` spend (`T_rec` at `h_rec`) creating `next_recovery_policy` at `next_recovery_vout` committing `B_{k+1}`. | `pending_recovery(B_{k+1})` (successor seal `(T_rec, next_recovery_vout)`) | None (`RECOVERY_FORBIDDEN` during delay). |
| `pending_recovery(B_{k+1})` | Owner-authored `SIGHASH_ALL` `OP_NAME_UPDATE` of `B_k.name` with `0x10` committing `id(B_{k+1})` confirmed at `< h_rec + delay_blocks`. | `active_binding(B_k)` (successor seal `(T_rec, next_recovery_vout)`) | **`B_k` restored immediately**; `B_{k+1}` permanently aborted (`RECOVERY_FORBIDDEN`). |
| `pending_recovery(B_{k+1})` | Tip reaches `H >= h_rec + delay_blocks` with no `0x10` cancel. | `active_binding(B_{k+1})` | **`B_{k+1}` active**; `B_k` permanently superseded (`ORIGIN_BINDING_INVALID`). |
| Any | Malformed spend of `recovery_seal` (missing `0x0c` or missing valid `next_recovery_vout`). | `incomplete` | Fail closed (`ORIGIN_STATUS_INCOMPLETE`). |

---

## 7. Security Considerations

- **Three-place key custody limit:** A `2-of-3` child name (`Parent A`, `Parent B`, `Notary`) survives any 1 lost share, but any 2 colluding holders can spend the name UTXO. Preventing both single-point loss and 2-party collusion requires `3-of-4` with an independent 4th custodian.
- **Name renewal obligation:** Over an 18-year childhood on Namecoin (`D = 36000`), guardians execute ~27–30 renewals. Off-chain agreements SHOULD define when the 3rd custodian co-signs renewals while keeping the on-chain script at full threshold (`SL-LDGR-006`).
- **Compromised issuer key:** Independent `arbiter_pk` requirements (`SL-ORIG-007`, `SL-ORIG-013`, `SL-ORIG-015`) prevent unilateral appointment, roster takeover, or name recovery; cold multisig `owner_policy` protects institutional issuers.

---

## 8. References

- **Normative:** [BIP-112], [BIP-141], [BIP-174], [BIP-340], [RFC8785].
- **Informative:** [RFC8448], [NC28].
