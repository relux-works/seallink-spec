# SPEC-04: Origin Certificates, Legal Capacity, and Multi-Guardian Quorums

- **Version:** `1.0.0-draft.1`
- **Status:** `draft` (core model and acyclic transitions `decided`; trusted calendar time-interval oracle profile remains `open` in `OPEN-QUESTIONS.md`)
- **Evidence / Maturity:** `vectors` (`vectors/trace-02-guardian-succession-assent.json`)
- **Registries:** `registry/object-types.json`, `registry/opreturn-actions.json`, `registry/refusal-codes.json`
- **Schemas:** `schemas/origin.schema.json`, `schemas/guardian.schema.json`, `schemas/contract.schema.json`

---

## 1. The Three-Record Separation Model and Authenticated Status Spines

A single "who owns whom" record fails when a parent loses parental rights or an agent changes guardians, because a verifier must independently establish: (1) the origin certificate remains permanently authentic; (2) the ledger name still belongs to the subject; (3) the subject has neither emancipated nor ended; and (4) the presenting guardian(s) currently hold live slots meeting the event quorum.

SealLink therefore separates origin, status, binding, roster, and per-slot guardianship into cleanly linked UTXO-backed lines (`SL-ORIG-001`, `decided`):

| Record | Object Type | Anchor / UTXO Spine | Question Answered |
| --- | --- | --- | --- |
| **1. Origin Certificate** | `seallink-origin/1` | Eternal anchor `0x09` + declares `binding_seal`, `status_seal`, and optional `roster_seal` | Who certified immutable `origin_class` (`person \| agent \| organization`), salted initial guardians, quorum policy, and `name_recovery`? |
| **2. Status Spine** | `seallink-capacity/1`, `seallink-end/1` | Spends `status_seal` with `0x09` | While `status_seal` is unspent, proves **neither emancipation nor subject end has occurred** without global chain scanning. |
| **3. Name Binding** | `seallink-name-binding/1` | Spends `binding_seal` (or `recovery_seal`) with `0x0c` | Which ledger registration `(name, registration_outpoint)` and `owner_policy` belong to `origin_id`? |
| **4. Roster Revision** | `seallink-guardian-roster/1` | Spends `roster_seal` (`both_of_2(disposer, arbiter)`) with `0x0f` | What is the current approved `revision`, `revision_size`, and valid slot set (including recovery of burned slots)? |
| **5. Slot Guardianship** | `seallink-guardian/1` | Per-slot UTXO chain (`0x0d` Stage 1 pending -> `0x0e` Stage 2 active) | Who occupies slot `i`, under what term, and is that slot active? |

**Identity permanence:** Identity rests on the eternal `origin_id` and its verifiable UTXO spines, not on the mutable ledger name string.

---

## 2. Origin Certificates, Privacy Commitments, and Status Spine (`seallink-origin/1`)

### 2.1 Origin-Certified Class and Private Commitments (`SL-ORIG-002`, `decided`)

1. Subject class (`person`, `agent`, `organization`) is established **solely** by a verified `seallink-origin/1` signed by an issuer `cred` policy trusted under local verifier policy.
2. Self-declared `seallink-card/1` fields prove nothing; if a card is present for a verified origin, `card.kind` MUST match `origin_class` (`ORIGIN_UNVERIFIED` on mismatch).
3. Two conflicting trusted origin certificates for one registration MUST refuse (`ORIGIN_UNVERIFIED`). Absence of an origin certificate yields class `unverified`.
4. **Pre-registration issuance:** `seallink-origin/1` is signed and anchored *before* name registration (`h_origin < h_firstupdate`), identifying the subject by `subject_initial_key` and committing `claims.intended_name` and `claims.intended_owner_policy`.
5. **Privacy of birth and initial guardians:** `seallink-origin/1` MUST NOT store plaintext `majority_unix` or plaintext initial guardian names:
   - `claims.majority_commitment` *(optional)* commits to `{"majority_unix": T}` using salted selective disclosure (`SL-WIRE-014`).
   - Each `guardian_policy.slots[i].initial_guardian_commitment` commits to the initial guardian's complete `NamePin` (`{name, registration, owner_policy}`) using salted selective disclosure (`SL-WIRE-014`). Initial activation opens `(salt_i, initial_guardian_NamePin)` and verifies exact commitment equality.
6. **Authenticated status discovery (`status_seal`):** `seallink-origin/1` MUST pin a confirmed `status_seal` (controlled by `capacity_authority` / end authority). Any verifier checking current status inspects `status_seal` on its own node:
   - If `status_seal` is **unspent**, neither `seallink-capacity/1` nor `seallink-end/1` has occurred.
   - If `status_seal` is **spent**, the verifier inspects the spending transaction's `0x09` commitment and MUST refuse with **`ORIGIN_STATUS_INCOMPLETE`** unless the presenter supplies the matching `seallink-capacity/1` or `seallink-end/1` bytes (following the chained `next_status_vout` after `capacity/1`).
7. **Eternal validity & compromise cutoff:** Verified against `issuer.role_policy` (`link.cred`) **at `h_origin`**, surviving routine key rotation and name expiry, provided `h_origin < h_c` under any `0x0b` compromise break (`CRED_ISSUER_CLOSED`). Issuer services MUST enforce durable idempotency by `request_sha256`.

### 2.2 Single-Use Name Binding (`SL-ORIG-003`, `decided`)

1. `seallink-origin/1` names a pre-created single-use `binding_seal`.
2. After `OP_NAME_FIRSTUPDATE` confirms at `h_firstupdate > h_origin` with output matching `intended_owner_policy`, the registrar spends `binding_seal` (`SIGHASH_ALL`) with `OP_RETURN 0x0c` committing `id(seallink-name-binding/1)` naming `(origin_id, seq=1, name, registration, owner_policy)`.
3. The subject's name value writes `"link": {"origin": "<origin_id_64hex>"}` (`SL-IDEN-003`). Removing or altering `link.origin` in a later update NEVER unbinds an already confirmed registration.
4. **Reverse uniqueness:** A registration already bound to one `origin_id` MUST refuse any second initial binding (`ORIGIN_BINDING_INVALID`).

---

## 3. Multi-Guardian Slots, Closed Event Classes, and Two-Stage Transitions

### 3.1 Revision-Denominated Quorums and Verifier-Derived `event_class` (`SL-ORIG-004`, `SL-ORIG-005`, `decided`)

1. `origin.guardian_policy` initializes `revision = 1`, `revision_size = N` (`1 <= N <= 32`), `disposer`, independent `arbiter`, `roster_seal` (`both_of_2(disposer, arbiter)`), `appointment_delay_blocks`, a closed `QuorumMap` over all 5 canonical event classes, and `slots[1..N]`.
2. **Closed event-class table (verifier-derived — NEVER signer-chosen):** The verifier deterministically derives the required `GuardianEventClass` from the object type and capability flags (taking the highest class across all capabilities in a grant) and MUST verify `payload.guardian_context.event_class == derived_class` (`GUARDIAN_QUORUM_UNMET` on mismatch):

| `GuardianEventClass` | Normative Scope (Highest Matching Class Applies) |
| --- | --- |
| `routine_read` | Stateless read-only `seallink-grant/1` (`external_mutation = false`, no `quotas`, no `delegate`, not `single_use`) and read-only `seallink-session-open/1`. |
| `effect_grant` | `seallink-grant/1` with `quotas`, `external_mutation = true`, or `single_use` revocation (no `delegate`, no contract). |
| `contract_assent` | `seallink-assent/1` targeting `seallink-contract/1` or `seallink-migration/1`, or contract-bound `seallink-grant/1`. |
| `custody_change` | Delegating `seallink-grant/1` (`delegate` present), provider migration, name `owner_policy` / `link.*` changes, or device-list updates. |
| `governance_change` | `seallink-guardian-roster/1` transitions, early emancipation consent, or governed recovery initiation. |

3. **Revision-denominated threshold (`SL-ORIG-005`):** For derived class `E` with quorum `{num, den, min}` from the active roster revision, required distinct valid guardian slots MUST be computed strictly against **`revision_size`** (NEVER against transient active slot count):
   ```text
   required(E) = max(min, ceil(num * revision_size / den))
   ```
4. **Distinct guardian rule:** Only an `autonomous` actor MAY hold a guardianship slot. Two slots MAY NOT simultaneously be held by the same `(name, registration)`. A guardian whose own `link.grant` is a multi-key `ThresholdPolicy` counts as at most one slot signature after its own policy threshold is satisfied (`SL-WIRE-013`).

### 3.2 Protocol-Level Ward Non-Autonomy (`SL-ORIG-006`, `decided`)

While a subject is in `ward` status (verified `origin/1` with `guardian_policy` present and no completed emancipation):
- Every verifier MUST reject a `seallink-grant/1` or `seallink-assent/1` for that subject unless it carries `guardian_context` and satisfies `required(derived_event_class)` across distinct active slots (`WARD_AUTONOMOUS_FORBIDDEN`).

### 3.3 Acyclic Two-Stage Appointment, Activation, and Slot State Machine (`SL-ORIG-007`, `decided`)

To eliminate `txid ↔ hash` cycles AND eliminate indefinite challenger vetoes, appointing a guardian proceeds in **two explicit stages**:

1. **Stage 1 — Appointment (`0x0d`, creates `pending_delay`):**
   - Incoming guardian `G_new` signs `seallink-assent/1` (`target_type = "seallink-guardian/1"`).
   - Appointing authority (`issuer.role_policy`, verified against `link.cred` at `h_app`) signs the **acyclic** `seallink-guardian/1` committing `prev_outpoint` (the `vacant` UTXO), `pending_vout`, `pending_policy` (`guardian_slot_pending` with `{disposer, challenger, guardian}` and `delay_blocks = appointment_delay_blocks`), and `active_policy` (`either_of_2(guardian_seal_pk, disposer_seal_pk)`).
   - Both `disposer` and independent `arbiter` co-sign one PSBT spending `prev_outpoint` (`both_of_2`), creating `pending_policy` at `pending_vout`, and anchoring `content_addr(seallink-guardian/1)` in `OP_RETURN 0x0d`.
   - Once confirmed at `h_app` with txid `T_app`, the pending slot outpoint is deterministically **`(T_app, pending_vout)`**. During `[h_app, h_app + delay_blocks)`, the slot has zero authority; `disposer` or `challenger` MAY spend `(T_app, pending_vout)` to veto the appointment.
2. **Stage 2 — Activation (`0x0e`, removes challenger veto permanently):**
   - At height `H >= h_app + delay_blocks`, `G_new` spends `(T_app, pending_vout)` via the CSV-unlocked `<guardian>` branch (`SIGHASH_ALL`), creating `active_policy` (`either_of_2(guardian_seal_pk, disposer_seal_pk)`) at output `vout = 0`, and anchoring `id(seallink-guardian/1)` in `OP_RETURN 0x0e`.
   - Once confirmed at `h_act` with txid `T_act`, the live active slot seal is deterministically **`(T_act, 0)`**. `challenger` is absent from `active_policy` and has zero power once activated.
3. **Fast Halt (1 party, mempool speed):** Either `guardian` resigns OR `disposer` halts immediately by spending `(T_act, 0)` (`either_of_2`) to a fresh `vacant` UTXO locked by `both_of_2(disposer, arbiter)` (optionally carrying `0x0a` for-cause withdrawal, which bars re-appointment without a new ruling). First observation in mempool permanently terminates that guardian's authority (`SEAL_SPENT` / `GUARDIAN_INACTIVE`).
4. **Initial slot activation:** For an initial guardian committed in `origin.guardian_policy.slots[i].initial_guardian_commitment`, opening `(salt_i, initial_guardian_NamePin)` and presenting `G_init`'s signed `seallink-assent/1` permits spending `vacant_utxo` directly to `active_policy` at `vout = 0` (`effective_delay_blocks = 1` or immediate upon confirmation); appointing ANY successor MUST follow full Stage 1 + Stage 2 above.

#### Complete Slot State Transition Table

Because Namecoin lacks output covenants, a malicious spender could spend a slot UTXO to an invalid output script ("burning" the slot). Every possible spend is handled deterministically:

| Current State | Observed Spend / Event | Next State | Guardian Authority | Recovery Path |
| --- | --- | --- | :-: | --- |
| `vacant` | Valid `0x0d` tx (`both_of_2`) creating `pending_policy` at `pending_vout`. | `pending_delay` | None | Stage 2 after `delay_blocks`. |
| `vacant` | Any other spend of `vacant_utxo`. | `contested_burned` | None | `seallink-guardian-roster/1` (`0x0f`). |
| `pending_delay` | Spend by `disposer` or `challenger` before Stage 2. | `vetoed` (if recreated as `both_of_2` -> `vacant`, else `contested_burned`) | None | New `0x0d` or `0x0f` roster transition. |
| `pending_delay` | Valid `0x0e` tx (`<guardian>` CSV branch) creating `active_policy` at `vout = 0`. | `active` | **Active** | Normal operation. |
| `pending_delay` | Any malformed spend of `(T_app, pending_vout)`. | `contested_burned` | None | `seallink-guardian-roster/1` (`0x0f`). |
| `active` | Spend of `(T_act, 0)` creating valid `both_of_2(disposer, arbiter)` at `vout = 0` (with optional `0x0a`). | `vacant` | **Ended** | New `0x0d` appointment. |
| `active` | Spend of `(T_act, 0)` to ANY other script ("slot burn"). | `contested_burned` | **Ended** | `seallink-guardian-roster/1` (`0x0f`). |
| Any | `seallink-capacity/1` transfer completed OR `seallink-end/1` verified. | `closed` | **Ended** | Terminal. |

### 3.4 Roster Revision Transitions (`seallink-guardian-roster/1`, `0x0f`, `SL-ORIG-015`, `decided`)

To change approved `revision_size` (e.g., reducing `2 -> 1` when one parent loses parental rights, adding a slot, updating `quorums`, or re-anchoring a `contested_burned` slot):
1. Both `disposer` and independent `arbiter` co-sign a PSBT spending the current `roster_seal` (`both_of_2(disposer, arbiter)`), creating `next_roster_policy` (`both_of_2(disposer, arbiter)`) at `next_roster_vout`, creating any `new_vacant` slot UTXOs at their declared `new_vacant_vout` indices, and anchoring `content_addr(seallink-guardian-roster/1)` via `OP_RETURN 0x0f`.
2. `payload.revision` MUST equal `prev_revision + 1`, and `len(payload.slots)` MUST equal `payload.revision_size`.
3. The new roster takes effect after `effective_delay_blocks` confirmations (`>= origin.guardian_policy.appointment_delay_blocks`). While `roster_seal` is spent and `seallink-guardian-roster/1` is not presented, verifiers refuse `ORIGIN_STATUS_INCOMPLETE`.
4. **Issuer-key survival (`SL-ORIG-008`, `decided`):** Both `seallink-guardian/1` and `seallink-guardian-roster/1` verify `issuer.role_policy` (`link.cred`) **at their confirmed anchor height**, bounded by `0x0b` (`h_c`), so routine issuer key rotation never orphans wards.

---

## 4. Guardianship Terms: Indefinite vs. Calendar Time

| Subject / Mode | `term` Form | Termination Rule (`SL-ORIG-009`, `decided`) |
| --- | --- | --- |
| **Agent / Indefinite** | `{"mode":"indefinite"}` | Lives until slot seal spend, verified `seallink-capacity/1`, verified `seallink-end/1`, or compromise cutoff `h_c`. |
| **Human Minor / Calendar** | `{"mode":"calendar","not_after_unix":T,"ceiling_height":H_max}` | Guardianship ends automatically at calendar majority `T` (never exceeding `H_max`, which is a failsafe ceiling and never extends past `T`). |

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
| **1. Under Guardianship** | `status_seal` unspent (no `capacity/1` or `end/1`); unexpired; active slot(s) at latest effective roster `revision` satisfy `required(derived_event_class)`; confirmed name binding matches current `owner_policy`. | Actions authorized by guardian quorum (and separate service grant where required). |
| **2. Guardianship Halted** | Not emancipated, but active slots cannot meet `required(derived_event_class)` (halted, vacant, pending, or `contested_burned`). | None (`GUARDIAN_INACTIVE` or `GUARDIAN_QUORUM_UNMET`). |
| **3. Transfer Pending** | Calendar `T` reached OR verified `seallink-capacity/1` spent `status_seal`, but name output has NOT yet been confirmed-transferred to `subject_new_owner_policy` with subject's own `SIGHASH_ALL` name update. | None for either side (`GUARDIAN_TRANSFER_PENDING`). Name renewal, revocation, and handover transfer remain allowed. |
| **4. Autonomous** | `capacity/1` (+ `t_low >= T` for human) verified, confirmed name transfer to `subject_new_owner_policy`, confirmed subject-authored update, and binding line updated. | Full autonomous protocol admission; guardianship slots permanently `closed`. |

- **Emancipation rule:** Transferring a ward's name upon majority/emancipation MUST move the name UTXO to a fresh `ScriptPolicy` generated by the subject — never hand guardians' old shared key shares to the subject.
- **Subject End (`SL-ORIG-012`, `decided`):** An eternal `seallink-end/1` record spending `status_seal` terminally (`0x09`, creating no successor `status_seal`) permanently closes all guardianship slots and refuses all future admission (`SUBJECT_ENDED`). Silence or lost keys NEVER constitute proof of end.

---

## 6. Dual-Mode Name Recovery (`name_recovery`)

`seallink-origin/1` immutably declares one of two recovery policies at issuance (`SL-ORIG-013`, `decided`):

1. **`"mode": "none"` (Irreversible Binding):** No third party can ever re-bind `origin_id` to a new ledger name. Attempting recovery refuses `RECOVERY_FORBIDDEN`.
2. **`"mode": "dual_party_delayed"` (Governed Recovery):**
   - `origin/1` pins `disposer`, independent `arbiter`, `delay_blocks >= 144` (recommended `>= 1008`), and a `2-of-2 P2WSH` `recovery_seal`.
   - To recover after catastrophic key loss, both `disposer` and `arbiter` co-sign a transaction spending `recovery_seal` with `0x0c` committing a new `seallink-name-binding/1` (`seq = prev_seq + 1`, naming the new confirmed registration, new `owner_policy`, and `supersedes_binding_id`).
   - The previous name binding stops admitting immediately; the new binding enters `pending_delay` for `delay_blocks`.
   - **Live-owner cancellation veto (`SL-ORIG-014`, `decided`):** At any block prior to `h_rec + delay_blocks`, the existing name's current `owner_policy` MAY broadcast an owner-authored (`SIGHASH_ALL`) `OP_NAME_UPDATE` containing `OP_RETURN 0x10` (`RECOVERY_CANCEL`) committing `id(pending_name_binding/1)`. Observing `0x10` cryptographically proves the old keys are alive and permanently aborts that recovery (`RECOVERY_FORBIDDEN`).
   - Old grants bound to the old name/key NEVER carry over to the recovered name.

---

## 7. Security Considerations

- **Three-place key custody limit:** A `2-of-3` child name (`Parent A`, `Parent B`, `Notary`) survives any 1 lost share, but any 2 colluding holders can spend the name UTXO. Preventing both single-point loss and 2-party collusion requires `3-of-4` with an independent 4th custodian.
- **Name renewal obligation:** Over an 18-year childhood on Namecoin (`D = 36000`), guardians execute ~27–30 renewals. Off-chain agreements SHOULD define when the 3rd custodian co-signs renewals while keeping the on-chain script at full threshold (`SL-LDGR-006`).
- **Compromised issuer key:** Independent `arbiter` requirements (`SL-ORIG-007`, `SL-ORIG-013`, `SL-ORIG-015`) prevent unilateral appointment, roster takeover, or name recovery; cold multisig `owner_policy` protects institutional issuers.

---

## 8. References

- **Normative:** [BIP-112], [BIP-141], [BIP-174], [BIP-340], [RFC8785].
- **Informative:** [RFC8448], [NC28].
