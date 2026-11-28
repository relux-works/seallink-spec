# PROFILE-rental-v1: Contract-Bound Physical and Digital Asset Leases

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — Reserved `open` standard service type (`registry/service-types.json`, `OPEN-QUESTIONS.md §3`); requires full SLIP + Draft 2020-12 schema + conformance vectors per `SPEC-07 §4.1` before promotion.
- **Service Type:** `rental`

---

## 1. Scope & Bilateral Contract Requirement

Governs physical smart locks (apartments, vehicles, lockers, workspaces) and leased digital infrastructure where the lessee assumes binding obligations (payment, care, return deadline) and cannot be unilaterally evicted without arbiter/mutual seal termination (`SPEC-05 §1`, `SPEC-05 §2.3`):

1. **Mandatory Bilateral Contract (`requires_contract = true`):** Every `rental/*` grant MUST bind a concluded `seallink-contract/1` (`GRANT_CONTRACT_REQUIRED` on unilateral grants) with disclosed `machine_clause_indices[]` matching the leased asset, lease window (`not_before_height`, `not_after_height`, calendar `not_after_unix`), and permitted actions.
2. **Arbiter-Protected Termination (`arbiter_or_both`):** Lease contracts SHOULD lock `contract.termination.seal` with `arbiter_or_both(lessor, lessee, arbiter)` so neither landlord nor tenant can unilaterally falsify termination during the active term (`SPEC-05 §2.3`); courts or arbitration panels record binding dispute outcomes via `seallink-notary/1 (act_kind = "contract-ruling")` (`SPEC-05 §5`) without exposing unrelated confidential contract clauses.
3. **Co-Tenant & Sub-Lease Support:** Multiple tenants share role `"tenant"` via unique `party_id` (`"tenant-1"`, `"tenant-2"`); optional sub-access (e.g., temporary guest/cleaner code with `not_after_unix`) uses depth-2 delegation (`SPEC-06 §3`).

---

## 2. Candidate Action Leaves & Orthogonal Flags (`SPEC-07 §4.1`)

| Action | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `allows_bearer_session` | `requires_contract` | `require_seal` | Risk Class |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `rental/unlock` | `true` | `false` | `true` | `false` | `false` | `true` | `true` | Class 1 (`3600s`) |
| `rental/access-log` | `false` | `true` | `false` | `false` | `false` | `true` | `true` | Class 2 (`5400s`) |
| `rental/checkin` | `true` | `false` | `true` | `false` | `false` | `true` | `true` | Class 1 (`3600s`) |

- **Target grammar:** `^rental:id/[a-z0-9][a-z0-9._-]{0,63}:[a-z0-9._-]{1,64}$` (e.g., `rental:id/smartlock-42:apt-3b`).
- **Hardware presence:** High-security locks MAY require recipient `fido2-es256`/`fido2-eddsa` with `presence_attestation: "up" | "uv"`.
- **Mechanical `terms_text` ban:** All `rental/*` actions refuse `terms_text` (`GRANT_TEXT_FORBIDDEN`).

---

## 3. Open SLIP Checklist Items (`SPEC-07 §4.1`)
1. Formal `schemas/profile-rental.schema.json` covering lock telemetry, offline-grace vs fail-closed emergency egress rules, and `result_sha256`.
2. Standard `contract-ruling` integration for early eviction / deposit escrow settlement.
3. Full conformance vectors (co-tenant `party_id` assents, arbiter termination `0x08`, `not_after_unix` expiry, `GRANT_CONTRACT_REQUIRED`).
