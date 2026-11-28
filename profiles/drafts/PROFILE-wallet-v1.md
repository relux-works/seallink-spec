# PROFILE-wallet-v1: Grant-Gated Treasury, Coin Spending, and Multi-Account Budget Control

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — Reserved `open` standard service type (`registry/service-types.json`, `OPEN-QUESTIONS.md §3`); requires full SLIP + Draft 2020-12 schema + conformance vectors per `SPEC-07 §4.1` before promotion.
- **Service Type:** `wallet`

---

## 1. Security Invariants (Financial Hard Boundaries)

Wallet executors govern irreversible asset transfers and therefore enforce SealLink's strictest operational boundaries (`SPEC-06 §2.2`, `SPEC-06 §5`):
1. **Concrete `executor` ONLY:** `executor_ref` is strictly forbidden on all spend actions (`GRANT_EXECUTOR_REF_FORBIDDEN`).
2. **NO Bearer Sessions (`allows_bearer_session = false`):** Unsigned bearer tokens MUST NEVER authorize financial spends (`SESSION_INVALID`). Every spend requires a fresh signed `seallink-invocation/1` (optionally requiring hardware `fido2-es256`/`fido2-eddsa` `presence_attestation: "uv"`!).
3. **Mandatory UTXO Seal (`require_seal = true`, `window_only` FORBIDDEN):** Every spend grant requires a confirmed `revocable` or `single_use` (`0x11`) UTXO seal; large one-off disbursements SHOULD use `single_use_1_of_2`.
4. **Exact integer arithmetic (`uint64_str`) & `uncertain` retention:** Zero IEEE 754 floats; crash-in-broadcast outcomes retain the full reserved debit as `uncertain` until on-chain reconciliation confirms whether the tx was mined or double-spent.

---

## 2. Candidate Action Leaves & Orthogonal Flags (`SPEC-07 §4.1`)

| Action | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `allows_bearer_session` | `requires_contract` | `require_seal` | Risk Class |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `wallet/balance` | `false` | `true` | `false` | `true` | `true` | `false` | `false` | Class 2 (`5400s`) |
| `wallet/spend` | `true` | `false` | `true` | `false` | `false` | `false` | `true` | Class 1 (`3600s`) |
| `wallet/psbt-cosign` | `true` | `false` | `true` | `false` | `false` | `false` | `true` | Class 1 (`3600s`) |

- **Target grammar:** `^wallet:id/[a-z0-9][a-z0-9._-]{0,63}:[a-z0-9._-]{1,64}$` (e.g., `wallet:id/acme:ops-btc`).
- **Required quotas (`wallet/spend`, `wallet/psbt-cosign`):** `seallink/coins` (`sat` / `nmc_sat` / CAIP-2 atomic unit, `resource == target`, `window ∈ {"term", "blocks:<N>", "seconds:<S>"}`).
- **Candidate `where` predicates:** `asset_id` (`eq`/`in`), `destination` (`eq`/`in`/`prefix`), `amount_atomic` (`range`), `max_fee_atomic` (`range`), `memo_sha256` (`hash_eq`).
- **Mechanical `terms_text` ban:** All `wallet/*` actions refuse `terms_text` (`GRANT_TEXT_FORBIDDEN`).

---

## 3. Open SLIP Checklist Items (`SPEC-07 §4.1`)
1. Formal `schemas/profile-wallet.schema.json` covering asset IDs, exact fee + principal reservation formulas, and `result_sha256` binding broadcast `txid`.
2. Double-spend / RBF reconciliation rules for `uncertain` broadcast settlements (`SPEC-06 §2.2`).
3. Depth-2 delegated department budgets (`R8.5` whole-parent pool ceiling across multiple sub-wallets) + full conformance vectors.
