# PROFILE-names-v1: Delegated Update-Only Ledger Name Operations and Auto-Renewal Services

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — Reserved `open` standard service type (`registry/service-types.json`, `OPEN-QUESTIONS.md §3`); requires full SLIP + Draft 2020-12 schema + conformance vectors per `SPEC-07 §4.1` before promotion.
- **Service Type:** `names`

---

## 1. Scope & Covenant-Free Safety Boundary (`SL-LDGR-006`)

Organizations and individuals operating Namecoin `id/` and `d/` names require safe workflows for routine `OP_NAME_UPDATE` manifest advances (`m: {h, s+1}`) and pre-expiry renewals (`D = 36000` blocks) without putting cold `name_owner` keys on internet-facing machines:

- **Namecoin covenant boundary (`SPEC-02 §3.2`, `SL-LDGR-006`):** Because unmodified Namecoin lacks output covenants (`OP_CTV`), a single key holding `name_owner` on chain can technically transfer the name. Therefore, a `names` signing/co-signing service MUST NEVER hold unilateral spending power over a high-value name! Instead:
  - **Pattern 1 — Co-Signing Watchtower / HSM (`m-of-n` `P2WSH`):** The `names` executor holds **1 of `m`** keys (e.g., 1 share of a `2-of-3` cold `P2WSH` `owner_policy`) and validates a `seallink-grant/1` (`names/psbt-cosign-update`) enforcing strict output checks: identical trailing `owner_policy`, identical `link.*` role pins (unless explicitly permitted), strictly monotonic `m.s`, and `<= 520`-byte canonical JCS `name-value`!
  - **Pattern 2 — Sponsored Registration & Fee Funding (`names/sponsor-fund`):** Funds client-owned `OP_NAME_NEW` / `OP_NAME_FIRSTUPDATE` / renewal fee UTXOs (`SPEC-03 §5` item 4) without ever taking custody of the client's `owner_policy`.
  - **Future Covenant-Native Binding Profile v2:** On a future Ledger Binding Profile supporting output covenants (`SPEC-02 §1.2`), renewal-only branches become consensus-enforced directly on L1.

---

## 2. Candidate Action Leaves & Orthogonal Flags (`SPEC-07 §4.1`)

| Action | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `allows_bearer_session` | `requires_contract` | `require_seal` | Risk Class |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `names/psbt-cosign-update` | `true` | `false` | `true` | `false` | `false` | `false` | `true` | Class 1 (`3600s`) |
| `names/sponsor-fund` | `true` | `false` | `true` | `false` | `false` | `false` | `true` | Class 1 (`3600s`) |

- **Target grammar:** `^names:id/[a-z0-9][a-z0-9._-]{0,63}:(id|d)/[a-z0-9][a-z0-9._-]{0,63}$`
- **NO Bearer Sessions (`allows_bearer_session = false`) & Mandatory Seal (`require_seal = true`):** All `names/*` mutations require fresh signed `seallink-invocation/1` (optionally requiring `fido2-*` `presence_attestation: "uv"`).
- **Candidate `where` predicates:** `allow_owner_change` (`eq` `false`), `allow_link_change` (`eq` `false`), `max_fee_sat` (`range`), `target_name` (`eq`/`in`/`prefix`).
- **Mechanical `terms_text` ban:** All `names/*` actions refuse `terms_text` (`GRANT_TEXT_FORBIDDEN`).

---

## 3. Open SLIP Checklist Items (`SPEC-07 §4.1`)
1. Formal `schemas/profile-names.schema.json` covering PSBT verification rules (`SIGHASH_ALL`, script preservation, 520B JCS diff checks) and `result_sha256`.
2. Automated renewal watchtower notification schedule (`>= 60` days before Namecoin `36000`-block expiry).
3. Full conformance vectors (`ADMIT` manifest-only co-sign, refuse owner-policy swap, refuse unauthorized `link.grant` change).
