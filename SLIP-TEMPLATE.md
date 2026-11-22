# SLIP-XXXX: Title of Proposal

- **SLIP:** `XXXX` *(assigned upon PR submission)*
- **Title:** Short descriptive title
- **Type:** `Core` | `Profile` | `Registry` | `Ledger-Binding` | `Informational`
- **Status:** `Draft` | `Review` | `Accepted` | `Final` | `Withdrawn` | `Superseded`
- **Requires:** List of `SPEC-*` or `SLIP-*` dependencies
- **Authors:** Name <email or SealLink id/>
- **Created:** YYYY-MM-DD

---

## 1. Abstract

One concise paragraph summarizing the proposed addition or change and the problem it solves.

## 2. Motivation and Non-Goals

Why existing `SPEC-00..07` primitives or reverse-DNS custom namespaces (`SPEC-07 §4`) are insufficient, and what is explicitly out of scope.

## 3. Specification

Normative rules using [RFC2119] / [RFC8174] keywords, assigned unique `SL-<AREA>-<NNN>` Rule IDs.

- If adding a **Service Profile or Action Leaf**, include every item required by `SPEC-07 §4.1` (orthogonal action flags: `external_mutation`, `discloses_data`, `quota_consuming`, `allows_executor_ref`, `requires_contract`, `require_seal`, Risk Class; closed argument and result JSON Schemas; `result_sha256` formula; pagination/replay semantics; quota reservation/settlement; export boundary).
- If adding a **Quota Kind**, include every item required by `SPEC-07 §4.2`.
- If adding a **Canonical Object Type, Refusal Code, Key Role, or OP_RETURN Action**, include exact patches to `registry/*.json` and `schemas/*.schema.json`.

## 4. Backwards Compatibility and Fail-Closed Behavior

Explain how unupgraded v1.0 verifiers handle the new construct (must fail closed with a registered refusal code).

## 5. Security and Privacy Considerations

Threat model, DoS/oracle analysis, key-role separation impact, and on-chain privacy impact (`SL-ARCH-012`).

## 6. Conformance Test Vectors

Reference the exact positive, single-defect negative, and stateful-journal test vectors added under `vectors/` and verified by `tools/speclint.py`.

---

## SLIP Lifecycle Process

1. **Draft:** Author opens a PR with `SLIP-XXXX`, updated `registry/` and `schemas/` patches, and conformance vectors. CI (`tools/speclint.py`) MUST pass with zero errors.
2. **Review:** Public technical review and independent verification against schemas and reference tooling.
3. **Accepted:** Consensus among maintainers; vectors verified by at least one implementation.
4. **Final:** Verified across two independent implementations (`dual-impl`) and merged into the next specification release.
