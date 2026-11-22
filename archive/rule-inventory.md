# SealLink v1.0 Rule Inventory and Migration Traceability

**Historical source corpus migrated into cleanroom SealLink v1.0:**
- `swarma-link-spec` v0.1.67 (`protocol/*`, `decisions/0001..0004`, `LIP-0001` through `LIP-0038`, `LIP-0014-source-contract-proposals`, `KEY-MAP.md`, `KEY-REGISTRY.md`, `UNRESOLVED_QUESTIONS.md`)
- `FINAL-ru.md` (Birth & Materialization Certificates / Guardianship design, `P1`–`P20`, 24 specification items)
- `book/ru/` v2.0 (Swarma Runtime & Platform boundary)

**Purpose:** Trace every behavior-critical invariant from the historical draft corpus to its exact SealLink v1.0 `SL-*` rule ID, schema/registry artifact, and conformance vector — or explicitly record why it was superseded, deferred to `OPEN-QUESTIONS.md`, or retired.

---

## 1. Critical Behavioral Rule Traceability (Rule-Level Mapping)

| Historical Rule / Source | Invariant | SealLink v1.0 Rule ID(s) | Status | Witness / Vector |
| --- | --- | --- | :-: | --- |
| `protocol/observation.md`, `LIP-0008 §4` | Independent verification on verifier's own chain view; local pins only | `SL-ARCH-001`, `SL-LDGR-002`, `SL-LDGR-008` | `decided` | `trace-01` |
| `LIP-0020 W1–W9` | Restricted RFC 8785 JCS, no `null`, `uint53`/`uint64_str`, 3 hashes, tagged digests | `SL-WIRE-001`–`SL-WIRE-011`, `SL-WIRE-018` | `decided` | `wire-jcs-and-hashes.json` |
| `LIP-0020 W11.11`, `LIP-0008 §12.6` | Monotonic attenuation (`child <= parent`) checked mechanically | `SL-ARCH-005`, `SL-WIRE-015`–`SL-WIRE-017`, `SL-GRNT-010` | `decided` | `constraints-and-schemas.json`, `trace-03` |
| `LIP-0021 O3.2` | Three distinct Namecoin prefix grammars (`NAME_NEW`, `NAME_FIRSTUPDATE`, `NAME_UPDATE`) | `SL-LDGR-005` | `decided` | `ledger-scripts-and-opreturn.json` |
| `LIP-0021 O3.3` | Owner authorship requires spent previous name input + strict `SIGHASH_ALL` (`0x01`) | `SL-LDGR-007` | `decided` | `trace-01` |
| `LIP-0021 O3.5`, `LIP-0010`, `LIP-0027` | Three-valued seal semantics (`unspent` / `revoked` / `unavailable`; missing != unspent) | `SL-ARCH-002`, `SL-LDGR-011` | `decided` | `trace-01`, `trace-03` |
| `LIP-0022` | Tip snapshot bracket, single-node comparison veto, dual `tip_age` (`first_sight`), recency `(R, R+K]` | `SL-LDGR-008` | `decided` *(constants `open`: `OQ-010..013`)* | `trace-01` |
| `LIP-0023` | Witness construction profile `W`, non-malleable SegWit inputs, linkage `seal_vout + 1` | `SL-LDGR-009` | `decided` | `ledger-scripts-and-opreturn.json` |
| `LIP-0002` | `single_use_1_of_2` branch attribution (issuer revoke vs grantee use), input-first scan | `SL-LDGR-004`, `SL-LDGR-012`, `SL-GRNT-006` | `decided` | `trace-03` |
| `LIP-0003` | Batch anchor `0x02` Merkle commitment | `SL-LDGR-014` | `decided` | `ledger-scripts-and-opreturn.json` |
| `LIP-0005` | Framed `OP_RETURN` action & non-exclusive locator table | `SL-LDGR-010`, `registry/opreturn-actions.json` | `decided` (`0x06` reserved) | `ledger-scripts-and-opreturn.json` |
| `LIP-0010`, `LIP-0033` | 520B name value budget, single `m` pin, 4-channel non-exclusive distribution cascade | `SL-IDEN-001`–`SL-IDEN-004`, `SL-IDEN-009` | `decided` *(domain bind `open`: `OQ-004`)* | `trace-01` |
| `LIP-0010 H51`, `LIP-0029` | Disposable CSPRNG fast-revocation seal + TRUC/P2A CPFP fee-bump output | `SL-LDGR-013`, `SL-IDEN-005` | `decided` format *(2-node regtest passed; prod propagation `open`: `OQ-006`)* | `ledger-scripts-and-opreturn.json`, `conformance/p2a-regtest/` |
| `KEY-REGISTRY` Rules 1–3, `KEY-MAP` | Strict key-role separation + cold `emergency_fee_reserve` (`m/84'/7'/3'`) | `SL-ARCH-006`, `SL-IDEN-005`, `registry/key-roles.json` | `decided` | `speclint.py` cross-registry check |
| `LIP-0034` | Dedicated `auth_key` + `auth_seal`, provisional key-only cells, atomic `auth-upgrade` | `SL-IDEN-010` | `decided` | `schemas/invocation.schema.json` |
| `LIP-0029`, `LIP-0015` | L0–L2 owner control plane, level inheritance, trust-root pin + delayed admin override | `SL-IDEN-011`, `SL-IDEN-012` | `decided` *(FIDO2/SSH `open`: `OQ-005`)* | `schemas/invocation.schema.json` |
| `LIP-0017 C10–C12` | N-party salted contracts, framework depth 1, confirmed contract seal determines termination type | `SL-CONT-001`–`SL-CONT-006` | `decided` | `wire-jcs-and-hashes.json`, `trace-02` |
| `LIP-0011 J8` | Chained violation verdicts (`0x03`) and salted invocation attribution | `SL-CONT-007` | `decided` | `schemas/contract.schema.json` |
| `LIP-0032`, `LIP-0021 §7.6` | Eternal vs revocable credentials (`0x09`/`0x0a`), owner-authenticated `h_c` break (`0x0b`), general notary (`0x04`/`0x05`) | `SL-CONT-008`–`SL-CONT-011` | `decided` | `schemas/credential.schema.json` |
| `LIP-0006 §7`, `LIP-0035` | Unilateral base grant; mechanical effect executors refuse `terms_text`; reserve before effect | `SL-ARCH-004`, `SL-GRNT-001`, `SL-GRNT-005`, `SL-GRNT-007` | `decided` | `constraints-and-schemas.json`, `trace-01` |
| `LIP-0026 R8.5` | Whole-parent aggregate budget sum across all row groups (`sum(rows * cap) <= pool_max`) | `SL-GRNT-010` | `decided` | `trace-03` |
| `LIP-0026 R8.6` | Pairwise-disjoint row-coin and stop-coin ranges across all groups | `SL-GRNT-009` | `decided` | `trace-03` |
| `LIP-0027 H1–H4` | Notary per-row stop coins (`GRANT_ROW_STOPPED`) | `SL-GRNT-011` | `decided` | `schemas/grant.schema.json` |
| `LIP-0025 M4.6` | Hash-chained anti-rollback journal + external CAS witness fencing + `+7200s` recovery boundary | `SL-GRNT-014` | `decided` *(witness wire `open`: `OQ-003`)* | `trace-01`, `trace-03` |
| `LIP-0028` | Short-lived (`<= 3600s`) bearer sessions with per-use chain/seal recheck | `SL-GRNT-013` | `decided` | `schemas/invocation.schema.json` |
| `LIP-0009` | Replaceable services, 3-class export boundary, 4-step exclusive cut-over | `SL-SERV-001`–`SL-SERV-003` | `decided` | `PROFILE-mail-v1.md`, `PROFILE-agent-v1.md` |
| `LIP-0036` | Two-phase federated screening (zero PII) -> L2-gated Contour A targeted disclosure | `SL-SERV-004` | `decided` | `SPEC-07 §3` |
| `LIP-0038` | Effect leaves (`post-message`, `spend-coins`, `name-update`, `model-call`) | `SL-SERV-005`, `OPEN-QUESTIONS.md` | **Deferred** (except `mail` & `agent-session` profiles) | `PROFILE-mail-v1.md`, `PROFILE-agent-v1.md` |
| `LIP-0024 §2`, `LIP-0004`, `LIP-0016 §2–3` | Legacy v0.1/v3 wire formats, Nostr `kind 8181`, seal endorsement, UTXO cert head `0x06` | **Retired** | Retired | Replaced by `SPEC-01`/`03`/`05`/`06` |

---

## 2. Guardianship and Origin Certificate Traceability (`FINAL-ru.md` `P1`–`P20` & 24 Items)

| Item | Topic | SealLink v1.0 Resolution | Status |
| --- | --- | --- | :-: |
| `P1–P2` | Origin-certified class (`person`, `agent`, `organization`) distinct from unverified cards | `SL-ARCH-008`, `SL-ORIG-002` | `decided` |
| `P3–P4` | Three-record separation (`origin/1`, `name-binding/1`, `guardian/1`) + identity permanence | `SL-ORIG-001`, `SL-ORIG-003` | `decided` |
| `P5` | Pre-registration issuance + single-use `binding_seal` (`0x0c`) + reverse uniqueness | `SL-ORIG-002`, `SL-ORIG-003` | `decided` |
| `P6–P7` | Privacy of public chain (`link.origin`) + salted commitments for initial guardians and `majority_unix` | `SL-ARCH-012`, `SL-IDEN-003`, `SL-ORIG-002` | `decided` |
| `P8–P9` | $N$ equal guardian slots + revision-denominated quorums + 4-class linear verifier-derived `event_class` + `SL-ORIG-016` consistency | `SL-ORIG-004`, `SL-ORIG-005`, `SL-ORIG-016` | `decided` |
| `P10` | Protocol-level ward non-autonomy (`WARD_AUTONOMOUS_FORBIDDEN`, `guardian_approvals[]`) | `SL-ORIG-006`, `SL-WIRE-013` | `decided` |
| `P11–P13` | Direct initial activation (`0x12`), acyclic two-stage appointment (`0x0d` pending -> `0x0e` active), explicit `challenger_pk`, fast halt, slot burn recovery via `0x0f` roster transition | `SL-ORIG-007`, `SL-ORIG-015` | `decided` |
| `P14` | Native `P2WSH` `m-of-n` multisig name ownership via `namepsbt` (ECDSA, no FROST on P2WPKH, no covenant renewal branch) | `SL-LDGR-004`, `SL-LDGR-006` | `decided` *(threshold ECDSA `open`: `OQ-007`)* |
| `P15–P16` | Calendar vs indefinite terms; asymmetric safety pause at majority boundary `T` | `SL-ORIG-009`, `SL-ORIG-010` | **Time oracle `open`** (`OQ-001`) |
| `P17` | Authenticated completeness via `status_seal` and `roster_seal` spines (`ORIGIN_STATUS_INCOMPLETE`) | `SL-ORIG-001`, `SL-ORIG-002`, `SL-ORIG-015` | `decided` |
| `P18` | Four ward admission states (`under_guardianship`, `halted`, `transfer_pending`, `autonomous`) + fresh subject `ScriptPolicy` on emancipation | `SL-ORIG-011` | `decided` |
| `P19` | Eternal `seallink-end/1` terminating `status_seal` (`SUBJECT_ENDED`); issuer-key survival at anchor height | `SL-ORIG-008`, `SL-ORIG-012` | `decided` |
| `P20` | Dual-mode `name_recovery` (`none` vs `dual_party_delayed`) + live-owner `0x10` `RECOVERY_CANCEL` veto | `SL-ORIG-013`, `SL-ORIG-014` | `decided` |

---

## 3. Historical Corpus Disposition Summary (38 Draft LIPs)

- **Core Backbone Consolidated (`SPEC-00`–`SPEC-07`):** `LIP-0001`, `0002`, `0003`, `0005`, `0006`, `0007`, `0008`, `0009`, `0010`, `0011`, `0012`, `0014`, `0015`, `0016` (§1/§3.1/§4), `0017`, `0018`, `0019`, `0020`, `0021`, `0022`, `0023`, `0025`, `0026`, `0027`, `0028`, `0029`, `0031`, `0032`, `0033`, `0034`, `0035`, `0036`, `0037`.
- **Moved to Profiles (`profiles/`) or Open Profiles (`OPEN-QUESTIONS.md`):** `LIP-0009` (`blob`), `LIP-0030` (`PROFILE-agent-v1.md` + external Swarma Runtime), `LIP-0038` (`wallet`, `names`, `compute`).
- **Moved to Informative Guide (`guides/GUIDE-01-custody-and-signers.md`):** `LIP-0013` (§3.4/§3.6 Authority Frame & Keymaker run-origin gate), `LIP-0014` companion (Keychain/Curator host seams, delegation signer reservation ledger), `KEY-MAP.md` operational tips.
- **Retired (Cleanroom v1.0):** `protocol/*` v0.1 bytes, `LIP-0004` (v3 & Nostr `kind 8181`), `LIP-0013` v3 / Matrix `8185`, `LIP-0014` v3 `/2` & `8186`, `LIP-0016` §2–3 UTXO cert head `0x06`, `LIP-0024` §2 seal endorsement.
