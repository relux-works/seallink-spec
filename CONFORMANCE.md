# SealLink Conformance Requirements

- **Version:** `1.0.0-draft.9`
- **Status:** `draft`
- **Normative Language:** [RFC2119], [RFC8174]

---

## 1. Conformance Roles

An implementation claiming conformance to SealLink v1.0 **MUST** declare which of the following roles it implements and MUST pass every required specification section, registry invariant, JSON Schema, and conformance vector listed for that role.

| Conformance Role | Required Specifications | Required Registries & Schemas | Required Vector Suites |
| --- | --- | --- | --- |
| **Core Wire Library** | `SPEC-00`, `SPEC-01` | `object-types.json`, `refusal-codes.json`, `constraints.json`, `actions.json`, all `schemas/*.schema.json` | `vectors/wire-jcs-and-hashes.json`, `vectors/constraints-and-schemas.json` |
| **Tier 1 Verifier** | Core Wire + `SPEC-02`, `SPEC-03` (§1–4), `SPEC-04`, `SPEC-05`, `SPEC-06` (§1–4, §6) | All `registry/*.json` and `schemas/*.schema.json` | All `vectors/*.json` (including `trace-01` through `trace-04`, `security-conformance.json`, and `refusal-coverage-matrix.json`) |
| **Effect Executor / Provider** | Tier 1 Verifier + `SPEC-07` (§1, §4), plus each supported `PROFILE-*.md` and any declared optional module below | All `registry/*.json`, `schemas/*.schema.json`, and owning `profile-*.schema.json` | All `vectors/*.json` plus profile-specific traces (`trace-01`, `trace-03`, `trace-04`) |
| **Issuer / Signer** | Core Wire + `SPEC-02` (§3, §5), `SPEC-03` (§1–3, §6), `SPEC-05`, `SPEC-06` (§1, §3) | `object-types.json`, `key-roles.json`, `opreturn-actions.json`, `constraints.json`, `actions.json` | `wire-jcs-and-hashes.json`, `ledger-scripts-and-opreturn.json`, `constraints-and-schemas.json` |
| **Institutional / Guardian Authority** | Tier 1 Verifier + Issuer + `SPEC-04` (full), `SPEC-05` (§4–5) | All `registry/*.json`, `origin.schema.json`, `guardian.schema.json`, `credential.schema.json` | `vectors/trace-02-guardian-succession-assent.json`, `vectors/trace-04-agent-guardian-intake.json` |

### 1.1 Optional-Declaration v1.0 Conformance Modules & Vector Selection Tags

The following three subsystems are fully specified, schema-validated, and vector-tested in SealLink v1.0, and are declared independently as **optional conformance modules**. A base service (for example, a standalone mail host) is NOT required to implement an optional module it does not advertise; any implementation that declares support for a module **MUST** implement its full specification and pass 100% of its conformance vectors.

- **Disabled-module refusal behavior (fail-closed):** An implementation that does **NOT** declare a given optional module MUST refuse any incoming request targeting that module's object type or operation without mutating journal state, returning **`ACTION_UNSUPPORTED`** (or **`WIRE_TYPE`** if the disabled module's object type is omitted from its parser table).
- **Vector selection tags (`module` / `role`):** Every vector case in `vectors/` belongs to `module = "core"` unless tagged with one of the three optional module tags below (`bearer-sessions`, `service-migration`, `federated-screening`), enabling Rust/Go conformance runners to select exact suites by declared role and enabled modules.

| Optional Module (`module` tag) | Normative Specification | Canonical Objects & Rules | Primary Refusal Code |
| --- | --- | --- | --- |
| **Bearer Sessions** (`bearer-sessions`) | `SPEC-06 §5` (`SL-GRNT-013`) | `seallink-session-open/1` (`open`/`extend`/`close`), full `§4` backing-grant open, CSPRNG 32B token, journal `session-state` & `session-use` debits across `session`/`own`/`row`, mandatory live `grant_env` recheck on `use` | `SESSION_INVALID` |
| **Service Migration & Exclusive Cut-Over** (`service-migration`) | `SPEC-07 §2` (`SL-SERV-002`, `SL-SERV-003`) | `seallink-migration/1`, canonical `MigrationInventory` only, separated `stage` vs `activate` (4 mandatory proofs: `local_executor_pin`, `holder_assent`, confirmed holder manifest, signed `migration-accept` statement), journal `migration-applied` | `SERVICE_MIGRATION_INVALID` |
| **Federated Screening & Progressive PII Disclosure** (`federated-screening`) | `SPEC-07 §3` (`SL-SERV-004`) | Phase 1 quota-bounded screening + Phase 2 L2 `approve-pii-disclosure` owner command (mandatory verified holder manifest + `sets.devices` + strict single direct hop `len(hops) == 1`) | `FEDERATION_POLICY_DENIED` |

---

## 2. Mandatory Behavioral Requirements

1. **Deterministic Refusal Ordering:** A conforming verifier MUST emit the exact first refusal code prescribed by `SPEC-01 §7`, `SPEC-05 §4.2`, and `SPEC-06 §4` for every test vector in `vectors/`.
2. **Fail-Closed Unknown Handling:** A conforming implementation MUST refuse unregistered `type` strings (`WIRE_TYPE`), unknown JSON members (`WIRE_MEMBER`), reserved action byte `0x06` (`CHAIN_FRAME_INVALID`), populated `extensions` (`WIRE_CONSTRAINT`), unsupported `ScriptPolicy` templates (`CHAIN_SCRIPT_UNSUPPORTED`), and any `open` construct lacking a locally enabled profile.
3. **Zero Silent Repair:** A conforming parser MUST reject non-canonical JSON (`WIRE_NOT_CANONICAL`) and MUST NOT normalize strings, reorder keys before hashing, coerce integer encodings, or strip unknown members.
4. **No Floating-Point Arithmetic:** Conforming implementations MUST NOT route any `uint53`, `uint64_str`, quota debit, rational quorum, or R8.5 aggregate budget sum through IEEE 754 floating-point arithmetic.
5. **Independent Chain Observation:** A conforming Tier 1 Verifier MUST NOT accept ledger state, block heights, or UTXO spend status from the presenter or issuer; it MUST query its own read-only tx-indexed node cross-checked against at least one independent comparison node (`SPEC-02 §4`).

---

## 3. Reference Verifier Core vs. Production Tier 1 Conformance Boundary

`tools/seallink_verifier.py` serves as the **Reference Verifier Core** for SealLink v1.0: it enforces Draft 2020-12 closed schemas, pure-Python BIP-340 / RFC 8032 Ed25519 / low-S NIST P-256 cryptography, authoritative issuer/guardian/executor key resolution, derived chain-history/witness evaluation over a declarative `ChainView`, and an in-memory hash-chained `FencedJournal`.

A production **Tier 1 Verifier** or **Effect Executor** claiming full operational conformance additionally requires:
1. A live read-only Namecoin Core (`txindex=1` verified via `getindexinfo`, plus `namehistory=1` or equivalent historical registration archive; reference cold-observer implementation provided in `tools/nc_rpc_adapter.py`) populating `ChainView` directly from confirmed active-chain blocks, UTXOs (`absent_from_utxo` on missing UTXOs), witnesses, multi-registration name histories, schema-driven signed continuation `*_vout` outputs, and local mempool, enforcing full `SPEC-02 §4` opening/closing observation brackets (`require_observation_bracket=True`), closed-bracket `pre_effect_recheck` with unified decision clock before side effects, and atomically merged operational `clock_watermark` / `first_sight_by_hash` state (`clock_mode="operational"` mandatory on `main`);
2. At least one operator-controlled independent comparison node (`SPEC-02 §4`);
3. Raw wire byte ingress prior to parsing (`SPEC-01 §7`); and
4. Durable crash-safe local storage implementing two-phase atomic admission (`admit_and_reserve()` committing one atomic `reservation` entry binding `nonce` + `reservations[]`, followed after effect execution by `commit_result(receipt_env)` verifying and reconciling signed `receipt.payload.settlements[]` 1-to-1 against the reservation, persisting verified signed receipt bytes FIRST, and committing ONE unified atomic terminal `settlement` entry — including `single_use_consumed: true` for single-use grants — with exact `content_addr(receipt_env)`) and mandatory witness-verified restart replay (`replay_persisted_entries(..., require_witness=True)` enforcing wire/schema validation on every entry and checking `(witness_pos, witness_commitment, write_token)` against an external CAS witness outside the local backup domain, `SPEC-06 §6`, `SL-GRNT-014`).

---

## 4. Interoperability Bar for Advancing Specification Maturity

Per `SPEC-00 §5.1`:
- **`prose` -> `vectors`:** Every registered refusal code (`86/86`) and every canonical object type (`30/30`) is exercised by schema-valid semantic refusal fixtures and raw wire fixtures (with every case in `vectors/refusal-coverage-matrix.json` and `vectors/security-conformance.json` tagged with `"module"`), every `decided` normative rule is explicitly mapped in the rule-coverage audit, negative security/false-admit, restart-recovery, historical re-registration, and exact-boundary regressions plus multi-operator verifier mutation audits pass, and all suites execute live through `tools/seallink_verifier.py` and Draft 2020-12 metaschemas in CI.
- **`vectors` -> `dual-impl`:** At least two independent implementations with disjoint cryptographic and JSON stacks pass 100% of `vectors/` byte-for-byte (identical object IDs, digests, content addresses, refusal codes, and journal commitments).
- **`dual-impl` -> `chain-tested`:** All five end-to-end traces (`trace-01` `PROFILE-mail-v1` `mail/read` + `executor_ref` + named recipient + `pre_effect_recheck` + offline mempool revoke, `trace-02` initial & successor guardian activation + `P2WSH` `namepsbt` + non-default `pending_vout = 2` CSV `guardian_slot_pending` + ward assent + `0x10` recovery cancel, `trace-03` depth-2 parent pool + sibling `row_ordinal` + crash-uncertain + restart replay + single-use `0x11` + TRUC v3 `P2A` CPFP, `trace-04` ward agent guardian intake + separate-process quota-free restart recovery, `trace-05` historical eternal credential across live expiry and lawful re-registration + live mid-read tip-change observation bracket) are executed with raw transaction artifacts via a cold read-only observer against a live Namecoin Core `nc28.0` regtest network (reference regtest proofs provided in `conformance/p2a-regtest/` and `conformance/traces-regtest/`) and qualified under production/mainnet conditions across independent implementations.
