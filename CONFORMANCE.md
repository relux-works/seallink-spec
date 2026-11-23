# SealLink Conformance Requirements

- **Version:** `1.0.0-draft.4`
- **Status:** `draft`
- **Normative Language:** [RFC2119], [RFC8174]

---

## 1. Conformance Roles

An implementation claiming conformance to SealLink v1.0 **MUST** declare which of the following roles it implements and MUST pass every required specification section, registry invariant, JSON Schema, and conformance vector listed for that role.

| Conformance Role | Required Specifications | Required Registries & Schemas | Required Vector Suites |
| --- | --- | --- | --- |
| **Core Wire Library** | `SPEC-00`, `SPEC-01` | `object-types.json`, `refusal-codes.json`, `constraints.json`, all `schemas/*.schema.json` | `vectors/wire-jcs-and-hashes.json`, `vectors/constraints-and-schemas.json` |
| **Tier 1 Verifier** | Core Wire + `SPEC-02`, `SPEC-03` (§1–4), `SPEC-04`, `SPEC-05`, `SPEC-06` (§1–4, §6) | All `registry/*.json` and `schemas/*.schema.json` | All `vectors/*.json` (including `trace-01` through `trace-04` and `refusal-coverage-matrix.json`) |
| **Effect Executor / Provider** | Tier 1 Verifier + `SPEC-06` (§5 if bearer sessions enabled), `SPEC-07`, plus each supported `PROFILE-*.md` | All `registry/*.json`, `schemas/*.schema.json`, and owning `profile-*.schema.json` | All `vectors/*.json` plus profile-specific traces (`trace-01`, `trace-03`, `trace-04`) |
| **Issuer / Signer** | Core Wire + `SPEC-02` (§3, §5), `SPEC-03` (§1–3, §6), `SPEC-05`, `SPEC-06` (§1, §3) | `object-types.json`, `key-roles.json`, `opreturn-actions.json`, `constraints.json` | `wire-jcs-and-hashes.json`, `ledger-scripts-and-opreturn.json`, `constraints-and-schemas.json` |
| **Institutional / Guardian Authority** | Tier 1 Verifier + Issuer + `SPEC-04` (full), `SPEC-05` (§4–5) | All `registry/*.json`, `origin.schema.json`, `guardian.schema.json`, `credential.schema.json` | `vectors/trace-02-guardian-succession-assent.json`, `vectors/trace-04-agent-guardian-intake.json` |

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
1. A live read-only Namecoin Core (`txindex=1`) RPC adapter populating `ChainView` directly from confirmed blocks, UTXOs, witnesses, and local mempool;
2. At least one operator-controlled independent comparison node (`SPEC-02 §4`);
3. Raw wire byte ingress prior to parsing (`SPEC-01 §7`); and
4. Durable crash-safe local storage coupled to an external CAS witness outside the local backup domain (`SPEC-06 §6`).

---

## 4. Interoperability Bar for Advancing Specification Maturity

Per `SPEC-00 §5.1`:
- **`prose` -> `vectors`:** Every registered refusal code (`84/84`) is exercised by schema-valid semantic refusal fixtures and raw wire fixtures, every `decided` normative rule is explicitly mapped in the rule-coverage audit, negative security/false-admit regressions and verifier-check mutation tests pass, and all suites execute live through `tools/seallink_verifier.py` and Draft 2020-12 metaschemas in CI.
- **`vectors` -> `dual-impl`:** At least two independent implementations with disjoint cryptographic and JSON stacks pass 100% of `vectors/` byte-for-byte (identical object IDs, digests, content addresses, refusal codes, and journal commitments).
- **`dual-impl` -> `chain-tested`:** All four end-to-end traces (`trace-01` mail offline + revoke, `trace-02` initial & successor guardian activation + `P2WSH` `namepsbt` + CSV `guardian_slot_pending` + ward assent + recovery, `trace-03` parent pool + dual-account per-`row_ordinal` multi-quota + single-use `0x11` + crash-uncertain + replay + revoke, `trace-04` ward agent guardian intake) plus TRUC v3 / `P2A` CPFP package relay are executed with raw transaction artifacts against a live Namecoin Core `nc28.0` regtest network (reference regtest proofs provided in `conformance/p2a-regtest/` and `conformance/traces-regtest/`) and qualified under production/mainnet conditions across independent implementations.
