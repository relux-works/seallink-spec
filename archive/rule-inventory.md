# SealLink v1.0 Rule Inventory and Migration Traceability

**Purpose:** Provide (1) a complete per-rule index of every declared normative `SL-*` rule across `SPEC-00`–`SPEC-07` and standard profiles (`PROFILE-mail-v1`, `PROFILE-agent-v1`), mapped to its current status and verification coverage; and (2) migration traceability from the historical draft corpus (`swarma-link-spec` v0.1.67, `LIP-0001`–`LIP-0038`, `FINAL-ru.md`, and `book/ru/` v2.0).

---

## 1. Complete Per-Rule Conformance Index (114 Declared `SL-*` Rules)

Every rule ID and refusal code below is mechanically validated by `tools/speclint.py` against `spec/SPEC-*.md`, `profiles/PROFILE-*.md`, and `registry/refusal-codes.json`.

### 1.1 Architecture and Governance (`SPEC-00`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-ARCH-001` | `decided` | Independent verification on verifier's own chain view; no trusted presenter claims | `trace-01`–`trace-04`, `security-conformance.json`, `tools/seallink_verifier.py` |
| `SL-ARCH-002` | `decided` | Three-valued verdict semantics (`Admit` / `Refuse` / `Unavailable`; missing != unspent) | `trace-01`, `trace-03`, `refusal-coverage-matrix.json` (`SEAL_UNAVAILABLE`, `CHAIN_UNHEALTHY`) |
| `SL-ARCH-003` | `decided` | Fast to halt (mempool spend), slow to add or transfer (CSV delay / confirmations) | `trace-01`, `trace-02`, `trace-03`, `refusal-coverage-matrix.json` |
| `SL-ARCH-004` | `decided` | Prose directs work; typed fields and scripts authorize effects (`terms_text` refused by effect executors) | `constraints-and-schemas.json`, `refusal-coverage-matrix.json` (`GRANT_TEXT_FORBIDDEN`) |
| `SL-ARCH-005` | `decided` | Monotonic attenuation (`child <= parent`) across capabilities, quotas, windows, and recipients | `constraints-and-schemas.json`, `trace-03`, `refusal-coverage-matrix.json` (`GRANT_CHILD_WIDER`) |
| `SL-ARCH-006` | `decided` | Strict key-role separation with closed signing domains | `registry/key-roles.json`, `registry/object-types.json`, `speclint.py` cross-registry check |
| `SL-ARCH-007` | `decided` | Availability-only off-chain storage and transport; authenticity solely via hash pins & signatures | `trace-01`, `refusal-coverage-matrix.json` (`MANIFEST_MISMATCH`), `GUIDE-01 §5` |
| `SL-ARCH-008` | `decided` | Actor-agnostic core mechanics with origin-certified class distinction | `trace-02`, `trace-04`, `schemas/origin.schema.json` |
| `SL-ARCH-009` | `decided` | Orthogonal actor axes (origin class vs. autonomy/guardianship mode) | `SPEC-00 §3`, `schemas/origin.schema.json`, `trace-02`, `trace-04` |
| `SL-ARCH-010` | `decided` | Single Source of Truth: prose defines normative behavior; `registry/*.json`, `schemas/*.schema.json`, and `vectors/*.json` define exact identifiers, grammars, and required outcomes; disagreement is a spec defect | `tools/speclint.py` (registries, `$ref`s, Draft 2020-12 metaschemas) |
| `SL-ARCH-011` | `decided` | Honest security guarantees and fail-closed threat boundaries | `SPEC-00 §6.1`, `CONFORMANCE.md §3`, `security-conformance.json` |
| `SL-ARCH-012` | `decided` | Privacy by default on public ledger (commitments, seals, and salted hashes only) | `schemas/name-value.schema.json`, `schemas/origin.schema.json`, `trace-02` |

### 1.2 Wire Format, Cryptography, and Constraint Algebra (`SPEC-01`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-WIRE-001` | `decided` | Per-type `max_bytes` octet ceiling and JSON nesting depth `<= 16` | `wire-jcs-and-hashes.json`, `refusal-coverage-matrix.json` (`WIRE_SIZE`, `WIRE_JSON`) |
| `SL-WIRE-002` | `decided` | Strict UTF-8 without BOM, no leading/trailing bytes, single RFC 8259 JSON object | `wire-jcs-and-hashes.json`, `refusal-coverage-matrix.json` (`WIRE_JSON`) |
| `SL-WIRE-003` | `decided` | No duplicate JSON member names at any nesting level (after escape decoding) | `wire-jcs-and-hashes.json`, `refusal-coverage-matrix.json` (`WIRE_DUPLICATE`) |
| `SL-WIRE-004` | `decided` | Closed JSON value subset (objects, arrays, strings, `uint53`, booleans; no `null` or floats) | `wire-jcs-and-hashes.json`, `refusal-coverage-matrix.json` (`WIRE_VALUE`, `WIRE_NUMBER`) |
| `SL-WIRE-005` | `decided` | Strings restricted to Unicode scalar values `>= U+0020`, excluding surrogates and `U+007F` | `wire-jcs-and-hashes.json`, `refusal-coverage-matrix.json` (`WIRE_STRING`) |
| `SL-WIRE-006` | `decided` | Exact RFC 8785 JCS canonical byte equality (no silent repair) | `wire-jcs-and-hashes.json`, `refusal-coverage-matrix.json` (`WIRE_NOT_CANONICAL`) |
| `SL-WIRE-007` | `decided` | `uint53` integer token range `[0, 2^53 - 1]` without sign, fraction, exponent, or leading zero | `wire-jcs-and-hashes.json`, `refusal-coverage-matrix.json` (`WIRE_NUMBER`, `WIRE_INTEGER`) |
| `SL-WIRE-008` | `decided` | `uint64_str` string grammar `^(0|[1-9][0-9]{0,19})$` in `[0, 2^64 - 1]` | `refusal-coverage-matrix.json` (`WIRE_INTEGER`), `schemas/common.schema.json` |
| `SL-WIRE-009` | `decided` | Strict integer form distinction (`uint53` vs. `uint64_str`) enforced by schema | `schemas/common.schema.json`, `constraints-and-schemas.json`, `speclint.py` |
| `SL-WIRE-010` | `decided` | Closed object schemas (`additionalProperties: false`) enforced at ingress | `refusal-coverage-matrix.json`, `security-conformance.json` (`WIRE_MEMBER`), mutation audit |
| `SL-WIRE-011` | `decided` | Three distinct hashes: `object_id`, `content_addr`, and domain-tagged `signing_digest` | `wire-jcs-and-hashes.json`, `trace-01`–`trace-04` |
| `SL-WIRE-012` | `decided` | Key encodings and signature algorithms: BIP-340, RFC 8032 Ed25519, strict low-S NIST P-256 | `wire-jcs-and-hashes.json`, `security-conformance.json` (`WIRE_KEY`, `WIRE_SIGNATURE`), `seallink_ref.py` |
| `SL-WIRE-013` | `decided` | Signed envelope, `SignatureSet`, `guardian_approvals[]`, device-alg type restriction, and authoritative policy binding | `wire-jcs-and-hashes.json`, `trace-02`, `trace-04`, `refusal-coverage-matrix.json`, `security-conformance.json` |
| `SL-WIRE-014` | `decided` | Salted selective disclosure (`clause_commit`, `claim_commit`, independent CSPRNG salts) | `wire-jcs-and-hashes.json`, `trace-02`, `schemas/contract.schema.json` |
| `SL-WIRE-015` | `decided` | Structured capability `{action, target, constraints}` and closed `extensions` refusal | `constraints-and-schemas.json`, `refusal-coverage-matrix.json` (`WIRE_CONSTRAINT`) |
| `SL-WIRE-016` | `decided` | Seven Constraint Algebra predicates (`eq`, `in`, `not_in`, `prefix`, `suffix`, `range`, `hash_eq`) and conservative pairwise attenuation | `constraints-and-schemas.json`, `refusal-coverage-matrix.json` (`GRANT_CHILD_WIDER`, `INVOKE_CONSTRAINT_FAILED`) |
| `SL-WIRE-017` | `decided` | Universal capability attenuation rule (every child capability covered by a parent capability) | `constraints-and-schemas.json`, `trace-03`, `refusal-coverage-matrix.json` (`GRANT_CHILD_WIDER`) |
| `SL-WIRE-018` | `decided` | Deterministic 10-step wire validation pipeline returning first refusal | `wire-jcs-and-hashes.json`, `refusal-coverage-matrix.json`, `tools/seallink_verifier.py` |

### 1.3 Ledger Binding, Scripts, Freshness, and Seals (`SPEC-02`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-LDGR-001` | `decided` | Abstract `ChainView` ledger interface decoupling core semantics from specific node RPC | `tools/seallink_verifier.py`, `CONFORMANCE.md §3`, `trace-01`–`trace-04` |
| `SL-LDGR-002` | `open` | Verifier conformance tiers (Tier 1 full tx-indexed node `decided`; Tier 2 SPV `open`: `OQ-002`) | `CONFORMANCE.md §1, §3`, `OPEN-QUESTIONS.md` (`OQ-002`) |
| `SL-LDGR-003` | `decided` | Namecoin Binding Profile v1 chain pins (mainnet genesis, `36000`-block expiry, `520`B value cap) | `refusal-coverage-matrix.json` (`CHAIN_MISMATCH`, `NAME_EXPIRED`), `trace-01` |
| `SL-LDGR-004` | `decided` | Closed `ScriptPolicy` templates (`P2WPKH`, `P2WSH` multisig, `single_use_1_of_2`, `guardian_slot_*`, `recovery_delayed_transfer`) | `ledger-scripts-and-opreturn.json`, `refusal-coverage-matrix.json` (`CHAIN_SCRIPT_UNSUPPORTED`) |
| `SL-LDGR-005` | `decided` | Three Namecoin output prefix grammars (`NAME_NEW`, `NAME_FIRSTUPDATE`, `NAME_UPDATE`) and pre-spend verification | `ledger-scripts-and-opreturn.json`, `refusal-coverage-matrix.json` |
| `SL-LDGR-006` | `decided` | No covenant renewal-only branch on unmodified Namecoin; multisig controls full `NAME_UPDATE` | `SPEC-02 §3.2`, `ledger-scripts-and-opreturn.json`, `GUIDE-01 §2` |
| `SL-LDGR-007` | `decided` | Author/writer verification: spent previous name input with strict `SIGHASH_ALL` (`0x01`) | `trace-01`, `refusal-coverage-matrix.json` (`NAME_WRITER_UNVERIFIED`), mutation audit |
| `SL-LDGR-008` | `open` | Consistent observation bracket, `>= 1` healthy comparison node (`CHAIN_UNHEALTHY`), dual `tip_age`, recency `(R, R+K]` (algorithm `decided`; constants `open`: `OQ-010..013`) | `trace-01`, `refusal-coverage-matrix.json`, `security-conformance.json`, mutation audit |
| `SL-LDGR-009` | `decided` | Witness Construction Profile `W` (SegWit inputs, non-malleable txid, adjacent `seal_vout + 1` linkage) | `ledger-scripts-and-opreturn.json`, `refusal-coverage-matrix.json` (`CHAIN_TX_CONSTRUCTION`), mutation audit |
| `SL-LDGR-010` | `decided` | Framed `SLNK` (`534c4e4b`) `OP_RETURN` grammar, action bytes `0x01`–`0x12`, reserved `0x06` refusal | `ledger-scripts-and-opreturn.json`, `registry/opreturn-actions.json`, `refusal-coverage-matrix.json` (`CHAIN_FRAME_INVALID`) |
| `SL-LDGR-011` | `decided` | Unified three-valued seal state (`unspent` / `revoked` / `unavailable`; mempool spends revoke immediately) | `trace-01`, `trace-03`, `refusal-coverage-matrix.json` (`SEAL_SPENT`, `SEAL_UNAVAILABLE`) |
| `SL-LDGR-012` | `decided` | Single-use branch attribution via witness selector (issuer revocation vs. grantee `0x11` use; input-first scan) | `trace-03`, `refusal-coverage-matrix.json` (`SEAL_SPENT`, `GRANT_CLOSED`) |
| `SL-LDGR-013` | `open` | Pre-signed disposable seals, `240`-sat `P2A` dust floor, mandatory TRUC `nVersion = 3` for zero-fee `tx_revoke` (format `decided`; prod relay `open`: `OQ-006`) | `ledger-scripts-and-opreturn.json`, `conformance/p2a-regtest/`, `conformance/traces-regtest/` |
| `SL-LDGR-014` | `decided` | Merkle batch anchor (`0x02`) domain-separated leaf/node hashing and sorted sibling inclusion proof | `ledger-scripts-and-opreturn.json`, `seallink_ref.py` |
| `SL-LDGR-015` | `decided` | Normative `ChainView` snapshot fields, units, fail-closed defaults, per-registration `history_truncated`, and no-resurrection `pre_effect_recheck` bracket | `SPEC-02 §2.2`, `tools/nc_rpc_adapter.py`, `security-conformance.json` |

### 1.4 Sovereign Identity, Manifests, and Custody (`SPEC-03`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-IDEN-001` | `decided` | Namecoin name value encoded as canonical JCS within strict 520-byte budget | `schemas/name-value.schema.json`, `refusal-coverage-matrix.json` (`NAME_VALUE_INVALID`) |
| `SL-IDEN-002` | `decided` | Strict top-level name value members (`link`, `m`, `nostr`) blocking duplicate keys and 71 Unicode case-fold aliases (`WIRE_DUPLICATE`) | `schemas/name-value.schema.json`, `trace-01`–`trace-04`, `security-conformance.json` |
| `SL-IDEN-003` | `decided` | Multi-role keys, on-chain role-policy hash pins (`{"p":...}`), cross-role key & policy-pin disjointness, and uniform `origin` commitment | `schemas/name-value.schema.json`, `trace-02`, `refusal-coverage-matrix.json` (`NAME_ROLE_CHANGED`, `ORIGIN_UNVERIFIED`) |
| `SL-IDEN-004` | `decided` | Name history walk resolving historical role policies at anchor height and recency window | `trace-01`, `refusal-coverage-matrix.json` (`NAME_HISTORY_UNAVAILABLE`, `NAME_ROLE_CHANGED`), `security-conformance.json` |
| `SL-IDEN-005` | `decided` | Closed 22-role key taxonomy, custody tiers, and cold `emergency_fee_reserve` separation | `registry/key-roles.json`, `speclint.py` cross-registry check, `GUIDE-01 §1` |
| `SL-IDEN-006` | `decided` | Single `m` pin authenticating canonical `seallink-manifest/1` (`<= 65536` bytes) and off-chain sets | `schemas/manifest.schema.json`, `trace-01`, `refusal-coverage-matrix.json` (`MANIFEST_MISMATCH`, `MANIFEST_UNAVAILABLE`) |
| `SL-IDEN-007` | `decided` | Pinned `providers[]` declarations and mutual provider/user bindings | `schemas/manifest.schema.json`, `trace-01`, `refusal-coverage-matrix.json` (`SERVICE_PROVIDER_UNBOUND`) |
| `SL-IDEN-008` | `decided` | Manifest `seq` monotonicity, removal semantics, and chain-reorg replacement rules | `refusal-coverage-matrix.json` (`MANIFEST_ROLLBACK`), `tools/seallink_verifier.py` |
| `SL-IDEN-009` | `open` | Non-exclusive 4-channel distribution cascade (cascade `decided`; DNS/TLS domain-bind `open`: `OQ-004`) | `refusal-coverage-matrix.json` (`MANIFEST_UNAVAILABLE`), `OPEN-QUESTIONS.md` (`OQ-004`), `GUIDE-01 §5` |
| `SL-IDEN-010` | `decided` | Provisional key-only onboarding, `auth-challenge/1`, and atomic `auth-upgrade/1` | `schemas/invocation.schema.json`, `refusal-coverage-matrix.json` (`AUTH_CHALLENGE_EXPIRED`, `AUTH_CHALLENGE_INVALID`, `AUTH_KEY_UNPINNED`) |
| `SL-IDEN-011` | `decided` | Owner control plane (`owner-command/1`, L0–L2 levels, device-key enrollment & revocation) | `schemas/invocation.schema.json`, `wire-jcs-and-hashes.json` (Ed25519/P-256), `refusal-coverage-matrix.json` (`DEVICE_UNAUTHORIZED`), `security-conformance.json` |
| `SL-IDEN-012` | `decided` | Host trust-root pin and delayed admin override (`GUIDE-01` runtime boundary) | `SPEC-03 §6`, `schemas/invocation.schema.json`, `GUIDE-01 §4` |

### 1.5 Origin Certificates and Multi-Guardian Governance (`SPEC-04`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-ORIG-001` | `decided` | Three-record separation (`origin/1`, `name-binding/1`, `guardian/1`) and authenticated `status_seal` / `roster_seal` spines | `trace-02`, `trace-04`, `schemas/origin.schema.json`, `schemas/guardian.schema.json` |
| `SL-ORIG-002` | `decided` | Origin-certified class (`person`, `agent`, `organization`), local trusted-issuer allowlist, issuer `link.cred` at anchor height, salted commitments, and `status_seal` binding to `capacity_authority` | `trace-02`, `refusal-coverage-matrix.json` (`ORIGIN_UNVERIFIED`, `ORIGIN_STATUS_INCOMPLETE`), `security-conformance.json`, mutation audit |
| `SL-ORIG-003` | `decided` | Pre-registration issuance, single-use `binding_seal` (`0x0c`), and reverse name-binding uniqueness | `trace-02`, `refusal-coverage-matrix.json` (`ORIGIN_BINDING_INVALID`) |
| `SL-ORIG-004` | `decided` | $N$ equal guardian slots and revision-denominated rational quorum thresholds (`m/n` exact integer math) | `trace-02`, `trace-04`, `schemas/origin.schema.json`, `schemas/guardian.schema.json` |
| `SL-ORIG-005` | `decided` | Four-class linear verifier-derived `event_class` (`routine_read`, `effect_grant`, `contract_assent`, `custody_change`) | `trace-02`, `trace-04`, `refusal-coverage-matrix.json` (`GUARDIAN_QUORUM_UNMET`) |
| `SL-ORIG-006` | `decided` | Protocol-level ward non-autonomy (`WARD_AUTONOMOUS_FORBIDDEN`, `guardian_approvals[]`, fail-safe halt on roster/key change) | `trace-02`, `trace-04`, `refusal-coverage-matrix.json` (`WARD_AUTONOMOUS_FORBIDDEN`, `GUARDIAN_INACTIVE`, `GUARDIAN_QUORUM_UNMET`), `security-conformance.json` |
| `SL-ORIG-007` | `decided` | Direct initial activation (`0x12`), acyclic two-stage appointment (`0x0d` -> `0x0e`), mandatory incoming `guardian_assent`, explicit `challenger_pk`, fast halt | `trace-02`, `trace-04`, `refusal-coverage-matrix.json` (`GUARDIAN_INACTIVE`), `security-conformance.json`, `conformance/traces-regtest/` |
| `SL-ORIG-008` | `decided` | Issuer-key survival: `guardian/1`, `guardian-roster/1`, `capacity/1`, and `end/1` verified against issuer `link.cred` at anchor height (policy-scoped `0x0b` `h_c`) | `trace-02`, `security-conformance.json`, mutation audit |
| `SL-ORIG-009` | `decided` | Calendar (`majority_unix`) vs. indefinite guardianship terms and `seallink-capacity/1` emancipation | `trace-02`, `schemas/origin.schema.json`, `schemas/guardian.schema.json`, `security-conformance.json` |
| `SL-ORIG-010` | `open` | Asymmetric safety pause at majority boundary `T` (safety rule `decided`; time-interval oracle profile `open`: `OQ-001`) | `refusal-coverage-matrix.json` (`GUARDIAN_TIME_BOUNDARY`), `OPEN-QUESTIONS.md` (`OQ-001`) |
| `SL-ORIG-011` | `decided` | Four ward admission states (`under_guardianship`, `halted`, `transfer_pending`, `autonomous`) and fresh subject `ScriptPolicy` handover on emancipation | `refusal-coverage-matrix.json` (`GUARDIAN_TRANSFER_PENDING`), `security-conformance.json`, mutation audit |
| `SL-ORIG-012` | `decided` | Eternal `seallink-end/1` terminally spending `status_seal` (`0x09` -> `SUBJECT_ENDED`) | `refusal-coverage-matrix.json` (`SUBJECT_ENDED`), `security-conformance.json` |
| `SL-ORIG-013` | `decided` | Immutable dual-mode `name_recovery` policy (`none` vs. `dual_party_delayed`) declared in `origin/1` | `trace-02`, `schemas/origin.schema.json`, `refusal-coverage-matrix.json` (`RECOVERY_FORBIDDEN`) |
| `SL-ORIG-014` | `decided` | Delayed recovery activation (`0x0c` + CSV), live-owner `0x10` `RECOVERY_CANCEL` veto restoring `B_k`, and post-delay promotion to `B_{k+1}` with `next_recovery_vout` | `trace-02` (both positive continuation branches), `refusal-coverage-matrix.json` (`RECOVERY_FORBIDDEN`) |
| `SL-ORIG-015` | `decided` | Roster transitions (`seallink-guardian-roster/1`, `0x0f`), slot actions (`retain_active`, `retain_vacant`, `new_vacant`), and ban on retaining slots across `disposer_pk`/`arbiter_pk` rotation | `trace-02`, `constraints-and-schemas.json`, `security-conformance.json`, mutation audit |
| `SL-ORIG-016` | `decided` | Structural guardianship consistency invariants (`n_slots`, quorum ordering, key/policy bounds, slot-action coherence) | `constraints-and-schemas.json` (6 negative vectors), `security-conformance.json`, `seallink_ref.py` |

### 1.6 Contracts, Credentials, Notaries, and Verdicts (`SPEC-05`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-CONT-001` | `decided` | Unilateral grant is base authorization primitive; contract binding is optional and bilateral | `refusal-coverage-matrix.json` (`GRANT_CONTRACT_REQUIRED`, `CONTRACT_NOT_PRESENTED`), `SPEC-05 §1` |
| `SL-CONT-002` | `decided` | N-party salted contracts with mandatory unique `party_id`, `ward_origin_id`, and `machine_clause_indices` completeness | `wire-jcs-and-hashes.json`, `trace-02`, `refusal-coverage-matrix.json` (`CONTRACT_TERMS_MISMATCH`, `CONTRACT_ID_MISMATCH`), `security-conformance.json` |
| `SL-CONT-003` | `decided` | Framework contract nesting depth capped at 1 (`framework_id` non-transitive) | `schemas/contract.schema.json`, `security-conformance.json` (`CONTRACT_NOT_PRESENTED`, `CONTRACT_ID_MISMATCH`, `CONTRACT_TERMS_MISMATCH`, `CONTRACT_SEAL_MISSING`) |
| `SL-CONT-004` | `decided` | Symmetric native `seallink-assent/1` (with `party_id` 1-to-1 coverage and ward `guardian_approvals[]`) and anchoring | `trace-02` (ward + co-tenant same-role assents), `refusal-coverage-matrix.json` (`CONTRACT_ASSENT_INVALID`), `security-conformance.json` |
| `SL-CONT-005` | `decided` | Confirmed contract seal spend determines termination (`SEAL_SPENT` / `CONTRACT_SEAL_MISSING`) | `refusal-coverage-matrix.json` (`CONTRACT_SEAL_MISSING`, `SEAL_SPENT`), `tools/seallink_verifier.py` |
| `SL-CONT-006` | `decided` | Agreed configuration commitment (`config_sha256`) enforced on contract-bound invocations | `refusal-coverage-matrix.json` (`CONTRACT_CONFIG_MISMATCH`), `PROFILE-agent-v1.md` |
| `SL-CONT-007` | `decided` | Chained violation verdicts (`0x03`, `seallink-verdict/1`) and salted request attribution | `schemas/contract.schema.json`, `registry/opreturn-actions.json` (`0x03`) |
| `SL-CONT-008` | `decided` | Verifiable credentials (`eternal` `0x09` vs. `revocable` `0x0a`) signed by issuer `link.cred` | `schemas/credential.schema.json`, `refusal-coverage-matrix.json` (`CRED_ANCHOR_MISSING`, `CRED_REVOKED_FOR_CAUSE`) |
| `SL-CONT-009` | `decided` | Owner-authenticated policy-scoped compromise break `h_c` (`0x0b`) invalidating only matching `compromised_policy` at `h >= h_c` | `refusal-coverage-matrix.json` (`CRED_ISSUER_CLOSED`), `security-conformance.json` (4-case A/B rotation & cutoff matrix) |
| `SL-CONT-010` | `decided` | Deterministic credential verification order (wire -> anchor -> issuer role & policy-scoped `h_c` -> window -> revocable seal) | `refusal-coverage-matrix.json` (`CRED_ANCHOR_MISSING`, `CRED_ISSUER_CLOSED`, `CRED_WINDOW_CLOSED`, `CRED_REVOKED_FOR_CAUSE`) |
| `SL-CONT-011` | `decided` | General off-authority-path notary acts (`seallink-notary/1`, `0x04`/`0x05`) | `schemas/credential.schema.json`, `registry/opreturn-actions.json` (`0x04`, `0x05`) |

### 1.7 Universal Grants, Delegation, Sessions, and Fenced Journals (`SPEC-06`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-GRNT-001` | `decided` | Universal `seallink-grant/1` (`<= 65536` bytes) across all actors and service profiles | `schemas/grant.schema.json`, `trace-01`, `trace-03`, `trace-04` |
| `SL-GRNT-002` | `decided` | Three recipient modes (`key`, `name`, `group` threshold) authenticated prior to receipt cache lookup | `trace-01` (`name`), `trace-03` (`key`), `trace-04`, `refusal-coverage-matrix.json` |
| `SL-GRNT-003` | `decided` | Concrete `executor` binding vs. stateless `executor_ref` matching | `trace-01`, `refusal-coverage-matrix.json` (`GRANT_EXECUTOR_MISMATCH`, `GRANT_EXECUTOR_REF_FORBIDDEN`), `security-conformance.json` |
| `SL-GRNT-004` | `decided` | Validity block window `[not_before_height, not_after_height)` and revocation modes (`seal` vs. root `window_only <= 12` blocks) | `refusal-coverage-matrix.json` (`GRANT_WINDOW_CLOSED`, `GRANT_CLOSED`, `WIRE_INTEGER`) |
| `SL-GRNT-005` | `decided` | Text-vs-effect invariant: mechanical effect executors refuse `terms_text` | `constraints-and-schemas.json`, `refusal-coverage-matrix.json` (`GRANT_TEXT_FORBIDDEN`) |
| `SL-GRNT-006` | `decided` | Signed `seallink-invocation/1` and acyclic `single_use` (`0x11`) delivery & durable consumption | `trace-03`, `refusal-coverage-matrix.json` (`GRANT_CLOSED`, `INVOKE_REPLAY`, `INVOKE_TIME_INVALID`), `conformance/traces-regtest/` |
| `SL-GRNT-007` | `decided` | Atomic two-phase dual-account (`own` + per-`row_ordinal` `row`) multi-quota reservation, rollback on partial refusal, and conservative settlement | `trace-03`, `security-conformance.json` (sibling-row isolation + journal replay), `refusal-coverage-matrix.json` (`QUOTA_EXCEEDED`, `QUOTA_CLOCK_REGRESSION`) |
| `SL-GRNT-008` | `decided` | Signed `seallink-receipt/1` (`settlements.maxItems = 64`, `account`, `row_ordinal`, `window`) binding invocation and `result_sha256` | `schemas/invocation.schema.json`, `trace-01`, `trace-03`, `trace-04`, `security-conformance.json` (32-quota / 64-line max receipt test) |
| `SL-GRNT-009` | `decided` | Bounded depth-2 re-delegation, pairwise-disjoint `R8.6` row-coin and stop-coin ranges | `trace-03`, `refusal-coverage-matrix.json` (`GRANT_NOT_DELEGABLE`, `GRANT_ROW_INVALID`), `security-conformance.json` |
| `SL-GRNT-010` | `decided` | Whole-parent aggregate budget sum `R8.5` (`sum(rows * cap) <= pool_max`) and mechanical child attenuation | `trace-03`, `refusal-coverage-matrix.json` (`GRANT_CHILD_WIDER`), `security-conformance.json` |
| `SL-GRNT-011` | `decided` | Optional notary endorsement and per-row stop coins (`GRANT_ROW_STOPPED`) | `schemas/grant.schema.json`, `refusal-coverage-matrix.json` (`GRANT_ROW_STOPPED`, `NOTARY_REQUIRED`) |
| `SL-GRNT-012` | `decided` | Exact 12-step deterministic invocation admission pipeline (early auth, Step 10d `executor_ref` capability check, Step 11b `INVOKE_ACTION_DENIED`, crash `uncertain`) | `trace-01`, `trace-03`, `trace-04`, `refusal-coverage-matrix.json`, `security-conformance.json` |
| `SL-GRNT-013` | `decided` | Short-lived (`<= 3600s`) bearer sessions (`seallink-session-open/1`) with per-use chain & seal recheck | `schemas/invocation.schema.json`, `refusal-coverage-matrix.json` (`SESSION_INVALID`) |
| `SL-GRNT-014` | `open` | Hash-chained anti-rollback `FencedJournal`, external CAS witness fencing, and `+7200s` recovery boundary (semantics `decided`; CAS witness wire `open`: `OQ-003`) | `trace-01`, `trace-03` (persisted replay + `uncertain`), `refusal-coverage-matrix.json` (`JOURNAL_LOST`, `JOURNAL_FENCED`), `OPEN-QUESTIONS.md` (`OQ-003`) |

### 1.8 Replaceable Services, Portability, Federation, and Extensions (`SPEC-07`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-SERV-001` | `decided` | Sovereign provider model, mutual manifest bindings, and pinned TLS mutual auth | `trace-01`, `refusal-coverage-matrix.json` (`SERVICE_PROVIDER_UNBOUND`), `GUIDE-01 §5` |
| `SL-SERV-002` | `decided` | Replaceable services, 3-class export boundary (no execution secrets), and `seallink-migration/1` signed by `source_executor` `service.receipt_key` | `schemas/invocation.schema.json`, `refusal-coverage-matrix.json` (`SERVICE_MIGRATION_INVALID`), `security-conformance.json` |
| `SL-SERV-003` | `decided` | Four-step exclusive provider cut-over preventing split-brain dual execution | `SPEC-07 §2.2`, `refusal-coverage-matrix.json` (`SERVICE_MIGRATION_INVALID`), `security-conformance.json` |
| `SL-SERV-004` | `decided` | Two-phase federated screening (zero PII) and L2-gated Contour A targeted disclosure | `refusal-coverage-matrix.json` (`FEDERATION_POLICY_DENIED`), `security-conformance.json`, `tools/seallink_verifier.py` |
| `SL-SERV-005` | `decided` | SLIP extension registration checklists for new service profiles, actions, quotas, contracts, and credentials | `SLIP-TEMPLATE.md`, `registry/service-types.json`, `SPEC-07 §4` |

### 1.9 Standard Domain Profiles (`PROFILE-mail-v1`, `PROFILE-agent-v1`)

| Rule ID | Status | Normative Requirement | Primary Verification / Conformance Coverage |
| --- | :-: | --- | --- |
| `SL-MAIL-001` | `decided` | User manifest provider binding for `service_type = "mail"` | `trace-01`, `schemas/manifest.schema.json`, `PROFILE-mail-v1.md §2.1` |
| `SL-MAIL-002` | `decided` | Mail provider self-declaration, external discovery, and mutual TLS/key auth | `trace-01`, `PROFILE-mail-v1.md §2.2`, `GUIDE-01 §5` |
| `SL-MAIL-003` | `decided` | Closed argument/result JSON Schemas for `mail/list`, `mail/read`, `mail/send` | `schemas/profile-mail.schema.json`, `trace-01`, `security-conformance.json` (`WIRE_MEMBER`) |
| `SL-MAIL-004` | `decided` | Server-side enforcement of constrained mail arguments (`folder`, `recipient`, `max_bytes`) | `trace-01`, `refusal-coverage-matrix.json` (`INVOKE_CONSTRAINT_FAILED`), `security-conformance.json` (`INVOKE_ACTION_DENIED`) |
| `SL-MAIL-005` | `decided` | Snapshot cursor pagination and exclusive mailbox provider cut-over | `schemas/profile-mail.schema.json`, `PROFILE-mail-v1.md §5` |
| `SL-MAIL-006` | `decided` | Normative `result_sha256` formula hashing exact MIME / response payload bytes | `trace-01` (exact 69-byte MIME hash verification in `speclint.py`) |
| `SL-AGNT-001` | `decided` | Agent runtime manifest declarations (`service_type = "agent-session"`) and mutual auth | `trace-03`, `trace-04`, `schemas/manifest.schema.json` |
| `SL-AGNT-002` | `decided` | Closed argument/result JSON Schemas for `agent/brief`, `agent/tool`, `agent/session`, `agent/guardian-message` | `schemas/profile-agent.schema.json`, `trace-03`, `trace-04`, `speclint.py` |
| `SL-AGNT-003` | `decided` | Normative `result_sha256` commitment over canonical JCS result body | `trace-03`, `trace-04`, `schemas/profile-agent.schema.json` |
| `SL-AGNT-004` | `decided` | Normative `agent/guardian-message` intake verification (`strict_drop` ward default, `event_class = "effect_grant"`, `guardian_approvals[]`) | `trace-04` (full positive + negative intake steps), `schemas/profile-agent.schema.json` |
| `SL-AGNT-005` | `decided` | Contract-bound sessions, dual-account (`own` + per-`row_ordinal` `row`) multi-quota enforcement, and `config_sha256` binding | `trace-03`, `refusal-coverage-matrix.json` (`CONTRACT_CONFIG_MISMATCH`, `QUOTA_EXCEEDED`), `security-conformance.json` |

---

## 2. Historical Behavioral Rule Traceability (Migration from Draft Corpus)

**Historical source corpus migrated into cleanroom SealLink v1.0:**
- `swarma-link-spec` v0.1.67 (`protocol/*`, `decisions/0001..0004`, `LIP-0001` through `LIP-0038`, `LIP-0014-source-contract-proposals`, `KEY-MAP.md`, `KEY-REGISTRY.md`, `UNRESOLVED_QUESTIONS.md`)
- `FINAL-ru.md` (Birth & Materialization Certificates / Guardianship design, `P1`–`P20`, 24 specification items)
- `book/ru/` v2.0 (Swarma Runtime & Platform boundary)

| Historical Rule / Source | Invariant | SealLink v1.0 Rule ID(s) | Status | Witness / Vector |
| --- | --- | --- | :-: | --- |
| `protocol/observation.md`, `LIP-0008 §4` | Independent verification on verifier's own chain view; local pins only | `SL-ARCH-001`, `SL-LDGR-002`, `SL-LDGR-008` | `decided` | `trace-01`, `security-conformance.json` |
| `LIP-0020 W1–W9` | Restricted RFC 8785 JCS, no `null`, `uint53`/`uint64_str`, 3 hashes, tagged digests | `SL-WIRE-001`–`SL-WIRE-011`, `SL-WIRE-018` | `decided` | `wire-jcs-and-hashes.json` |
| `LIP-0020 W11.11`, `LIP-0008 §12.6` | Monotonic attenuation (`child <= parent`) checked mechanically | `SL-ARCH-005`, `SL-WIRE-015`–`SL-WIRE-017`, `SL-GRNT-010` | `decided` | `constraints-and-schemas.json`, `trace-03` |
| `LIP-0021 O3.2` | Three distinct Namecoin prefix grammars (`NAME_NEW`, `NAME_FIRSTUPDATE`, `NAME_UPDATE`) | `SL-LDGR-005` | `decided` | `ledger-scripts-and-opreturn.json` |
| `LIP-0021 O3.3` | Owner authorship requires spent previous name input + strict `SIGHASH_ALL` (`0x01`) | `SL-LDGR-007` | `decided` | `trace-01`, `refusal-coverage-matrix.json` |
| `LIP-0021 O3.5`, `LIP-0010`, `LIP-0027` | Three-valued seal semantics (`unspent` / `revoked` / `unavailable`; missing != unspent) | `SL-ARCH-002`, `SL-LDGR-011` | `decided` | `trace-01`, `trace-03` |
| `LIP-0022` | Tip snapshot bracket, `>= 1` healthy comparison node (`CHAIN_UNHEALTHY`), dual `tip_age` (`first_sight`), recency `(R, R+K]` | `SL-LDGR-008` | `decided` *(constants `open`: `OQ-010..013`)* | `trace-01`, `security-conformance.json` |
| `LIP-0023` | Witness construction profile `W`, non-malleable SegWit inputs, linkage `seal_vout + 1` | `SL-LDGR-009` | `decided` | `ledger-scripts-and-opreturn.json`, `refusal-coverage-matrix.json` |
| `LIP-0002` | `single_use_1_of_2` branch attribution (issuer revoke vs grantee use), input-first scan | `SL-LDGR-004`, `SL-LDGR-012`, `SL-GRNT-006` | `decided` | `trace-03`, `conformance/traces-regtest/` |
| `LIP-0003` | Batch anchor `0x02` Merkle commitment | `SL-LDGR-014` | `decided` | `ledger-scripts-and-opreturn.json` |
| `LIP-0005` | Framed `OP_RETURN` action & non-exclusive locator table | `SL-LDGR-010`, `registry/opreturn-actions.json` | `decided` (`0x06` reserved) | `ledger-scripts-and-opreturn.json` |
| `LIP-0010`, `LIP-0033` | 520B name value budget, single `m` pin, 4-channel non-exclusive distribution cascade | `SL-IDEN-001`–`SL-IDEN-004`, `SL-IDEN-009` | `decided` *(domain bind `open`: `OQ-004`)* | `trace-01` |
| `LIP-0010 H51`, `LIP-0029` | Disposable CSPRNG fast-revocation seal + mandatory TRUC v3 / `P2A` CPFP fee-bump output | `SL-LDGR-013`, `SL-IDEN-005` | `decided` format *(2-node regtest passed; prod propagation `open`: `OQ-006`)* | `ledger-scripts-and-opreturn.json`, `conformance/p2a-regtest/` |
| `KEY-REGISTRY` Rules 1–3, `KEY-MAP` | Strict key-role separation + cold `emergency_fee_reserve` (`m/84'/7'/3'`) | `SL-ARCH-006`, `SL-IDEN-005`, `registry/key-roles.json` | `decided` | `speclint.py` cross-registry check |
| `LIP-0034` | Dedicated `auth_key` + `auth_seal`, provisional key-only cells, atomic `auth-upgrade` | `SL-IDEN-010` | `decided` | `schemas/invocation.schema.json`, `refusal-coverage-matrix.json` |
| `LIP-0029`, `LIP-0015` | L0–L2 owner control plane, level inheritance, trust-root pin + delayed admin override | `SL-IDEN-011`, `SL-IDEN-012` | `decided` *(FIDO2/SSH `open`: `OQ-005`)* | `schemas/invocation.schema.json`, `wire-jcs-and-hashes.json` |
| `LIP-0017 C10–C12` | N-party salted contracts with unique `party_id`, framework depth 1, confirmed contract seal determines termination | `SL-CONT-001`–`SL-CONT-006` | `decided` | `wire-jcs-and-hashes.json`, `trace-02` |
| `LIP-0011 J8` | Chained violation verdicts (`0x03`) and salted invocation attribution | `SL-CONT-007` | `decided` | `schemas/contract.schema.json` |
| `LIP-0032`, `LIP-0021 §7.6` | Eternal vs revocable credentials (`0x09`/`0x0a`), owner-authenticated policy-scoped `h_c` break (`0x0b`), general notary (`0x04`/`0x05`) | `SL-CONT-008`–`SL-CONT-011` | `decided` | `schemas/credential.schema.json`, `refusal-coverage-matrix.json`, `security-conformance.json` |
| `LIP-0006 §7`, `LIP-0035` | Unilateral base grant; mechanical effect executors refuse `terms_text`; atomic dual-account (`own` + per-`row_ordinal` `row`) reserve before effect | `SL-ARCH-004`, `SL-GRNT-001`, `SL-GRNT-005`, `SL-GRNT-007` | `decided` | `constraints-and-schemas.json`, `trace-01`, `trace-03`, `security-conformance.json` |
| `LIP-0026 R8.5` | Whole-parent aggregate budget sum across all row groups (`sum(rows * cap) <= pool_max`) | `SL-GRNT-010` | `decided` | `trace-03`, `security-conformance.json` |
| `LIP-0026 R8.6` | Pairwise-disjoint row-coin and stop-coin ranges across all groups | `SL-GRNT-009` | `decided` | `trace-03`, `security-conformance.json` |
| `LIP-0027 H1–H4` | Notary per-row stop coins (`GRANT_ROW_STOPPED`) | `SL-GRNT-011` | `decided` | `schemas/grant.schema.json`, `refusal-coverage-matrix.json` |
| `LIP-0025 M4.6` | Hash-chained anti-rollback journal + external CAS witness fencing + `+7200s` recovery boundary | `SL-GRNT-014` | `decided` *(witness wire `open`: `OQ-003`)* | `trace-01`, `trace-03` |
| `LIP-0028` | Short-lived (`<= 3600s`) bearer sessions with per-use chain/seal recheck | `SL-GRNT-013` | `decided` | `schemas/invocation.schema.json`, `refusal-coverage-matrix.json` |
| `LIP-0009` | Replaceable services, 3-class export boundary, 4-step exclusive cut-over | `SL-SERV-001`–`SL-SERV-003` | `decided` | `PROFILE-mail-v1.md`, `PROFILE-agent-v1.md`, `security-conformance.json` |
| `LIP-0036` | Two-phase federated screening (zero PII) -> L2-gated Contour A targeted disclosure | `SL-SERV-004` | `decided` | `SPEC-07 §3`, `security-conformance.json` |
| `LIP-0038` | Effect leaves (`post-message`, `spend-coins`, `name-update`, `model-call`) | `SL-SERV-005`, `OPEN-QUESTIONS.md` | **Deferred** (except `mail` & `agent-session` profiles) | `PROFILE-mail-v1.md`, `PROFILE-agent-v1.md` |
| `LIP-0024 §2`, `LIP-0004`, `LIP-0016 §2–3` | Legacy v0.1/v3 wire formats, Nostr `kind 8181`, seal endorsement, UTXO cert head `0x06` | **Retired** | Retired | Replaced by `SPEC-01`/`03`/`05`/`06` |

---

## 3. Guardianship and Origin Certificate Traceability (`FINAL-ru.md` `P1`–`P20` & 24 Items)

| Item | Topic | SealLink v1.0 Resolution | Status |
| --- | --- | --- | :-: |
| `P1–P2` | Origin-certified class (`person`, `agent`, `organization`) distinct from unverified cards | `SL-ARCH-008`, `SL-ORIG-002` | `decided` |
| `P3–P4` | Three-record separation (`origin/1`, `name-binding/1`, `guardian/1`) + identity permanence | `SL-ORIG-001`, `SL-ORIG-003` | `decided` |
| `P5` | Pre-registration issuance + single-use `binding_seal` (`0x0c`) + reverse uniqueness | `SL-ORIG-002`, `SL-ORIG-003` | `decided` |
| `P6–P7` | Privacy of public chain (`link.origin`) + salted commitments for initial guardians and `majority_unix` | `SL-ARCH-012`, `SL-IDEN-003`, `SL-ORIG-002` | `decided` |
| `P8–P9` | $N$ equal guardian slots + revision-denominated quorums + 4-class linear verifier-derived `event_class` + `SL-ORIG-016` consistency | `SL-ORIG-004`, `SL-ORIG-005`, `SL-ORIG-016` | `decided` |
| `P10` | Protocol-level ward non-autonomy (`WARD_AUTONOMOUS_FORBIDDEN`, `guardian_approvals[]`, fail-safe ward grant halt on roster/key change) | `SL-ORIG-006`, `SL-WIRE-013` | `decided` |
| `P11–P13` | Direct initial activation (`0x12`), acyclic two-stage appointment (`0x0d` pending -> `0x0e` active), incoming `guardian_assent`, explicit `challenger_pk`, fast halt, `0x0f` roster transition (`retain_active`/`retain_vacant`/`new_vacant`, banned on `disposer_pk`/`arbiter_pk` rotation) | `SL-ORIG-007`, `SL-ORIG-015` | `decided` |
| `P14` | Native `P2WSH` `m-of-n` multisig name ownership via `namepsbt` (ECDSA, no FROST on P2WPKH, no covenant renewal branch) | `SL-LDGR-004`, `SL-LDGR-006` | `decided` *(threshold ECDSA `open`: `OQ-007`)* |
| `P15–P16` | Calendar vs indefinite terms; asymmetric safety pause at majority boundary `T` | `SL-ORIG-009`, `SL-ORIG-010` | **Time oracle `open`** (`OQ-001`) |
| `P17` | Authenticated completeness via `status_seal` (bound to `capacity_authority`, institutional DoS fail-closed) and `roster_seal` spines (`ORIGIN_STATUS_INCOMPLETE`) | `SL-ORIG-001`, `SL-ORIG-002`, `SL-ORIG-015` | `decided` |
| `P18` | Four ward admission states (`under_guardianship`, `halted`, `transfer_pending`, `autonomous`) + fresh subject `ScriptPolicy` on emancipation | `SL-ORIG-011` | `decided` |
| `P19` | Eternal `seallink-end/1` terminating `status_seal` (`SUBJECT_ENDED`); issuer-key survival at anchor height | `SL-ORIG-008`, `SL-ORIG-012` | `decided` |
| `P20` | Dual-mode `name_recovery` (`none` vs `dual_party_delayed`) + live-owner `0x10` `RECOVERY_CANCEL` veto restoring `B_k` + delayed promotion to `B_{k+1}` | `SL-ORIG-013`, `SL-ORIG-014` | `decided` |

---

## 4. Historical Corpus Disposition Summary (38 Draft LIPs)

- **Core Backbone Consolidated (`SPEC-00`–`SPEC-07`):** `LIP-0001`, `0002`, `0003`, `0005`, `0006`, `0007`, `0008`, `0009`, `0010`, `0011`, `0012`, `0014`, `0015`, `0016` (§1/§3.1/§4), `0017`, `0018`, `0019`, `0020`, `0021`, `0022`, `0023`, `0025`, `0026`, `0027`, `0028`, `0029`, `0031`, `0032`, `0033`, `0034`, `0035`, `0036`, `0037`.
- **Moved to Profiles (`profiles/`) or Open Profiles (`OPEN-QUESTIONS.md`):** `LIP-0009` (`blob`), `LIP-0030` (`PROFILE-agent-v1.md` + external Swarma Runtime), `LIP-0038` (`wallet`, `names`, `compute`).
- **Moved to Informative Guide (`guides/GUIDE-01-custody-and-signers.md`):** `LIP-0013` (§3.4/§3.6 Authority Frame & Keymaker run-origin gate), `LIP-0014` companion (Keychain/Curator host seams, delegation signer reservation ledger), `KEY-MAP.md` operational tips, TLS SPKI pinning & managed CDN guidance.
- **Retired (Cleanroom v1.0):** `protocol/*` v0.1 bytes, `LIP-0004` (v3 & Nostr `kind 8181`), `LIP-0013` v3 / Matrix `8185`, `LIP-0014` v3 `/2` & `8186`, `LIP-0016` §2–3 UTXO cert head `0x06`, `LIP-0024` §2 seal endorsement.
