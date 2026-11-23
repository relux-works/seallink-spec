# SPEC-05: Contracts, Symmetric Assent, Verifiable Credentials, and General Notary Acts

- **Version:** `1.0.0-draft.5`
- **Status:** `draft` (normative rules `decided`)
- **Evidence / Maturity:** `vectors` (`vectors/wire-jcs-and-hashes.json`, `vectors/trace-02-guardian-succession-assent.json`, `vectors/refusal-coverage-matrix.json`)
- **Registries:** `registry/object-types.json`, `registry/key-roles.json`, `registry/opreturn-actions.json`, `registry/refusal-codes.json`
- **Schemas:** `schemas/contract.schema.json`, `schemas/credential.schema.json`

---

## 1. Relationship Between Grants and Contracts

In SealLink v1.0, a **unilateral grant (`SPEC-06`) is the base authorization primitive**: it requires no recipient assent and imposes no obligations on the recipient. A **contract (`seallink-contract/1`)** is the bilateral or multilateral overlay that adds mutual agreement, obligations, framework governance, and shared or arbiter-controlled termination (`SL-CONT-001`, `decided`).

- A contract MAY exist without any grant (e.g., an anchored agreement between two people or organizations).
- Any action profile imposing payment, work, rental, or liability obligations on the recipient (such as `rental` or contract-bound `agent/session`) MUST declare `requires_contract = true`; executors refuse unilateral grants for such actions (`GRANT_CONTRACT_REQUIRED`).

---

## 2. N-Party Structured Contracts (`seallink-contract/1`)

### 2.1 Structure, Salted Selective Disclosure, and Machine-Clause Completeness (`SL-CONT-002`, `decided`)

A `seallink-contract/1` object (`<= 65536` bytes, `schemas/contract.schema.json`) binds `N >= 2` parties (any combination of people, organizations, agents, or unverified actors):

1. **Header fields:** `type`, `network`, `genesis`, `profile`, `contract_salt` (32 CSPRNG bytes, preventing offline guessing of short contracts), `parties[2..32]` — where each entry carries a mandatory unique-within-contract **`party_id`** (`^[a-z0-9][a-z0-9._-]{0,63}$`, allowing multiple parties to share a legal `role` such as co-tenants `"tenant"` with `"tenant-1"` and `"tenant-2"`; duplicate `party_id` refuses `WIRE_MEMBER`) and is either an **autonomous party** `{party_id, role, name_pin?, signing_policy: ThresholdPolicy}` or a **ward party** `{party_id, role, ward_origin_id, name_pin}` (omitting static `signing_policy` so guardian succession never invalidates a live contract) — `window` (`not_before_height`, optional `not_after_height`, optional calendar `not_after_unix`), optional `machine_clause_indices`, optional `framework_id`, optional/required `seal`, optional `assent_output`, optional `config_sha256`, and optional `moderation`.
2. **Clauses & Selective Disclosure:** Each clause `i` is a canonical JCS object containing free-text prose (`text`, where `\n` is allowed per `SL-WIRE-005`), typed machine terms (mirroring any bound grant capabilities/quotas), or both. The contract stores ONLY the ordered array `clause_commitments[]` where:
   ```text
   clause_commitments[i] = H_tag("seallink-clause/1", salt_i || canonical_JCS(clause_i))
   contract_id           = SHA256(canonical_JCS(seallink-contract/1))
   ```
   When a grant binds `contract_id` (and optionally `framework_id`), both complete contract documents MUST be presented (`CONTRACT_NOT_PRESENTED`) and MUST recompute to their bound identifiers (`CONTRACT_ID_MISMATCH`).
3. **Deterministic machine-clause completeness:** Every clause index carrying machine-enforced terms MUST be listed in strictly ascending order in `machine_clause_indices[]` (with every index `< len(clause_commitments)`). An executor MUST require disclosure of `(salt_i, clause_i)` for EVERY index `i` in `machine_clause_indices[]`, verify `commit(salt_i, clause_i) == clause_commitments[i]`, and check every disclosed machine term against the bound grant (`CONTRACT_TERMS_MISMATCH` on missing disclosure or mismatch). Prose-only clauses outside `machine_clause_indices[]` MAY remain undisclosed to the executor.
4. **Framework Nesting (`SL-CONT-003`, `decided`):** A contract MAY name at most one `framework_id`, and a framework contract MUST NOT name another framework contract (maximum nesting depth = 1). Every grant's window MUST nest inside its bound contract's window, which MUST nest inside its framework contract's window.

### 2.2 Symmetric Native Assent (`seallink-assent/1`) and Anchoring (`SL-CONT-004`, `decided`)

1. **Symmetric off-chain assent:** A contract is concluded when EVERY distinct `party_id` in `parties[]` is covered 1-to-1 by a valid identical-format `seallink-assent/1` (`<= 32768` bytes, accommodating multi-guardian `guardian_approvals[]` and up to 32-of-32 `SignatureSet`, `target_type = "seallink-contract/1"`, `target_id = contract_id`, matching `party_id` and `party_role == party.role`; duplicate or missing `party_id` assents refuse `CONTRACT_ASSENT_INVALID`):
   - Permitted signer roles for `seallink-assent/1` are strictly `grant` and `guardian_quorum` (`registry/object-types.json`, coherent with `registry/key-roles.json`); `auth` and `device` keys MUST NEVER sign `seallink-assent/1` (`WIRE_SIGNATURE`).
   - For an **autonomous party** (`signing_policy` present), `seallink-assent/1` uses the ordinary `{"payload","signatures"}` envelope whose `signatures.policy` MUST strictly equal `party.signing_policy` (`SL-WIRE-013`).
   - For a **ward party** (`ward_origin_id` present, `SPEC-04`), `seallink-assent/1` MUST carry `payload.guardian_context` (`origin_id == party.ward_origin_id`, `ward_name == party.name_pin.name`, `event_class = "contract_assent"`, `revision` matching the ward's active roster revision) and top-level `guardian_approvals[]` satisfying `required("contract_assent")` across distinct active guardian slots (`SL-ORIG-006` refusal precedence: `WARD_AUTONOMOUS_FORBIDDEN`, then `GUARDIAN_INACTIVE`, then `WIRE_SIGNATURE`, then `GUARDIAN_QUORUM_UNMET`).
   - Assent freshness for grant issuance is at most `72` hours (`259200s`) and single-use per issuance (`CONTRACT_ASSENT_INVALID`).
2. **Contract anchor (`0x07`):** A contract is anchored via `OP_RETURN` action `0x07` committing `contract_id` (`loc_type = 0x00` default for private contracts).
3. **Optional on-chain assent:** Parties MAY additionally name a confirmed `N-of-N` `P2WSH` `assent_output` in `seallink-contract/1` and have the `0x07` anchor transaction spend it (`SIGHASH_ALL` on all signatures), proving mutual assent on chain even to observers who never see contract plaintext.

### 2.3 The Contract Seal Decides Termination (`SL-CONT-005`, `decided`)

1. **Mandatory seal before signing:** Every framework contract and every contract under which any grant is issued MUST name a confirmed `seal` created **before** parties sign `seallink-assent/1`. Signing services and verifiers MUST check confirmation and exact compiled `ScriptPolicy` match of both the bound contract's seal and any named framework contract's seal on their own node (`CONTRACT_SEAL_MISSING` on conclusive absence/mismatch; `SEAL_UNAVAILABLE` on inconclusive read).
2. **Script derives termination type — never prose:** Every reader, renderer, and UI MUST derive the contract's termination type strictly from `seal.script_policy` (`SL-LDGR-004`):
   - `{"kind":"key"}` -> **`issuer_only`**
   - `{"kind":"branch","template":"either_of_2"}` -> **`either_party`**
   - `{"kind":"branch","template":"both_of_2"}` -> **`both_together`**
   - `{"kind":"branch","template":"arbiter_or_both"}` -> **`arbiter`**
   A prose clause describing termination binds parties as text only and NEVER ends a contract or overrides the script-derived type.
3. **One spend ends all grants:** Spending a contract or framework seal (`SEAL_SPENT`) durably terminates every grant bound to that contract (or framework) upon first observation. The spending transaction SHOULD carry `OP_RETURN` action `0x08` committing `typed_digest(seallink-termination/1)` (`SIGHASH_ALL`); however, the spend alone terminates the contract regardless of whether `0x08` is valid or present.

### 2.4 Agreed Configuration Hash (`SL-CONT-006`, `decided`)

Any contract profile under which a runtime launches a configured agent (`profiles/PROFILE-agent-v1.md`) MUST require `config_sha256`. A runtime launcher that cannot reproduce `config_sha256` from the exact profile, skills, and tools it is about to launch MUST refuse to start (`CONTRACT_CONFIG_MISMATCH`).

---

## 3. Violation Verdicts and Salted Request Attribution (`seallink-verdict/1`)

For moderated contracts (e.g., hosted services or agent sessions), `seallink-contract/1` MAY declare `moderation: {rules_sha256, moderator_key, moderator_kind}` (`SL-CONT-007`, `decided`):

1. Each recorded violation is a moderator-signed `seallink-verdict/1` chained via `ordinal` and `prev_verdict_id`, committing to `rules_sha256`, `violated_rule`, `request_salted_sha256`, and `response_salted_sha256`.
2. **Salted invocation attribution:** To allow dispute evidence without exposing plaintext on chain or enabling dictionary guesses against short messages, `seallink-invocation/1` MAY include a fresh 32-byte `content_salt` (distinct from `nonce`), with `salted_hash = SHA256(content_salt || plaintext_bytes)`.
3. A grant-seal revocation spend MAY include `OP_RETURN` action `0x03` committing `typed_digest(seallink-verdict/1)`. Closure still follows the seal spend alone; the verdict frame supplies auditable dispute evidence.

---

## 4. Verifiable Credentials (`seallink-credential/1`)

Third-party attestations about a subject — diplomas, licenses, notary credentials, human-verification claims (`subject-claim`), runtime isolation audits (`agent-audit`), and work-completion acts — share one object type: **`seallink-credential/1`** (`SL-CONT-008`, `decided`).

### 4.1 Lifecycles, Anchoring, and Compromise Cutoff `h_c`

1. **Signing role:** Signed ONLY by the issuer's `link.cred` role policy (`issuer.role_policy`, verified per `SL-IDEN-003` and `SL-WIRE-013`). A credential is NEVER a grant and confers zero execution authority by itself; verifier policies may only use credentials to narrow admission.
2. **Signed-form anchoring (`0x09`):** Every credential MUST be anchored via `OP_RETURN` action `0x09` committing **`content_addr = SHA256(signed_bytes)`**, proving the signature existed at or before the earliest confirmed anchor block `h_anchor` (`CRED_ANCHOR_MISSING`).
3. **Two lifecycles:**
   - **`eternal`:** MUST NOT carry `revocation_seal`; `not_after_height` optional. Verified against the historical registration lineage matching `issuer.registration` at `h_anchor` (`link.cred` role policy active at `h_anchor`). Survives routine issuer key rotation, expiry, transfer, and lawful later re-registration of the same name spelling by another holder (while current tip lookups by spelling resolve to the new holder).
   - **`revocable`:** MUST carry a confirmed `revocation_seal`; `not_after_height` is optional. By default verifies the issuer's `link.cred` role policy current at tip (exceptions such as `seallink-guardian/1` verify at `h_anchor`, `SL-ORIG-008`). Spending the seal closes the credential (`SEAL_SPENT`); spending with `OP_RETURN 0x0a` (`seallink-credential-withdrawal/1`) records `CRED_REVOKED_FOR_CAUSE`.
4. **Owner-authenticated compromise break `h_c` (`0x0b`, `SL-CONT-009`, `decided`):**
   - If an issuer's `cred` or `notary` role policy (current or retired) is compromised, the issuer's cold `name_owner` `ScriptPolicy` broadcasts an `OP_NAME_UPDATE` (removing/replacing the role if current, signed `SIGHASH_ALL`) containing the 50-byte `0x0b` frame embedding `h_c_le64` (`<= inclusion_height`) and `typed_digest(seallink-credential-break/1)`.
   - Because verifiers reconstruct `seallink-credential-break/1` directly from the name history (using the spent previous name output `name_input`, `issuer` `NamePin`, `role`, candidate historical `compromised_policy`, and on-chain `h_c`), withholding off-chain break documents cannot hide a compromise.
   - For the exact affected `(issuer, registration, owner_policy, role, compromised_policy)` whose reconstructed `typed_digest(seallink-credential-break/1)` matches the `0x0b` frame commitment: anchors at `h_anchor < h_c` survive, while anchors at `h_anchor >= h_c` durably refuse **`CRED_ISSUER_CLOSED`** (for both eternal and revocable lifecycles). Multiple breaks matching the same policy narrow by `min(h_c)`. Records signed by a distinct successor policy `B` installed via valid `OP_NAME_UPDATE` (or under a different role) do NOT match `compromised_policy = A` and therefore remain valid.
5. **Privacy:** Raw PII MUST NOT appear on chain (`loc_type = 0x00` default). Issuers deduplicating humans MUST NOT hash raw biometrics directly. Per-claim selective disclosure uses `claim_commitments` with an independent 32-byte CSPRNG salt per entry (`SL-WIRE-014`).

### 4.2 Deterministic Credential Verification Order (`SL-CONT-010`, `decided`)

1. Wire pipeline (`SPEC-01 §7`) -> `WIRE_*`
2. Supported `credential_kind` -> `WIRE_TYPE`; claim schema compliance -> `WIRE_MEMBER`
3. Chain/genesis match -> `CHAIN_MISMATCH`; subject `name_pin` owner match -> `NAME_OWNER_MISMATCH`
4. Earliest confirmed signed-form `0x09` anchor present -> `CRED_ANCHOR_MISSING`; confirmation depth `>= required_depth` -> `CHAIN_DEPTH_INSUFFICIENT`
5. Issuer `link.cred` history walk available -> `NAME_HISTORY_UNAVAILABLE`; `owner_policy` & `role_policy` match -> `NAME_OWNER_MISMATCH`; `0x0b` compromise check (`h_anchor < h_c`) -> `CRED_ISSUER_CLOSED`
6. Height / calendar window check -> `CRED_WINDOW_CLOSED`
7. Revocable seal state (`0x0a` cause -> `CRED_REVOKED_FOR_CAUSE`; plain spend -> `SEAL_SPENT`; unavailable -> `SEAL_UNAVAILABLE`)

---

## 5. General Notary Acts (`seallink-notary/1`)

A notary is an independent off-authority-path actor (human, organization, or agent; refusing by actor class is invalid unless required by explicit policy) acting under its `link.notary` role policy (`SL-CONT-011`, `decided`):

1. **Four act kinds (each with a closed `details` schema in `schemas/credential.schema.json`):**
   - `contract-notarization`: certifies that named parties executed `contract_id` (plus optional `notary_clause_sha256`).
   - `certified-copy`: certifies correspondence of `original_sha256` and `media_type` to an inspected original.
   - `fact-attestation`: certifies a witnessed `fact_sha256` under `fact_schema` at `(tip_height, tip_hash)`.
   - `child-within-parent`: optional re-delegation attestation naming `(parent_grant_id, child_grant_id, ordinal)` when parent policy demands prose/policy review alongside mechanical narrowing.
2. **Lifecycles & Anchoring (`0x04`):** Anchored via `OP_RETURN` action `0x04` committing `content_addr(seallink-notary/1)`. Supports BOTH **`eternal`** (no `notary_seal`, verified against `link.notary` at `h_anchor`, bounded by `0x0b` `h_c`) and **`revocable`** (`notary_seal` required; plain spend withdraws allowing recertification; spend with `0x05` records `CRED_REVOKED_FOR_CAUSE` and bars recertification without a new ruling).
3. **Notary identity pin:** Every reference to a notary pins `(name, registration, owner_policy)` with mandatory writer verification (`SL-LDGR-007`) so transferring a notary's name never transfers notarizing authority.

---

## 6. Security Considerations

- **Choosing `h_c`:** Setting `h_c` too late preserves earlier attacker forgeries; setting `h_c` too early invalidates legitimate historical documents.
- **Selective clause context:** Disclosing a single contract clause without qualifying clauses can mislead; `machine_clause_indices` ensures executors always see every machine-enforced clause, while arbiters MAY demand additional prose clauses before ruling.
- **Notary truth limit:** A notary act cryptographically binds the notary's accountability to a claim; it never proves physical truth mathematically.

---

## 7. References

- **Normative:** [RFC8785], [BIP-340], [BIP-141], [JSON-SCHEMA-2020-12].
- **Informative:** [RFC8448].
