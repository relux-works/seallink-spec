# SPEC-05: Contracts, Symmetric Assent, Verifiable Credentials, and General Notary Acts

- **Version:** `1.0.0-draft.10`
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

1. **Header fields & party binding:** `type`, `network`, `genesis`, `profile`, `contract_salt` (32 CSPRNG bytes, preventing offline guessing of short contracts), `parties[2..32]` — where each entry carries a mandatory unique-within-contract **`party_id`** (`^[a-z0-9][a-z0-9._-]{0,63}$`, allowing multiple parties to share a legal `role` such as co-tenants `"tenant"` with `"tenant-1"` and `"tenant-2"`; duplicate `party_id` refuses `WIRE_MEMBER`) and is either an **autonomous party** `{party_id, role, name_pin?, signing_policy: ThresholdPolicy}` or a **ward party** `{party_id, role, ward_origin_id, name_pin}` (omitting static `signing_policy` so guardian succession never invalidates a live contract) — `window` (`not_before_height`, optional `not_after_height`, optional calendar `not_after_unix`), optional `machine_clause_indices`, optional `framework_id`, optional/required `seal`, optional `assent_output`, optional `config_sha256`, and optional `moderation`.
   - **Autonomous `name_pin` & ward detection:** Whenever an autonomous party declares `name_pin`, the verifier MUST verify `(name, registration, owner_policy)` on the active chain, verify `party.signing_policy` matches that name's `link.grant` policy at the contract anchor height (or current tip pre-anchor), AND perform history-based origin detection (`SL-ORIG-003`): if that registration belongs to a non-emancipated ward, refusing `WARD_AUTONOMOUS_FORBIDDEN` prevents a ward from bypassing guardianship by listing itself as an autonomous party.
   - **Distinct party identities:** All entries in `contract.parties[]` MUST represent pairwise-distinct party identities (comparing `(name, registration, canonical owner_policy)` when `name_pin` is present, or `ward_origin_id`, or canonical `signing_policy` for key-only parties; duplicate party identities refuse `CONTRACT_TERMS_MISMATCH`).
   - **Grant participant binding:** For any grant bound to `contract_id`, BOTH the grant's `issuer` and its `recipient` MUST correspond to distinct parties listed in `contract.parties[]` (by `(name, registration, owner_policy)` for named actors, or exact `signing_policy` match for key/group recipients; `CONTRACT_TERMS_MISMATCH` otherwise).
2. **Clauses, Closed `ClauseObject` / `MachineClauseTerms`, & Selective Disclosure:** Each disclosed clause `i` conforms to the closed `ClauseObject` schema (`schemas/contract.schema.json`, `minProperties: 1`, `additionalProperties: false`): optional `title` (single-line string `1..256`), optional `text` (`1..16384`, where `\n` is allowed per `SL-WIRE-005`), and optional `machine_terms` (`MachineClauseTerms`, closed: required `capabilities[1..64]`, optional `config_sha256`, optional `not_before_height`, optional `not_after_height`). The contract stores ONLY the ordered array `clause_commitments[]` where:
   ```text
   clause_commitments[i] = H_tag("seallink-clause/1", salt_i || canonical_JCS(clause_i))
   contract_id           = SHA256(canonical_JCS(seallink-contract/1))
   ```
   When a grant binds `contract_id` (and optionally `framework_id`), both complete contract documents MUST be presented (`CONTRACT_NOT_PRESENTED`), MUST recompute to their bound identifiers (`CONTRACT_ID_MISMATCH`), and MUST NOT have persisted `contract` or `framework` closures in the local journal (`SEAL_SPENT`).
3. **Deterministic machine-clause completeness & narrowing:** Every clause index carrying machine-enforced terms MUST be listed in strictly ascending order in `machine_clause_indices[]` (with every index `< len(clause_commitments)`). An executor MUST require disclosure of `(salt_i, clause_i)` for EVERY index `i` in `machine_clause_indices[]`, verify `commit(salt_i, clause_i) == clause_commitments[i]`, validate `clause_i` against `ClauseObject` requiring `clause_i.machine_terms` to be present and valid under `MachineClauseTerms`, and mechanically verify that: (a) every capability in `grant.capabilities[]` narrows (`SL-WIRE-017`) at least one capability declared across the disclosed `machine_terms.capabilities[]`, (b) any declared `machine_terms.config_sha256` equals `contract.config_sha256`, and (c) the grant's block window nests inside any declared `machine_terms.not_before_height` / `machine_terms.not_after_height` (`CONTRACT_TERMS_MISMATCH` on missing disclosure or mismatch). Prose-only clauses outside `machine_clause_indices[]` MAY remain undisclosed to the executor.
4. **Framework Nesting & Window Enforcement (`SL-CONT-003`, `decided`):** A contract MAY name at most one `framework_id`, and a framework contract MUST NOT name another framework contract (maximum nesting depth = 1). Every grant's block window MUST nest inside its bound contract's window (`not_before_height` and optional `not_after_height`), which MUST nest inside its framework contract's window (`CONTRACT_TERMS_MISMATCH` on violation). Whenever `contract.window.not_after_unix` or `framework.window.not_after_unix` is present, verifiers MUST refuse `GRANT_WINDOW_CLOSED` once decision time `now >= not_after_unix`.

### 2.2 Symmetric Native Assent (`seallink-assent/1`) and Anchoring (`SL-CONT-004`, `decided`)

1. **Symmetric off-chain assent (`AssentPayload`):** Every `seallink-assent/1` (`<= 32768` bytes, accommodating multi-guardian `guardian_approvals[]` and up to 32-of-32 `SignatureSet`) carries closed members `(type, network, genesis, target_type, target_id, party_id, party_role, issued_at, expires_at, nonce)` plus optional `party_name` (REQUIRED when `target_type ∈ {"seallink-guardian/1", "seallink-migration/1"}`, and verified against `party.name_pin.name` when present on contracts) and optional `guardian_context` (REQUIRED for ward parties; paired strictly with `guardian_approvals[]`). A contract is concluded when EVERY distinct `party_id` in `parties[]` is covered 1-to-1 by a valid `seallink-assent/1` (`target_type = "seallink-contract/1"`, `target_id = contract_id`, matching `party_id` and `party_role == party.role`; duplicate or missing `party_id` assents refuse `CONTRACT_ASSENT_INVALID`):
   - Permitted signer roles for `seallink-assent/1` are strictly `grant` and `guardian_quorum` (`registry/object-types.json`, coherent with `registry/key-roles.json`); `auth` and `device` keys MUST NEVER sign `seallink-assent/1` (`WIRE_SIGNATURE`).
   - For an **autonomous party** (`signing_policy` present), `seallink-assent/1` uses the ordinary `{"payload","signatures"}` envelope whose `signatures.policy` MUST strictly equal `party.signing_policy` (`SL-WIRE-013`).
   - For a **ward party** (`ward_origin_id` present, `SPEC-04`), `seallink-assent/1` MUST carry `payload.guardian_context` (`origin_id == party.ward_origin_id`, `ward_name == party.name_pin.name`, `event_class = "contract_assent"`, `revision` matching that ward's active roster revision) and top-level `guardian_approvals[]` satisfying `required("contract_assent")` across distinct active guardian slots (`SL-ORIG-006` refusal precedence: `WARD_AUTONOMOUS_FORBIDDEN`, then `ORIGIN_UNVERIFIED`, then `GUARDIAN_INACTIVE`, then `WIRE_SIGNATURE`, then `GUARDIAN_QUORUM_UNMET`). Contracts MAY include **multiple distinct ward parties**; verifiers MUST resolve each ward party against its own origin bundle keyed by `party.ward_origin_id` (`ORIGIN_UNVERIFIED` if any ward party lacks a verified matching origin bundle).
   - **Historical ward representation at confirmed anchor height `h_anchor`:** Once a contract is anchored on chain at confirmed height `h_anchor` (via `0x07` or `0x01`), each ward party's `seallink-assent/1` — specifically its ward name resolution (`party_name` vs active binding at `h_anchor`), active guardian roster revision, active slot states, and each approving guardian's `link.grant` signing policy — MUST be verified **at `h_anchor`** (and checked against any retroactive `0x0b` `CredentialBreak` for `role = "grant"`: `h_anchor < h_c` survives, while `h_anchor >= h_c` refuses **`CRED_ISSUER_CLOSED`**), rather than against tip. Consequently, subsequent `0x0f` roster revisions or guardian key rotations NEVER break already-concluded contracts, while contract window, unspent contract seal, and any *new* ward grants/invocations continue to be evaluated at tip.
   - **Assent freshness anchored at conclusion/issuance:** Assent freshness is evaluated strictly against the confirmed **`block_time`** of the `0x07` contract anchor (or confirmed `0x01` grant anchor for unanchored contract grants; missing anchor `block_time` MUST fail closed with `CHAIN_FRAME_INVALID` — NEVER silently falling back to local wall-clock `now`) using exact bounds:
     ```text
     issued_at <= anchor_time < expires_at   AND   expires_at - issued_at <= 259200   AND   anchor_time - issued_at <= 259200
     ```
     (`<= 72` hours; `CONTRACT_ASSENT_INVALID` on stale, expired, overlong, or post-dated assent at anchor time). Concluded contracts therefore remain valid throughout their declared `window` without re-testing assent freshness against later invocation wall-clock time.
2. **Contract anchor (`0x07`):** A contract is anchored via `OP_RETURN` action `0x07` committing `contract_id` (`loc_type = 0x00` default for private contracts).
3. **Optional on-chain assent:** Parties MAY additionally name a confirmed `N-of-N` `P2WSH` `assent_output` in `seallink-contract/1` and have the `0x07` anchor transaction spend it (`SIGHASH_ALL` on all signatures), proving mutual assent on chain even to observers who never see contract plaintext.

### 2.3 The Contract Seal Decides Termination (`SL-CONT-005`, `decided`)

1. **Mandatory seal before signing:** Every framework contract and every contract under which any grant is issued MUST name a confirmed `seal` whose `script_policy` conforms to `ContractSealScriptPolicy` (`key`, `multisig`, `either_of_2`, `both_of_2`, or `arbiter_or_both`) created **before** parties sign `seallink-assent/1`. Signing services and verifiers MUST check confirmation and exact compiled `ScriptPolicy` match of both the bound contract's seal and any named framework contract's seal on their own node (`CONTRACT_SEAL_MISSING` on conclusive absence/mismatch; `SEAL_UNAVAILABLE` on inconclusive read).
2. **Script derives termination type — never prose:** Every reader, renderer, and UI MUST derive the contract's termination type strictly from `seal.script_policy` (`SL-LDGR-004`):
   - `{"kind":"key"}` or `{"kind":"multisig"}` -> **`issuer_only`**
   - `{"kind":"branch","template":"either_of_2"}` -> **`either_party`**
   - `{"kind":"branch","template":"both_of_2"}` -> **`both_together`**
   - `{"kind":"branch","template":"arbiter_or_both"}` -> **`arbiter`**
   A prose clause describing termination binds parties as text only and NEVER ends a contract or overrides the script-derived type.
3. **One spend ends all grants:** Spending a contract or framework seal (`SEAL_SPENT`) durably terminates every grant bound to that contract (or framework) upon first observation and records a durable `contract` / `framework` closure. The spending transaction SHOULD carry `OP_RETURN` action `0x08` committing `typed_digest(seallink-termination/1)` (`SIGHASH_ALL`), where `seallink-termination/1` is signed under the terminating party's or arbiter's `grant` / contract signing policy; however, the spend alone terminates the contract regardless of whether `0x08` is valid or present.

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
2. **Signed-form anchoring (`0x09`):** Every credential MUST be anchored via a presenter-supplied confirmed `OP_RETURN` action `0x09` transaction (`anchor_txid`) on the active chain committing **`content_addr = SHA256(signed_bytes)`**, proving the signature existed at or before confirmed block `h_anchor` (`CRED_ANCHOR_MISSING`). Presenters SHOULD supply the earliest confirmed `0x09` anchor transaction (because an earlier `h_anchor < h_c` strictly dominates a later anchor; Tier 1 Namecoin nodes do not maintain a global `OP_RETURN`-content index).
3. **Two lifecycles and subject binding modes (`key`, `name`, `origin`):**
   - **`eternal`:** MUST NOT carry `revocation_seal`; `not_after_height` / `not_after_unix` optional. Verified against the historical registration lineage matching `issuer.registration` at `h_anchor` (`link.cred` role policy active at `h_anchor`). Similarly, if `subject.mode = "name"`, `subject.name_pin` `(name, registration, owner_policy)` is verified at **`h_anchor`** (so an eternal diploma survives both issuer and subject name expiry/transfer). If `subject.mode = "origin"`, the presenter MUST supply a verified `origin_bundle` matching `subject.origin_id` (`ORIGIN_UNVERIFIED` if omitted or invalid), and the verifier verifies **historical origin existence and trusted issuance** (`h_origin <= h_anchor`, confirmed `binding_seal` and `status_seal` UTXOs at `<= h_anchor` [failing closed `ORIGIN_STATUS_INCOMPLETE` if missing/unconfirmed], valid `name_binding` if supplied, and `h_origin < h_c` under any origin-issuer `0x0b` break) — independent of whether an initial `0x0c` name binding had already confirmed at `h_anchor`, and independent of subsequent emancipation, status change, `seallink-end/1`, or name transfer.
   - **`revocable`:** MUST carry a confirmed `revocation_seal`; `not_after_height` / `not_after_unix` optional. By default verifies the issuer's `link.cred` role policy, `subject.name_pin` (when `subject.mode = "name"`), and active `origin_bundle` status (when `subject.mode = "origin"`, `ORIGIN_UNVERIFIED` if missing/invalid) current at tip (exceptions such as `seallink-guardian/1` verify issuer at `h_anchor`, `SL-ORIG-008`). Spending the seal closes the credential (`SEAL_SPENT`); spending with `OP_RETURN 0x0a` (`typed_digest(seallink-credential-withdrawal/1)`) records `CRED_REVOKED_FOR_CAUSE` (`seallink-credential-withdrawal/1` is an unsigned cause record authenticated by the on-chain spend of `revocation_seal`; when presented alongside `0x0a`, verifiers validate its closed schema and exact `credential_id` / `typed_digest` match against the `0x0a` frame; a `0x0a` spend without an off-chain document still revokes permanently and NEVER admits).
4. **Owner-authenticated compromise break `h_c` (`0x0b`, `SL-CONT-009`, `decided`):**
   - If an issuer's or guardian's `cred`, `notary`, or `grant` role policy (current or retired) is compromised, the actor's cold `name_owner` `ScriptPolicy` broadcasts an `OP_NAME_UPDATE` (removing/replacing the role if current, signed `SIGHASH_ALL`) containing the 50-byte `0x0b` frame embedding `h_c_le64` (`<= inclusion_height`) and `typed_digest(seallink-credential-break/1)`.
   - Because verifiers reconstruct `seallink-credential-break/1` (`schemas/credential.schema.json#/$defs/CredentialBreak`, with `role ∈ {"cred", "notary", "grant"}`) directly from the name history — using the confirmed spent previous name output `name_input` (whose trailing script MUST equal `compile(issuer.owner_policy)` and whose spend MUST pass `SL-LDGR-007`), `issuer` `NamePin`, `role`, candidate historical canonical `compromised_policy` (`ThresholdPolicy` without `"alg"`), and on-chain `h_c` — withholding off-chain break documents cannot hide a compromise.
   - For the exact affected `(issuer, registration, owner_policy, role, compromised_policy)` whose reconstructed `typed_digest(seallink-credential-break/1)` matches the `0x0b` frame commitment: anchors at `h_anchor < h_c` (e.g., `h_anchor = h_c - 1`) **survive**, while anchors at `h_anchor >= h_c` (`h_anchor = h_c` or `h_anchor = h_c + 1`) durably refuse **`CRED_ISSUER_CLOSED`** (for eternal and revocable credentials, notary acts, AND both historical and live-tip ward `grant` approvals). Multiple breaks matching the same policy narrow by `min(h_c)`. Durable `role` closures in `FencedJournal` MUST be scoped by mandatory **`policy_sha256`** and optional **`cutoff_height = h_c`** (`schemas/invocation.schema.json#/$defs/ClosureSubject`) and written idempotently (zero duplicate writes on repeated observation), so observing a late anchor `h_late >= h_c` NEVER blocks an earlier anchor `h_early < h_c` of the same document or a distinct successor policy `B` installed via valid `OP_NAME_UPDATE` in the same journal.
5. **Privacy:** Raw PII MUST NOT appear on chain (`loc_type = 0x00` default). Issuers deduplicating humans MUST NOT hash raw biometrics directly. Per-claim selective disclosure uses `claim_commitments` with an independent 32-byte CSPRNG salt per entry (`SL-WIRE-014`).

### 4.2 Deterministic Credential Verification Order (`SL-CONT-010`, `decided`)

1. Wire pipeline (`SPEC-01 §7`) -> `WIRE_*`
2. Supported `credential_kind` -> `WIRE_TYPE`; claim schema compliance -> `WIRE_MEMBER`
3. Chain/genesis match -> `CHAIN_MISMATCH`
4. Presenter-supplied confirmed signed-form `0x09` anchor present on active chain -> `CRED_ANCHOR_MISSING`; confirmation depth `>= required_depth` -> `CHAIN_DEPTH_INSUFFICIENT`
5. Subject verification: if `subject.mode = "name"`, verify `subject.name_pin` at `h_anchor` (`eternal`) or tip (`revocable`) -> `NAME_OWNER_MISMATCH` / `NAME_NOT_FOUND`; if `subject.mode = "origin"`, require a verified `origin_bundle` matching `subject.origin_id` (`historical_existence_only` with `h_origin <= h_anchor` for `eternal`, without requiring initial `0x0c` binding to exist at `h_anchor`; live origin status for `revocable`) -> `ORIGIN_UNVERIFIED`
6. Issuer `link.cred` history walk available -> `NAME_HISTORY_UNAVAILABLE`; `owner_policy` & `role_policy` match (at `h_anchor` for `eternal` or tip for `revocable`) -> `NAME_OWNER_MISMATCH` / `WIRE_SIGNATURE`; `0x0b` compromise check (`h_anchor >= h_c` refuses; `h_anchor < h_c` survives) -> `CRED_ISSUER_CLOSED`
7. Height window (`not_before_height <= H < not_after_height`) AND calendar window (`now < not_after_unix` when present) -> `CRED_WINDOW_CLOSED`
8. Persisted journal `credential` closure check AND revocable seal state (`0x0a` cause -> `CRED_REVOKED_FOR_CAUSE`; plain spend -> `SEAL_SPENT`; unavailable -> `SEAL_UNAVAILABLE`)

---

## 5. General Notary Acts (`seallink-notary/1`)

A notary is an independent off-authority-path actor (human, organization, or agent; refusing by actor class is invalid unless required by explicit policy) acting under its `link.notary` role policy (`SL-CONT-011`, `decided`):

1. **Four act kinds (each with a closed `details` schema bound strictly to `act_kind == details.kind` in `schemas/credential.schema.json`):**
   - `contract-notarization`: certifies that named parties executed `contract_id` (plus optional `notary_clause_sha256`).
   - `certified-copy`: certifies correspondence of `original_sha256` and `media_type` to an inspected original.
   - `fact-attestation`: certifies a witnessed `fact_sha256` under `fact_schema` at `(tip_height, tip_hash)`.
   - `child-within-parent`: optional re-delegation attestation naming `(parent_grant_id, child_grant_id, ordinal)` when parent policy demands prose/policy review alongside mechanical narrowing.
2. **Lifecycles & Anchoring (`0x04`):** Anchored via a presenter-supplied confirmed `OP_RETURN` action `0x04` transaction committing `content_addr(seallink-notary/1)` (presenters SHOULD supply the earliest confirmed `0x04` anchor). Supports BOTH **`eternal`** (no `notary_seal`, verified against `link.notary` at `h_anchor`, bounded by `0x0b` `h_c`) and **`revocable`** (`notary_seal` required; plain spend withdraws allowing recertification; spend with `0x05` committing `typed_digest(seallink-credential-withdrawal/1)` — authenticated by the on-chain `notary_seal` spend — records `CRED_REVOKED_FOR_CAUSE` and bars recertification without a new ruling).
3. **Notary identity pin & deterministic verification order:** Every reference to a notary pins `(name, registration, owner_policy)` with mandatory writer verification (`SL-LDGR-007`) so transferring a notary's name never transfers notarizing authority. Verifying any `seallink-notary/1` MUST execute in order:
   1. Wire pipeline (`SPEC-01 §7`) & `network`/`genesis` match (`CHAIN_MISMATCH`);
   2. Presenter-supplied confirmed `0x04` anchor matching `content_addr(seallink-notary/1)` (`CRED_ANCHOR_MISSING`) at depth `>= required_depth` (`CHAIN_DEPTH_INSUFFICIENT`);
   3. Notary `link.notary` history walk & writer-verified `owner_policy` match at `h_anchor` (`eternal`) or tip (`revocable`) (`NAME_HISTORY_UNAVAILABLE` / `NAME_OWNER_MISMATCH` / `WIRE_SIGNATURE`) + `0x0b` compromise check (`h_anchor >= h_c` refuses `CRED_ISSUER_CLOSED`; `h_anchor < h_c` survives);
   4. Persisted journal `credential` closure check AND (for `revocable`) `notary_seal` state (`0x05` -> `CRED_REVOKED_FOR_CAUSE`; plain spend -> `SEAL_SPENT`; unavailable -> `SEAL_UNAVAILABLE`);
   5. When required by a parent grant (`notary_mode != "none"`): `act_kind == "child-within-parent"`, exact `(parent_grant_id, child_grant_id, ordinal)` equality, and exact notary `NamePin` membership in `parent.delegate.notaries[]` (plus `notary.name == parent.delegate.notary_name` when configured; `NOTARY_REQUIRED` otherwise).

---

## 6. Security Considerations

- **Choosing `h_c`:** Setting `h_c` too late preserves earlier attacker forgeries; setting `h_c` too early invalidates legitimate historical documents.
- **Selective clause context:** Disclosing a single contract clause without qualifying clauses can mislead; `machine_clause_indices` ensures executors always see every machine-enforced clause, while arbiters MAY demand additional prose clauses before ruling.
- **Notary truth limit:** A notary act cryptographically binds the notary's accountability to a claim; it never proves physical truth mathematically.

---

## 7. References

- **Normative:** [RFC8785], [BIP-340], [BIP-141], [JSON-SCHEMA-2020-12].
- **Informative:** [RFC8448].
