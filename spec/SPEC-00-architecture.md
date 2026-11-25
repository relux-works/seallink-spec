# SPEC-00: SealLink Architecture, Ontology, and Governance

- **Version:** `1.0.0-draft.10`
- **Status:** `draft` (normative rules tagged `decided` or `open`; open items tracked in `OPEN-QUESTIONS.md`)
- **Evidence / Maturity:** `prose`
- **Authors:** Ivan Oparin, Alexey Grigorev
- **Normative Language:** RFC 2119 and RFC 8174 (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHOULD`, `MAY`)
- **Conformance:** `CONFORMANCE.md`

---

## 1. Abstract and Positioning

SealLink is a protocol that enables intelligent actors — **people, organizations, and autonomous software agents** — to register sovereign identities, relationships, contracts, obligations, verifiable credentials, and revocable powers of attorney (grants) so that any verifier can validate them independently on its own ledger node without trusting the issuer's server, a central registry, or the message transport.

A name on a public UTXO-and-name ledger binds an actor to its cryptographic role keys and policies. A canonically encoded, cryptographically signed document expresses a relationship or capability. Every revocable relationship is bound to an unspent transaction output (a **seal**); spending that seal terminates the relationship across all observing verifiers without contacting the issuer's infrastructure.

### 1.1 Non-Goals and Institutional Boundaries

SealLink defines exact boundaries for what cryptography can and cannot establish:

- **Does not replace legal institutions.** A civil registry, licensed notary, court, or corporate registrar is represented as an actor with a name and keys. Whether to trust a given notary or registry is strictly a local verifier policy choice.
- **Does not prove ground truth or legal validity.** SealLink proves who signed what, under which authority chain, and when it was anchored or revoked. Real-world birth, consent free of coercion, and judicial fairness remain outside the protocol.
- **Does not mandate key storage, message transport, or agent OS isolation.** Hardware enclaves, personal key services, Nostr/Matrix/XMPP transports, and agent isolation runtimes (such as Swarma Runtime) are external specifications consuming SealLink (`guides/GUIDE-01-custody-and-signers.md`).
- **Does not hard-code one blockchain.** Core semantics depend on an abstract ledger interface (`ChainView`, `SPEC-02`); Namecoin is Binding Profile v1.
- **One-way legal capacity model.** In v1.0, legal capacity transitions at most once (`ward` -> `autonomous`). Adult conservatorship or reversible capacity states are outside v1.0 scope.

---

## 2. The Eight Core Principles

Every conforming SealLink implementation and extension profile **MUST** uphold these eight invariants:

| Rule ID | State | Principle |
| --- | --- | --- |
| `SL-ARCH-001` | `decided` | **Independent Verification.** The party executing an effect or relying on a claim MUST verify every identity, chain history, anchor, and seal on its own ledger view. Pins MUST come from local verifier configuration, never from presenter-supplied input. |
| `SL-ARCH-002` | `decided` | **Three-Valued Verdict Semantics.** Every verification terminates in exactly one of three outcomes: **Admit**, **Refuse** (non-closing; transient or invalid presentation), or **Close** (permanent, durably journaled termination). Unknown, unavailable, or unsupported evidence MUST NEVER degrade to Admit. |
| `SL-ARCH-003` | `decided` | **Fast to Halt, Slow to Add or Transfer.** Revocation via seal spend acts upon first validated observation (including local mempool as a fail-closed local accelerator) with durable local closure; confirmed chain state establishes the deterministic consensus fact shared across independent observers. Adding devices, appointing successor guardians, changing guardian rosters, transferring names, and recovering identities require confirmed chain state and mandatory delay where governed. |
| `SL-ARCH-004` | `decided` | **Prose Directs Work; Typed Fields and Scripts Authorize Effects.** Mechanical effect executors MUST decide solely from typed machine fields and on-chain scripts and MUST refuse grants carrying operative free-text terms (`GRANT_TEXT_FORBIDDEN`). Contract termination rules derive exclusively from the contract seal script, never from prose. |
| `SL-ARCH-005` | `decided` | **Monotonic Attenuation.** Delegated authority MUST ONLY narrow relative to its parent across capabilities, constraints, additive quotas, whole-parent pool sums, and validity windows. Every verifier checks narrowing mechanically. |
| `SL-ARCH-006` | `decided` | **Strict Key-Role Separation.** Every key role has a closed set of permitted signing domains (`registry/key-roles.json`, coherent with `registry/object-types.json`). Messaging keys NEVER grant authority; authentication keys NEVER authorize effects or contract assents; owner-control device keys NEVER authenticate to foreign verifiers. |
| `SL-ARCH-007` | `decided` | **Availability-Only Storage and Transport.** Off-chain stores, mirrors, and transports (inline, Blossom, HTTPS `.well-known`, Nostr, Matrix) are trusted for availability only. Content-addressed SHA-256 pins and cryptographic signatures establish authenticity regardless of delivery channel. |
| `SL-ARCH-008` | `decided` | **Actor-Agnostic Core with Origin-Certified Class.** Core mechanics treat all actors identically; refusing an actor solely for being human, corporate, or an agent is invalid unless required by explicit policy. Certified subject class (`person`, `agent`, `organization`) is established solely by a trusted `seallink-origin/1` certificate, never by self-declaration. |

---

## 3. Actor Ontology and Role Glossary

### 3.1 Two Orthogonal Axes

Every SealLink actor sits along two independent axes (`SL-ARCH-009`, `decided`):

1. **Certified Class** (fixed at origin; immutable):
   - `person` — human individual certified by a birth origin certificate (`origin_class = "person"`).
   - `agent` — materialized software agent certified by a materialization origin certificate (`origin_class = "agent"`).
   - `organization` — legal entity, collective, or institution certified by an incorporation origin certificate (`origin_class = "organization"`).
   - `unverified` — any ledger name (or ephemeral key-only actor) without a verified origin certificate. Fully usable for permissionless and pseudonymous interaction.
2. **Legal Capacity / Autonomy** (transitions at most once, one-way: `ward` -> `autonomous`):
   - `ward` — non-fully-autonomous actor (minor human child, or software agent prior to recognized legal capacity). Its name UTXO is controlled by a guardian/custodian `ScriptPolicy`; autonomous commitments signed solely by the ward are rejected at the protocol layer (`SPEC-04`).
   - `autonomous` — actor controlling its own name `ScriptPolicy` and executing grants and contracts in its own right (adult person, organization, unverified actor, or emancipated agent).

### 3.2 Canonical Role Glossary

| Normative Term (EN) | Companion Projection Term (RU) | Definition |
| --- | --- | --- |
| **Actor** | Актор | Any participant (person, organization, agent, or unverified key/name). |
| **Issuer** | Доверитель / Издатель | Actor issuing a grant, credential, origin certificate, or notary act. |
| **Recipient** | Поверенный / Получатель | Actor (single key, name, or `m-of-n` group) authorized to invoke a grant. |
| **Executor** | Исполнитель | Concrete service or host verifying a grant and executing the authorized action. |
| **Guardian** | Опекун | Autonomous actor holding an active guardianship slot responsible for a ward. |
| **Ward** | Подопечный | Actor in `ward` capacity represented by one or more guardians. |
| **Notary** | Нотариус | Independent third party certifying documents, facts, contracts, or optional delegations. |
| **Arbiter** | Арбитр | Independent party named in a contract seal or origin recovery/succession rule (e.g., court or arbitration key). |
| **Seal** | Печать | Dedicated ledger UTXO whose validated spend terminates or consumes a specific right or transition. |
| **Provider** | Провайдер | Service actor bound by `NamePin` in a holder's `seallink-manifest/1` for a labeled `service_type`. |

---

## 4. Protocol Layer Architecture

The SealLink v1.0 specification is organized as eight orthogonal normative documents plus pluggable domain profiles, machine-readable registries, JSON Schemas, and executable conformance vectors:

| Spec | Layer | Owns |
| --- | --- | --- |
| **`SPEC-00`** | Foundation | Principles, actor ontology, role glossary, threat model, governance. |
| **`SPEC-01`** | Wire & Crypto | Restricted RFC 8785 JCS, dual integers, BIP-340 tagged hashes, 3 hashes, `SignatureSet` & `guardian_approvals`, universal policy binding, salted selective disclosure, 7-predicate Constraint Algebra, wire pipeline. |
| **`SPEC-02`** | Ledger Binding | Abstract `ChainView`, Namecoin Binding v1 (`NAME_NEW` / `NAME_FIRSTUPDATE` / `NAME_UPDATE` grammars, CSV/SegWit), `ScriptPolicy`, `SIGHASH_ALL` writer check, multi-node freshness, Witness construction, `SLNK` `OP_RETURN`, Merkle batch `0x02`, UTXO seals & TRUC/P2A CPFP. |
| **`SPEC-03`** | Identity & Custody | 520-byte name value (multi-role keys / on-chain role-policy pins + uniform `origin` pin + `m` head), key taxonomy & cold emergency reserve, `manifest/1` (sets, self-service, pinned labeled `providers[]`, `auth`), `card/1`, 4-channel cascade, provisional onboarding & name auth, owner control plane (`devices`, L0–L2). |
| **`SPEC-04`** | Origin & Guardianship | Eternal `origin/1` (salted privacy commitments, `status_seal`, `roster_seal`, explicit `disposer_pk`/`arbiter_pk`/`challenger_pk`), single-use `name-binding/1`, `N` equal guardian slots & 4-class verifier-derived quorums, ward non-autonomy, initial (`0x12`) & two-stage (`0x0d`/`0x0e`) activation, roster transitions (`0x0f`), consistency invariants, emancipation (`capacity/1`), `end/1`, dual-mode `name_recovery` (`0x10` cancel) & seal continuation tables. |
| **`SPEC-05`** | Contracts & Credentials | N-party salted contracts (`ward_origin_id` for ward parties, `machine_clause_indices`), framework nesting, confirmed contract seal termination, symmetric `assent/1` (`guardian_approvals[]` for wards), on-chain assent, agreed config hash, verifiable credentials (`eternal`/`revocable`, `h_c`), general notary acts, violation verdicts & salted request attribution. |
| **`SPEC-06`** | Grants & Delegation | Universal `grant/1` (unilateral base + optional contract + ward `guardian_approvals[]`), concrete `executor` vs stateless `executor_ref`, UTXO seal vs root-only `window_only`, acyclic single-use attribution (`0x11`), `invocation/1` & `receipt/1`, depth-2 re-delegation (R8.5 aggregate budget + R8.6 disjoint coin ranges), early-auth admission pipeline, crash-in-effect-window `uncertain` recovery, bearer sessions, anti-rollback fenced journals. |
| **`SPEC-07`** | Services & Portability | Grant-gated executor contract, provider authority & pinned transport mutual auth, replaceable service cut-over (`migration/1`), federated screening & progressive PII disclosure (Contour A), extension/SLIP checklists. |

---

## 5. Specification Governance, Authority, and Maturity

### 5.1 Single Source of Truth (`SL-ARCH-010`, `decided`)

1. **Prose defines normative behavior; `registry/*.json`, `schemas/*.schema.json`, and `vectors/*.json` define exact identifiers, grammars, and required outcomes.** If prose, schemas, and test vectors disagree, the specification release is defective. An implementation is NEVER the normative oracle.
2. **Human books and whitepapers are downstream projections** of this specification. Where any guide or projection disagrees with `spec/`, `profiles/`, `registry/`, or `schemas/`, the normative specification prevails.
3. **Rule States:** Every normative rule carries one of two states: `decided` (normative requirement) or `open` (explicitly unresolved and tracked in `OPEN-QUESTIONS.md`; readers MUST fail closed on any unprofiled open construct).
4. **Evidence / Maturity Levels:** Each specification document independently tracks its empirical maturity:
   - `prose` — normative text and schemas authored and lint-checked;
   - `vectors` — deterministic positive/negative and end-to-end RFC 8448-style byte traces published and verified against schemas and reference cryptography;
   - `dual-impl` — verified byte-for-byte identical across at least two independent implementations with disjoint crypto stacks (target: Rust + Go);
   - `chain-tested` — end-to-end verified on Namecoin regtest and/or mainnet.
5. **Post-Freeze Evolution:** Once v1.0 freezes, protocol additions, new standard `service_type` entries, and new canonical object types are proposed via numbered SealLink Improvement Proposals (`SLIP-TEMPLATE.md`).

---

## 6. Global Threat Model and Privacy Default

### 6.1 Honest Security Guarantees (`SL-ARCH-011`, `decided`)

- **Issuer-independent, observer-local mempool-speed revocation vs. confirmed-chain determinism:** SealLink separates two distinct tiers of ledger observation: (1) **confirmed-chain facts** (block anchors, confirmed seals, name histories, confirmed spends) which are deterministic across all independent verifiers observing the same active chain tip; and (2) **local mempool observations**, which act strictly as **fail-closed local accelerators** for revocation (seals) and in-flight name-update visibility. SealLink does not promise zero-latency global simultaneous revocation across the Internet; it guarantees that any observing verifier reading its own healthy node permanently closes an authority upon first validated observation of a seal spend (in its mempool or in a block), without depending on the issuer's server.
- **Compromised executor limit:** Cryptography bounds whom an honest executor admits and creates auditable receipts and dispute bundles; it cannot prevent a compromised executor from misusing credentials it legitimately holds or copying already-disclosed plaintext.
- **Privacy by default (`SL-ARCH-012`, `decided`):** The public ledger MUST carry only cryptographic commitments (hashes and UTXO seals) — never personal names, birth dates, family graphs, private ward lists, or plaintext contract terms. Sensitive fields inside `seallink-origin/1` (initial guardians and majority timestamps) use salted selective-disclosure commitments (`SPEC-01 §5`, `SPEC-04 §2`). Off-chain signed documents default to private delivery (`loc_type = 0x00`, inline or E2EE transport); public publication via `seallink-card/1` or public mirrors is strictly opt-in. Note that public ledger graphs (UTXO spend timing and name-update frequency) remain observable to chain analysts.

---

## 7. References

### 7.1 Normative References
- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- **[RFC8259]** Bray, T., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017.
- **[RFC8785]** Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.
- **[RFC8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- **[BIP-340]** Wuille, P., Nick, J., and T. Ruffing, "Schnorr Signatures for secp256k1", BIP-340.
- **[BIP-141]** Lombrozo, E., Lau, J., and P. Wuille, "Segregated Witness (Consensus layer)", BIP-141.
- **[BIP-143]** Lau, J. and P. Wuille, "Transaction Signature Verification for Version 0 Witness Program", BIP-143.
- **[BIP-112]** BtcDrak, Friedenbach, M., and E. Lombrozo, "CHECKSEQUENCEVERIFY", BIP-112.
- **[BIP-174]** Chow, A., "Partially Signed Bitcoin Transaction Format", BIP-174.
- **[SEC1]** Certicom Research, "SEC 1: Elliptic Curve Cryptography", Version 2.0, May 2009.
- **[JSON-SCHEMA-2020-12]** Wright, A., Andrews, H., Hutton, B., and G. Dennis, "JSON Schema: A Media Type for Describing JSON Documents", Draft 2020-12.

### 7.2 Informative References
- **[RFC8448]** Thomson, M., "Example Handshake Traces for TLS 1.3", RFC 8448, January 2019.
- **[BIP-431]** Sanders, G., "Topology Restrictions for Pinning (TRUC)", v3 transactions in Bitcoin Core v28 / Namecoin Core `nc28.0`.
- **[BIP-433]** Sanders, G., "Pay to Anchor (P2A)", witness v1 anchor output `51024e73` in Bitcoin Core v28 / Namecoin Core `nc28.0`.
- **[NC28]** Namecoin Core `nc28.0`, `src/script/names.cpp`, `src/script/solver.cpp`, `src/policy/policy.cpp`.
