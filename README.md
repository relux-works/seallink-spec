# SealLink Protocol Specification

**Version:** `1.0.0-draft.1`  
**Status:** `draft` *(wire format not yet frozen; open items tracked in [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md))*  
**Evidence / Maturity:** `vectors` *(schemas, unit vectors, and 3 end-to-end RFC 8448-style byte traces verified in CI; `dual-impl` Rust + Go and live Namecoin regtest runs follow next)*  
**Authors:** Ivan Oparin, Alexey Grigorev  
**License:** Prose under CC BY 4.0; registries, schemas, vectors, and tooling under MIT ([LICENSE.md](LICENSE.md)).

> **Single-File Release Bundle:** Download the compiled self-contained Markdown specification and SHA-256 checksum from [GitHub Releases](https://github.com/relux-works/seallink-spec/releases).

---

## Overview

SealLink is an open protocol enabling **intelligent actors — people, organizations, and autonomous software agents** — to register sovereign identities, relationships, contracts, obligations, verifiable credentials, and revocable powers of attorney (grants) so that any verifier can check them independently on its own ledger node without trusting the issuer's server, a central registry, or the message transport.

- **Sovereign Identity:** A name on a public UTXO-and-name ledger (Namecoin Binding Profile v1) binds an actor to its role keys/on-chain role-policy pins, `ScriptPolicy` (`P2WPKH` or native `P2WSH` `m-of-n` multisig), uniform privacy-preserving `origin` commitment, and one `seallink-manifest/1` head with pinned `NamePin` providers.
- **Unified Authorization:** A unilateral, canonically encoded `seallink-grant/1` expresses fine-grained capabilities via a decidable 7-predicate Constraint Algebra (`eq`, `in`, `not_in`, `prefix`, `suffix`, `range`, `hash_eq`) and separate additive `quotas`, with optional bilateral contract binding (`seallink-contract/1`) and bounded depth-2 re-delegation (enforcing whole-parent budget sums and disjoint coin ranges).
- **Issuer-Independent Revocation:** Every revocable authority is tied to an unspent transaction output (a **seal**). Spending the seal closes the authority across observing verifiers at mempool speed with durable local closure — even when the issuer's infrastructure is offline.
- **Origin and Multi-Guardian Quorums:** Eternal `seallink-origin/1` certificates (`person`, `agent`, `organization`) with salted privacy commitments, authenticated `status_seal` / `roster_seal` UTXO spines, single-use name bindings, acyclic two-stage guardianship (`0x0d`/`0x0e`), roster transitions (`0x0f`), and verifier-derived closed `event_class` quorums enforce protocol-level non-autonomy for wards while supporting clean emancipation and dual-mode name recovery.

---

## Specification Suite

| Document | Scope | Status | Maturity |
| --- | --- | :-: | :-: |
| [SPEC-00-architecture.md](spec/SPEC-00-architecture.md) | Positioning, 8 Core Principles, Actor Ontology, Role Glossary, Governance, Threat Model, References | `draft` | `prose` |
| [SPEC-01-wire-and-crypto.md](spec/SPEC-01-wire-and-crypto.md) | Restricted RFC 8785 JCS, Dual Integers, BIP-340 Tagged Hashes, `SignatureSet` Policy Binding, Salted Disclosure, 7-Predicate Constraint Algebra, Wire Pipeline | `draft` | `vectors` |
| [SPEC-02-ledger-and-names.md](spec/SPEC-02-ledger-and-names.md) | Abstract `ChainView`, Namecoin Binding v1 (`NAME_NEW` / `NAME_FIRSTUPDATE` / `NAME_UPDATE`, CSV/SegWit), `ScriptPolicy`, `SIGHASH_ALL` Writer Check, Freshness, Witness `W`, `SLNK` `OP_RETURN`, Merkle Batch `0x02`, UTXO Seals & P2A CPFP | `draft` | `vectors` |
| [SPEC-03-identity-and-custody.md](spec/SPEC-03-identity-and-custody.md) | 520B Name Value (Multi-Role Keys & On-Chain Policy Pins, Uniform `origin` Pin), Key Taxonomy & Cold Reserve, `manifest/1` & Pinned `providers[]`, Entity Card, 4-Channel Cascade, Provisional Onboarding & Name Auth, Owner Control | `draft` | `vectors` |
| [SPEC-04-origin-and-guardianship.md](spec/SPEC-04-origin-and-guardianship.md) | Origin Certificates (Salted Commitments, `status_seal`, `roster_seal`), Single-Use Name Binding, $N$-Slot Guardianship & Verifier-Derived Quorums, Ward Non-Autonomy, Two-Stage Appointment (`0x0d`/`0x0e`), Roster Transitions (`0x0f`), Slot State Table, Emancipation, `end/1`, Dual-Mode `name_recovery` (`0x10`) | `draft` | `vectors` |
| [SPEC-05-contracts-and-credentials.md](spec/SPEC-05-contracts-and-credentials.md) | N-Party Salted Contracts (`machine_clause_indices`), Framework Nesting, Confirmed Seal Termination, Symmetric `assent/1` (with `guardian_context`), Config Hash, Verifiable Credentials (`eternal`/`revocable`, `h_c`), General Notary Acts, Violation Verdicts | `draft` | `vectors` |
| [SPEC-06-grants-and-delegation.md](spec/SPEC-06-grants-and-delegation.md) | Universal `grant/1` (`executor` vs Stateless `executor_ref`, Seal vs Root `window_only`, Acyclic `single_use` `0x11`), `invocation/1` & `receipt/1`, Depth-2 Re-Delegation (`R8.5`/`R8.6`), Early-Auth Admission Pipeline, Bearer Sessions, Anti-Rollback Fenced Journals | `draft` | `vectors` |
| [SPEC-07-services-and-portability.md](spec/SPEC-07-services-and-portability.md) | Sovereign Provider Authority & Pinned TLS Mutual Auth, Replaceable Services & Exclusive Cut-Over (`migration/1`), Federated Screening & Progressive PII Disclosure (Contour A), SLIP Extension Checklists | `draft` | `vectors` |

### Standard Profiles, Governance, SSOT, Vectors, and Guides

- **Standard Profiles ([`profiles/`](profiles/README.md)):**
  - [PROFILE-mail-v1.md](profiles/PROFILE-mail-v1.md) — Sovereign email hosting and delegated mailbox access (`mail/list`, `mail/read`, `mail/send`).
  - [PROFILE-agent-v1.md](profiles/PROFILE-agent-v1.md) — Bounded autonomous agent briefs (`agent/brief`), tool calls (`agent/tool`), contract-bound isolated sessions (`agent/session`), and guardian message verification (`agent/guardian-message`).
- **Governance & Conformance:**
  - [CONFORMANCE.md](CONFORMANCE.md) — Conformance roles, mandatory behavioral invariants, and maturity progression criteria.
  - [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md) — Authoritative registry of all `open` rules, provisional numeric constants, and unprofiled service types.
  - [SLIP-TEMPLATE.md](SLIP-TEMPLATE.md) — SealLink Improvement Proposal template and lifecycle process.
  - [CHANGELOG.md](CHANGELOG.md) — Release history.
- **Machine-Readable Registries ([`registry/`](registry/)):**
  - [`object-types.json`](registry/object-types.json) — 30 canonical `seallink-*/1` types, byte limits, signing roles, and schema links.
  - [`refusal-codes.json`](registry/refusal-codes.json) — 84 deterministic refusal codes with closure and retryability flags.
  - [`opreturn-actions.json`](registry/opreturn-actions.json) — `SLNK` (`534c4e4b`) `OP_RETURN` action bytes (`0x01`–`0x11`, `0x06` reserved) and locator types (`0x00`, `0x01`, `0x02`, `0x05`).
  - [`key-roles.json`](registry/key-roles.json) — 22 key roles, curves, custody tiers, and signing domain constraints.
  - [`service-types.json`](registry/service-types.json) — Standard service types + reverse-domain extension grammar.
  - [`constraints.json`](registry/constraints.json) — 7 conservative Constraint Algebra predicates and quota windows.
- **Formal JSON Schemas ([`schemas/`](schemas/)):** 12 Draft 2020-12 schemas (`common`, `name-value`, `manifest`, `card`, `origin`, `guardian`, `contract`, `credential`, `grant`, `invocation`, `profile-mail`, `profile-agent`).
- **Executable Conformance Vectors ([`vectors/`](vectors/)):**
  - `wire-jcs-and-hashes.json` — Restricted JCS positive/negative, 3 hashes, `clause_hash`, BIP-340 `SignatureSet`.
  - `ledger-scripts-and-opreturn.json` — All 3 Namecoin prefix scripts, all `ScriptPolicy` compilations, `P2A` CPFP, `SLNK` `OP_RETURN` hex frames, and 5-leaf Merkle batch `0x02` inclusion proofs.
  - `constraints-and-schemas.json` — All 7 Constraint Algebra predicates (match + narrowing + conservative rejections) and negative schema/semantic fixtures.
  - `trace-01-mail-offline-revoke.json` — End-to-end mail trace (offline issuer, `mail/read` receipt, constraint refusal, mempool seal spend -> `GRANT_CLOSED`).
  - `trace-02-guardian-succession-assent.json` — End-to-end guardianship trace (acyclic Stage 1 `0x0d` -> Stage 2 `0x0e` -> roster `0x0f` -> ward contract `assent/1`, old guardian refused `GUARDIAN_INACTIVE`, ward refused `WARD_AUTONOMOUS_FORBIDDEN`).
  - `trace-03-delegation-pool-single-use.json` — End-to-end delegation & single-use trace (2 groups sharing 1 pool under R8.5/R8.6, acyclic `0x11` single-use execution, crash replay idempotency, issuer revocation -> `GRANT_CLOSED`).
- **Informative Guides & Traceability:**
  - [GUIDE-01-custody-and-signers.md](guides/GUIDE-01-custody-and-signers.md) — Hardware/cold custody, Namecoin `namepsbt`, crash-safe delegation reservation ledger, and Agent Isolation Runtime integration.
  - [archive/rule-inventory.md](archive/rule-inventory.md) — Granular invariant-level migration traceability from the historical draft corpus.

---

## Automated Verification and Release Bundles

Run the specification linter (validating registries, cross-registry signer coherence, rule uniqueness, JSON Schema Draft 2020-12 metaschemas, and cryptographic verification of all test vectors) and the single-file bundle check locally:

```bash
python3 tools/speclint.py
python3 tools/build_bundle.py --version v1.0.0-draft.1 --check
```

Pushing a signed release tag (`v*`) triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which runs the full lint and vector suite, compiles the entire specification into one deterministic Markdown file (`seallink-spec-<tag>.md` + `.sha256`), and publishes a GitHub Release automatically.
