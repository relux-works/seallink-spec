# Changelog

All notable changes to the SealLink Protocol Specification are documented in this file.

## [1.0.0-draft.1] - 2026-11-22

Initial modular draft of the SealLink v1.0 Protocol Specification:

- **Normative Core Specifications (`spec/SPEC-00` through `spec/SPEC-07`):** Architecture, Restricted RFC 8785 JCS wire format and 7-predicate Constraint Algebra, Namecoin Core `nc28.0` ledger binding (`NAME_NEW` / `NAME_FIRSTUPDATE` / `NAME_UPDATE`, `ScriptPolicy`, Merkle batch `0x02`, `P2A` CPFP), 520-byte multi-role identity with on-chain role-policy pins and pinned `NamePin` providers, eternal origin certificates with salted privacy commitments, authenticated `status_seal` / `roster_seal` spines, acyclic two-stage guardianship (`0x0d`/`0x0e`) and roster transitions (`0x0f`), N-party salted contracts with `machine_clause_indices` and symmetric `seallink-assent/1`, universal grants with R8.5/R8.6 depth-2 re-delegation, acyclic single-use consumption (`0x11`), early-auth admission pipeline, fenced anti-rollback journals, and replaceable service portability.
- **Standard Profiles (`profiles/`):** `PROFILE-mail-v1.md` (`mail`) and `PROFILE-agent-v1.md` (`agent-session`), backed by closed argument and result JSON Schemas.
- **Machine-Readable SSOT (`registry/`, `schemas/`):** 6 JSON registries (30 object types, 22 key roles, 84 refusal codes, 17 `SLNK` `OP_RETURN` action definitions, 8 standard service types, 7 Constraint Algebra predicates) and 12 Draft 2020-12 JSON Schemas.
- **Executable Conformance Vectors (`vectors/`):** Unit vectors (JCS, hashes, `clause_hash`, BIP-340 `SignatureSet`, Namecoin prefix scripts, `ScriptPolicy`, Merkle batch `0x02`, Constraint Algebra, negative schema/semantic cases) and 3 end-to-end RFC 8448-style traces (`mail` offline+revoke, guardian succession+ward assent, parent pool+single-use+replay+revoke).
- **Governance & Tooling:** `CONFORMANCE.md`, `OPEN-QUESTIONS.md`, `SLIP-TEMPLATE.md`, `guides/GUIDE-01-custody-and-signers.md`, `archive/rule-inventory.md`, zero-dependency reference primitives (`tools/seallink_ref.py`), vector generator (`tools/gen_vectors.py`), linter (`tools/speclint.py`), single-file Markdown bundle builder (`tools/build_bundle.py`), and GitHub Actions CI/Release pipelines.
