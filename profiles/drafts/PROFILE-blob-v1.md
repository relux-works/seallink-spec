# PROFILE-blob-v1: Grant-Aware Content-Addressed Blob Store (Blossom BUD-01/02/04)

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — Reserved `open` standard service type (`registry/service-types.json`, `OPEN-QUESTIONS.md §3`); requires full SLIP + Draft 2020-12 schema + conformance vectors per `SPEC-07 §4.1` before promotion.
- **Service Type:** `blob`

---

## 1. Scope & Replaceable Content-Addressed Storage

Combines content-addressed Blossom (`BUD-01` `GET /<sha256>`, `BUD-02` upload/delete, `BUD-04` mirroring) with sovereign SealLink `manifest.providers[service_type="blob"]` bindings and fine-grained storage/egress quotas:
- Holders store encrypted backups, media, agent artifacts, and public manifest mirrors on one or more replaceable `blob` providers (`NamePin`-pinned, zero platform lock-in).
- Read grants for static public/shared blobs MAY use stateless `executor_ref` (when quota-free); uploads, pins, deletes, and metered bandwidth require concrete `executor` + `seallink/bytes` quotas.
- Provider migration (`SPEC-07 §2`) exports content-addressed blob shard manifests (`MigrationInventory.items[] <= 4096`) verifiable purely by SHA-256 without revealing client-side encryption keys.

---

## 2. Candidate Action Leaves & Orthogonal Flags (`SPEC-07 §4.1`)

| Action | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `allows_bearer_session` | `requires_contract` | `require_seal` | Risk Class |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `blob/get` | `false` | `true` | `false` *(optional egress quota)* | `true` *(when quota-free)* | `true` | `false` | `false` | Class 2 (`5400s`) |
| `blob/put` | `true` | `false` | `true` | `false` | `true` | `false` | `true` | Class 1 (`3600s`) |
| `blob/delete` | `true` | `false` | `true` | `false` | `false` | `false` | `true` | Class 1 (`3600s`) |

- **Target grammar:** `^blob:id/[a-z0-9][a-z0-9._-]{0,63}:[a-z0-9._-]{1,64}$` (e.g., `blob:id/alice:backups`).
- **Required quotas (`blob/put`):** `seallink/bytes` (`bytes`, `resource == target`).
- **Candidate `where` predicates:** `sha256` (`eq`/`in`), `mime_type` (`eq`/`in`/`prefix`), `size_bytes` (`range`), `retention_days` (`range`).
- **Mechanical `terms_text` ban:** All `blob/*` actions refuse `terms_text` (`GRANT_TEXT_FORBIDDEN`).

---

## 3. Open SLIP Checklist Items (`SPEC-07 §4.1`)
1. Formal `schemas/profile-blob.schema.json` covering Blossom HTTP header framing, chunked upload verification, and `result_sha256`.
2. Storage quota release semantics on `blob/delete` vs immutable archival retention.
3. Full conformance vectors (quota overrun, `executor_ref` read migration, mempool revocation).
