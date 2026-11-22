# SPEC-07: Grant-Gated Services, Replaceable Providers, Federated Disclosure, and Extensions

- **Version:** `1.0.0-draft.1`
- **Status:** `draft` (normative rules `decided`; unprofiled standard service types tracked `open` in `OPEN-QUESTIONS.md`)
- **Evidence / Maturity:** `vectors` (`vectors/trace-01-mail-offline-revoke.json`)
- **Registries:** `registry/service-types.json`, `registry/object-types.json`, `registry/refusal-codes.json`
- **Schemas:** `schemas/manifest.schema.json`, `schemas/invocation.schema.json`

---

## 1. Sovereign Provider Model and Mutual Authentication

SealLink decouples user identity from service hosting (email, agent hosts, XMPP, blob storage, wallets, compute) through three normative rules (`SL-SERV-001`, `decided`):

1. **Pinned Provider Binding (`manifest.providers`):** A resource holder `id/alice` declares her active service providers in her `seallink-manifest/1` (`SPEC-03 §3.1`) by labeled `(service_type, label, provider: NamePin)` tuples. Because `provider` pins `(name, registration, owner_policy)`, an expired and re-registered provider spelling cannot hijack dynamic delegations.
2. **Provider Authority Rule:** A participating provider hosting resources for `id/alice` recognizes `id/alice` (its confirmed ledger name, `ScriptPolicy`, role keys, and origin/guardian rules) as the sole root of authority over `id/alice`'s hosted resources. The provider MUST serve any caller presenting a valid `seallink-grant/1` issued by `id/alice` (and verifying `id/alice`'s confirmed manifest binds this provider's exact `NamePin` for `(service_type, label)`, refusing `SERVICE_PROVIDER_UNBOUND` otherwise), without requiring the caller to hold a proprietary account at that provider.
3. **Mutual Transport Authentication:** Before sending private grants, credentials, or sensitive data to a provider `id/provider`, the client resolves `id/provider` on its own ledger view, fetches `id/provider`'s verified `seallink-manifest/1`, and authenticates the endpoint against `service.tls_spki_sha256` (or a verified `seallink-statement/1` with `statement_kind = "transport-binding"` and `transport = "https-tls-spki"` in `id/provider`'s `certs` set) plus verifies signed responses against `service.receipt_key` — never trusting unverified HTTP redirects or peer-claimed provider identities.

---

## 2. Replaceable Services and Exclusive Cut-Over (`seallink-migration/1`)

An actor MUST be able to switch from Provider A (`source_executor`) to Provider B (`dest_executor`) of a compatible `service_type` profile while keeping her `id/` identity and without creating duplicate authorized effects or resurrecting spent quotas (`SL-SERV-002`, `decided`).

### 2.1 Portable State Separation

Every service export profile MUST strictly partition three classes of data:
1. **Holder data** (messages, blobs, files, metadata) — portable; holder-side E2EE decryption keys need never be disclosed to either provider.
2. **Accounting evidence** (journal position/commitment, settled usage, outstanding uncertain reservations, signed receipts) — portable for reconciliation, NEVER treated by `dest_executor` as unconsumed authority.
3. **Execution credentials** (provider wallet keys, upstream API secrets, DKIM keys, active bearer tokens, TLS private keys) — **STRICTLY EXCLUDED** from export; `dest_executor` MUST refuse any export containing execution credentials (`SERVICE_MIGRATION_INVALID`).

### 2.2 Four-Step Exclusive Cut-Over (`SL-SERV-003`, `decided`)

1. **Stage:** Copy hash-checked holder data to `dest_executor` while `source_executor` remains the sole accounting authority (`dest_executor` admits zero effects on imported state).
2. **Fence & Close:** `source_executor` durably fences new admissions across all replicas, drains in-flight work (retaining every unresolved outcome as bounded `outstanding_exposure`), and signs `seallink-migration/1` (`journal_pos`, `journal_commitment`, `inventory_sha256`, `outstanding_exposure`) with its pinned `receipt` key.
3. **Revoke Old Grants & Issue Replacement Grants:** Close predecessor concrete-executor grants at `source_executor` via seal spend (a closing receipt alone is NOT revocation). For stateful grants, issue fresh concrete-executor grants naming `dest_executor` with reconciled remaining quotas (deducting settled usage AND all uncertain exposure). Update `manifest.providers` in one ledger name update.
4. **Activate:** Holder signs `seallink-assent/1` (`target_type = "seallink-migration/1"`); `dest_executor` counter-signs acceptance, verifies full hash inventory, persists import atomically (rejecting rollback or conflicting `migration_id` with `SERVICE_MIGRATION_INVALID`), and enables admissions while `source_executor` remains fenced.

- **Unavailable old provider:** Operator reconciliation is the default. Never infer unused budget or non-execution from timeouts or silence; keep old uncertain exposure isolated and issue an independent bounded allocation for non-conflicting work.
- **Commercial default:** Start with small capped prepaid contracts. Unused prepaid credit remains `source_executor`'s liability and does not transfer automatically by data export.

---

## 3. Federated Screening and Progressive PII Disclosure

When two previously unknown actors (or their agents) communicate before establishing mutual trust, SealLink defines a two-phase progressive-disclosure composition (`SL-SERV-004`, `decided`):

| Phase | Admission Gate | Data & Tool Boundary | Human / Guardian Gate |
| --- | --- | --- | --- |
| **Phase 1: Screening** | Pinned local trust policy + verified peer identity/members binding + optional `seallink-credential/1` (e.g., `subject-claim` / `agent-audit`) + bounded screening grant. | Zero PII and zero external mutation tools inside the screening context. Explicit per-peer quotas required (`FEDERATION_POLICY_DENIED` if missing). | Autonomous within bounded screening quotas. |
| **Phase 2: Targeted Disclosure** | Fresh unilateral `seallink-grant/1` targeting ONE exact recipient and ONE isolated vault executor (e.g., `contact-vault` or `calendar-broker`), finite window, dedicated UTXO seal. | **Contour A routing:** For PII release (e.g., `contact/release`), the recipient MUST be the partner's personal identity or companion client calling the isolated vault directly — PII MUST NOT transit screening agents or hubs (`FEDERATION_POLICY_DENIED`). | Explicit L2 / presence-verified approval by the human owner or guardian quorum; the screening agent MUST NEVER self-issue a disclosure grant. |

Neither federation membership nor a verified `seallink-credential/1` ever creates grant authority; trust policy may only narrow admission.

---

## 4. Extension Rules and SLIP Registration Checklists

Every new **Service Profile**, **Action Leaf**, **Quota Kind**, **Contract Profile**, or **Credential Kind** MUST be proposed via a SLIP (`SLIP-TEMPLATE.md`) or namespaced under reverse-DNS (`com.example/<name>`) for custom deployments, and MUST explicitly specify (`SL-SERV-005`, `decided`):

### 4.1 Action Leaf and Service Profile Checklist
1. **Identifier:** Exact `service_type` (registered in `registry/service-types.json` or valid reverse-domain) and lowercase slash-separated action leaves (`<domain>/<verb>`).
2. **Orthogonal Action Properties:**
   - Cognitive `work` (MAY accept `terms_text`) vs mechanical `effect` (MUST enforce `GRANT_TEXT_FORBIDDEN`);
   - `external_mutation` (`true | false`);
   - `discloses_data` (`true | false`);
   - `quota_consuming` (`true | false`);
   - `allows_executor_ref` (`true | false`, allowed ONLY when `external_mutation = false` and `quota_consuming = false`);
   - `requires_contract`, `require_seal`, and Chain Risk Class (`Class 1` 60m vs `Class 2` 90m).
3. **Closed Target, Arguments, and Result Schemas:** Formal Draft 2020-12 JSON Schema (`schemas/profile-<name>.schema.json`) for `arguments` and `result` objects, target grammar, and permitted Constraint Algebra predicates per argument.
4. **Pagination / Snapshot and Replay Semantics:** Exact behavior for multi-page reads, provider switch invalidation, and duplicate `invocation_id` retries.
5. **Quota Consumption and Settlement:** Consumed quota kinds, reservation formula before effect, actual settlement/release rule, and uncertain-outcome retention rule.
6. **Receipt and Export Format:** Exact `result_sha256` payload definition (`SHA256(canonical_JCS(result_obj))`), mutual transport auth binding, and portable export boundary (`§2.1`).
7. **Deterministic Refusal Order and Vectors:** Complete positive, single-defect negative, and stateful-journal revocation test vectors citing exact `SL-*` rule IDs.

### 4.2 Quota Kind Checklist
Every new `quota.kind` in `registry/constraints.json` MUST define: identifier, resource grammar, exact atomic integer unit and scale (zero binary64), min/max bounds, rounding direction (always upward/conservative on reservation), permitted `window` modes, concurrency/replica sharing, uncertain-outcome retention, denied-request charging (default: refused requests consume zero quota), and paired conformance vectors.

---

## 5. Security Considerations

- **No wildcard recipients:** Services MUST NEVER convert an authenticated login session (`SPEC-03 §5`) or federation allowlist into a wildcard grant recipient.
- **Irreversibility of disclosure:** Spending a disclosure seal stops future reads but cannot erase already-disclosed bytes; prefer revocable handles and ephemeral channels over permanent personal identifiers.
- **No central verification oracle:** Services SHOULD run their own Tier 1 verifier and Namecoin node (`SPEC-02 §1.1`) rather than delegating verification to a third-party validation API.

---

## 6. References

- **Normative:** [RFC8785], [BIP-340], [JSON-SCHEMA-2020-12].
- **Informative:** [RFC8448].
