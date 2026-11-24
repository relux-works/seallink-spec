# SPEC-07: Grant-Gated Services, Replaceable Providers, Federated Disclosure, and Extensions

- **Version:** `1.0.0-draft.8`
- **Status:** `draft` (normative rules `decided`; unprofiled standard service types tracked `open` in `OPEN-QUESTIONS.md`)
- **Evidence / Maturity:** `vectors` (`vectors/trace-01-mail-offline-revoke.json`, `vectors/trace-04-agent-guardian-intake.json`, `vectors/refusal-coverage-matrix.json`)
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

Service providers declaring conformance to the optional v1.0 **Service Migration** module (`CONFORMANCE.md §1.1`) MUST strictly separate **staging (`mode = "stage"`)** from **activation (`mode = "activate"`, normative default)** and enforce this exact four-step verifiable cut-over (providers NOT declaring this module MUST refuse `seallink-migration/1` fail-closed with `ACTION_UNSUPPORTED` / `WIRE_TYPE`):

1. **Stage (`mode = "stage"`, canonical `MigrationInventory` only):** Assemble a canonical JCS `MigrationInventory` (`schemas/invocation.schema.json#/$defs/MigrationInventory`) strictly containing `migration_id`, `holder_name`, `service_type`, and allowlisted portable holder `items[]` (`{path, sha256, size_bytes, media_type}`) — ad-hoc legacy inventory objects are FORBIDDEN (`SERVICE_MIGRATION_INVALID`). Copy hash-checked holder data to `dest_executor` while `source_executor` remains the sole accounting authority: `mode = "stage"` verifies `seallink-migration/1` wire format, signature against `source_executor`'s confirmed manifest `service.receipt_key`, canonical `MigrationInventory` allowlist, and exact `SHA256(canonical_JCS(inventory)) == migration.inventory_sha256` (zero execution secrets), performs **zero journal writes**, and admits zero effects on imported state.
2. **Fence & Close (`seallink-migration/1`):** `source_executor` durably fences new admissions across all replicas, drains in-flight work (retaining every unresolved outcome as bounded `outstanding_exposure`), and signs `seallink-migration/1` (`migration_id`, `holder`, `service_type`, `source_executor`, `dest_executor`, `journal_pos`, `journal_commitment`, `inventory_sha256`, `outstanding_exposure`, `issued_at`) with its confirmed manifest `service.receipt_key`.
3. **Revoke Old Grants & Issue Replacement Grants:** Close predecessor concrete-executor grants at `source_executor` via seal spend (a closing receipt alone is NOT revocation). For stateful grants, issue fresh concrete-executor grants naming `dest_executor` with reconciled remaining quotas (deducting settled usage AND all uncertain exposure). Update `manifest.providers` in one ledger name update pinning `dest_executor`'s exact `NamePin`.
4. **Activate (`mode = "activate"`, ALL 4 mandatory proofs + journal `migration-applied`):** `dest_executor` MUST fail closed (`GRANT_EXECUTOR_MISMATCH` if `migration.dest_executor != local_executor_pin`, `SERVICE_PROVIDER_UNBOUND` if holder's manifest does not pin `dest_executor`, `SERVICE_MIGRATION_INVALID` otherwise) unless ALL four normative activation proofs pass:
   - *(a) Local executor & source verification:* `migration.dest_executor` equals `local_executor_pin` (`NamePin`, refusing `GRANT_EXECUTOR_MISMATCH` otherwise), `seallink-migration/1` verifies against `source_executor`'s confirmed manifest `service.receipt_key`, and canonical `MigrationInventory` passes allowlist + `inventory_sha256` equality with zero execution secrets;
   - *(b) Holder assent:* Verified `seallink-assent/1` (`target_type = "seallink-migration/1"`, `target_id = id(seallink-migration/1)`, `party_name = holder.name`; for a `ward`, carrying `guardian_context` with `event_class = "custody_change"` and satisfied `guardian_approvals[]` per `SPEC-04 §3.1`);
   - *(c) Confirmed provider pin:* Holder's confirmed `seallink-manifest/1` `providers[]` pins `dest_executor`'s exact `NamePin` for `service_type`;
   - *(d) Destination acceptance statement & uniqueness:* Verified `dest_executor`-signed `seallink-statement/1` (`statement_kind = "migration-accept"`, `subject = {migration_id, holder, source_executor, inventory_sha256}`) matching `local_executor_pin`, AND no duplicate or conflicting `migration_id` in `FencedJournal`.
   Only once all four proofs pass does `dest_executor` durably append ONE `migration-applied` `JournalEntry` to `FencedJournal` and enable admissions while `source_executor` remains fenced.

- **Unavailable old provider:** Operator reconciliation is the default. Never infer unused budget or non-execution from timeouts or silence; keep old uncertain exposure isolated and issue an independent bounded allocation for non-conflicting work.
- **Commercial default:** Start with small capped prepaid contracts. Unused prepaid credit remains `source_executor`'s liability and does not transfer automatically by data export.

---

## 3. Federated Screening and Progressive PII Disclosure

When two previously unknown actors (or their agents) communicate before establishing mutual trust, services declaring conformance to the optional v1.0 **Federated Screening & Progressive PII Disclosure** module (`CONFORMANCE.md §1.1`) MUST enforce this exact two-phase composition (`SL-SERV-004`, `decided`; services NOT declaring this module MUST refuse fail-closed with `ACTION_UNSUPPORTED` / `FEDERATION_POLICY_DENIED`):

| Phase | Admission Gate | Data & Tool Boundary | Human / Guardian Gate |
| --- | --- | --- | --- |
| **Phase 1: Screening** | Pinned local trust policy + verified peer identity/members binding + optional `seallink-credential/1` (e.g., `subject-claim` / `agent-audit`) + bounded screening grant. | Zero PII and zero external mutation tools inside the screening context. Explicit per-peer quotas required (`FEDERATION_POLICY_DENIED` if missing). | Autonomous within bounded screening quotas. |
| **Phase 2: Targeted Disclosure** | Fresh unilateral `seallink-grant/1` targeting ONE exact recipient (`recipient_name`, NEVER a screening agent or hub) and ONE concrete isolated vault executor (e.g., `contact-vault` or `calendar-broker`), finite window, dedicated UTXO seal (checked against persisted journal closures), paired with a verified L2 approval (`approve-pii-disclosure`). | **Contour A strict single-hop direct routing (`route_mode = "direct"`, `len(route_hops) == 1`):** PII MUST flow in one direct hop from the isolated vault to the exact authorized `recipient_name` — NEVER through any `screening_agent`, `hub`, or `relay` hop (`FEDERATION_POLICY_DENIED`). | Explicit L2 presence-verified `seallink-owner-command/1` (`command = "approve-pii-disclosure"`, `level = 2`, `arguments = {grant_id, recipient_name, fields_sha256, route_mode: "direct"}`) verified against the holder's **mandatory confirmed `seallink-manifest/1` AND pinned `sets.devices` (`seallink-device-list/1`)** naming an active unspent `presence = true, ceiling = 2` device (missing manifest or device list MUST fail closed `MANIFEST_UNAVAILABLE` / `DEVICE_UNAUTHORIZED`, NEVER skipped; or satisfied ward guardian quorum for a ward). Verifiers confirm exact `grant_id`, `recipient_name`, `route_mode == "direct"`, `fields_sha256`, and `iat <= now < exp` (`FEDERATION_POLICY_DENIED` on any mismatch or missing approval). |

Neither federation membership nor a verified `seallink-credential/1` ever creates grant authority; trust policy may only narrow admission.

---

## 4. Extension Rules and SLIP Registration Checklists

Every new **Service Profile**, **Action Leaf**, **Quota Kind**, **Contract Profile**, or **Credential Kind** MUST be proposed via a SLIP (`SLIP-TEMPLATE.md`) or namespaced under reverse-DNS (`com.example/<name>`) for custom deployments, and MUST explicitly specify (`SL-SERV-005`, `decided`):

### 4.1 Action Leaf and Service Profile Checklist
1. **Identifier:** Exact `service_type` (registered in `registry/service-types.json` or valid reverse-domain) and lowercase slash-separated action leaves (`<domain>/<verb>`) registered in `registry/actions.json`.
2. **Orthogonal Action Properties:**
   - Cognitive `work` (MAY accept `terms_text`) vs mechanical `effect` (MUST enforce `GRANT_TEXT_FORBIDDEN`);
   - `external_mutation` (`true | false`);
   - `discloses_data` (`true | false`);
   - `quota_consuming` (`true | false`);
   - `allows_executor_ref` (`true | false`, allowed ONLY when `external_mutation = false` and `quota_consuming = false`);
   - `requires_contract`, `require_seal`, and Chain Risk Class (`Class 1` 60m vs `Class 2` 90m).
3. **Target Authority Binding:** Exact rule mapping `invocation.target` to the authorized root issuer (`GRANT_TARGET_UNAUTHORIZED` whenever a foreign actor issues a grant targeting another holder's resource).
4. **Closed Target, Arguments, and Result Schemas:** Formal Draft 2020-12 JSON Schema (`schemas/profile-<name>.schema.json`) for `arguments` and `result` objects, target grammar, and permitted Constraint Algebra predicates per argument.
5. **Pagination / Snapshot and Replay Semantics:** Exact behavior for multi-page reads, provider switch invalidation, and duplicate `invocation_id` retries.
6. **Quota Consumption and Settlement:** Consumed quota kinds, reservation formula before effect, actual settlement/release rule, and uncertain-outcome retention rule.
7. **Receipt and Export Format:** Exact `result_sha256` payload definition (`SHA256(canonical_JCS(result_obj))`), mutual transport auth binding, and portable export boundary (`§2.1`).
8. **Deterministic Refusal Order and Vectors:** Complete positive, single-defect negative, and stateful-journal revocation test vectors citing exact `SL-*` rule IDs.

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
