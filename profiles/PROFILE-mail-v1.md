# PROFILE-mail-v1: Sovereign Email Hosting and Delegated Mailbox Access

- **Version:** `1.0.0-draft.1`
- **Service Type:** `mail` (`registry/service-types.json`)
- **Status:** `draft` (normative profile rules `decided`)
- **Evidence / Maturity:** `vectors` (`vectors/trace-01-mail-offline-revoke.json`)
- **Requires:** `SPEC-01`, `SPEC-02`, `SPEC-03`, `SPEC-06`, `SPEC-07`
- **Schemas:** `schemas/profile-mail.schema.json`

---

## 1. Purpose

This profile defines sovereign email hosting where the **holder owns her identity (`id/alice`), not the mail host**, binds one or more labeled mailboxes (`personal`, `work`, etc.) by pinned `NamePin` in `seallink-manifest/1`, switches providers without losing identity, and issues fine-grained UTXO-revocable grants (e.g., permitting an agent or accountant to read only `"Invoices"` while the issuer's devices remain offline).

---

## 2. Manifest Declarations, Discovery, and Transport Binding

### 2.1 User Provider Binding (`SL-MAIL-001`, `decided`)
A holder `id/alice` declares each hosted mailbox in `seallink-manifest/1` `providers[]` using a full `NamePin`:
```json
{
  "label": "work",
  "provider": {
    "name": "id/mail-host-a",
    "owner_policy": {"kind": "key", "pk": "02..."},
    "registration": {"txid": "...", "vout": 0}
  },
  "service_type": "mail"
}
```
An actor MAY bind multiple `mail` providers under distinct `label` values (`personal`, `work`, `archive`).

### 2.2 Mail Provider Self-Declaration, External Discovery, and Mutual Auth (`SL-MAIL-002`, `decided`)
1. A mail provider `id/mail-host-a` declares in its own `seallink-manifest/1` `service`:
   - `service_type`: `"mail"`
   - `actions`: subset of `["mail/list", "mail/read", "mail/send"]`
   - `receipt_key`: pinned BIP-340 `receipt` key
   - `endpoint`: HTTPS base URL
   - `tls_spki_sha256`: SHA-256 of the server's DER-encoded SubjectPublicKeyInfo (alternatively pinned via a signed `seallink-statement/1` with `statement_kind = "transport-binding"` and `transport = "https-tls-spki"` in the provider's `certs` set).
2. **Mutual authentication:** Clients MUST verify the server's TLS certificate SPKI against `tls_spki_sha256` (or the verified `transport-binding` statement) AND verify every `seallink-receipt/1` against `service.receipt_key`.
3. **External sender mailbox discovery:** An external sender targeting `id/alice` resolves `id/alice`'s confirmed `seallink-manifest/1`, selects the `providers[]` entry for `("mail", label)` (default `label = "primary"` if unspecified, or advertised in `seallink-card/1` `transports`), resolves the pinned `provider` `NamePin`, and delivers to the provider's `service.endpoint` (or SMTP MX authenticated via the provider's manifest/card transport declaration).

---

## 3. Orthogonal Action Properties Table

| Action | Kind | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `requires_contract` | `require_seal` | Risk Class |
| --- | --- | :-: | :-: | :-: | :-: | :-: | :-: | --- |
| `mail/list` | Mechanical effect | `false` | `true` | `false` *(optional)* | `true` *(iff no `quotas`)* | `false` | `true` | Class 2 (90m) |
| `mail/read` | Mechanical effect | `false` | `true` | `false` *(optional)* | `true` *(iff no `quotas`)* | `false` | `true` | Class 2 (90m) |
| `mail/send` | Mechanical effect | `true` | `false` | `true` (`seallink/count`) | `false` *(concrete `executor` MUST be pinned)* | `false` | `true` | Class 1 (60m) |

All three actions are mechanical effects and MUST refuse grants carrying `terms_text` (`GRANT_TEXT_FORBIDDEN`).

---

## 4. Target, Closed Argument/Result Schemas, and `result_sha256` (`SL-MAIL-003`, `decided`)

- **Target grammar:** `mailbox:<owner_name>:<label>` (e.g., `mailbox:id/alice:work`).
  The provider MUST verify that `<owner_name>`'s confirmed `seallink-manifest/1` binds this provider's exact `NamePin` for `("mail", <label>)` (`SERVICE_PROVIDER_UNBOUND` otherwise) AND that the root grant was issued by `<owner_name>` (or its satisfied guardian quorum if `<owner_name>` is a `ward`).
- **Closed argument and result schemas:** All `invocation.arguments` and returned result objects MUST validate strictly against `schemas/profile-mail.schema.json`:
  - `mail/list`: `MailListArgs` -> `MailListResult`
  - `mail/read`: `MailReadArgs` -> `MailReadResult`
  - `mail/send`: `MailSendArgs` -> `MailSendResult`
- **Normative `result_sha256` formula (`SL-MAIL-006`, `decided`):** For every `outcome = "executed"` response, `receipt.payload.result_sha256` MUST equal `SHA256(canonical_JCS(result_object))` where `result_object` conforms to the action's closed result schema above. For `mail/read`, raw RFC 5322 message bytes travel alongside the signed receipt and MUST hash to `MailReadResult.mime_sha256`.
- **Replay semantics:** For `mail/list` and `mail/read`, a duplicate `invocation_id` within `[iat, exp)` MAY return the cached signed receipt; for `mail/send`, a duplicate `invocation_id` MUST perform zero second SMTP handoff and MUST return the original stored signed receipt (including `outcome = "uncertain"` if unresolved).

### 4.1 Constrained Arguments and Server-Side Enforcement (`SL-MAIL-004`, `decided`)

| Action | Argument | Schema Type | Supported `where` Predicates |
| --- | --- | --- | --- |
| `mail/list`, `mail/read` | `folder` | `string` | `eq`, `in`, `not_in`, `prefix` |
| `mail/list`, `mail/read` | `sender_domain` | `string` (lowercase ASCII) | `eq`, `in`, `not_in`, `suffix` |
| `mail/read` | `message_id` | `string` | `eq`, `in` |
| `mail/list`, `mail/read` | `max_bytes` | `uint64_str` | `range` |
| `mail/send` | `to` | `string` | `eq`, `in`, `not_in`, `suffix` |
| `mail/send` | `subject` | `string` | `eq`, `prefix` |
| `mail/send` | `body_sha256` | `hex64` | `hash_eq` |
| `mail/send` | `size_bytes` | `uint64_str` | `range` |

- **Server-side verification for `mail/read`:** If the grant constrains `folder`, `sender_domain`, or `max_bytes`, the provider MUST verify the actual stored message's folder, `From` domain, and byte length satisfy every `where` predicate before returning bytes (`INVOKE_CONSTRAINT_FAILED`). A caller MUST NOT bypass a `folder` predicate by passing a `message_id` belonging to another folder.
- **Quota reservation for `mail/send`:** MUST reserve `1` unit from `{"kind":"seallink/count","resource":"mailbox:<owner>:<label>","unit":"messages"}` atomically in the fenced journal (`SPEC-06 §6`) before SMTP submission, retaining the reservation if handoff outcome is `uncertain`.

---

## 5. Snapshot Pagination and Provider Cut-Over (`SL-MAIL-005`, `decided`)

1. A `mail/list` request with `page = 0` and no `snapshot_id` establishes a provider-local immutable snapshot (`snapshot_id`, TTL `<= 300s`, frozen to matching messages present at that invocation's observation).
2. Subsequent pages (`page > 0`) MUST pass `snapshot_id` in a newly signed `seallink-invocation/1`, re-running the full `SPEC-06 §4` pipeline (including live UTXO seal check).
3. Messages arriving after snapshot creation do NOT appear in pages of that `snapshot_id`. If the grant's seal is spent between page 0 and page 1, page 1 refuses `GRANT_CLOSED` (if already journaled) or `SEAL_SPENT` (if first witnessed on page 1) and discards the snapshot.
4. **Provider switch:** Snapshots are strictly local to the issuing provider and are NOT exported during `seallink-migration/1`. Presenting an old provider's `snapshot_id` to a new provider refuses `INVOKE_CONSTRAINT_FAILED`; the caller restarts at `page = 0` on the new provider.

---

## 6. Reference End-to-End Trace (`vectors/trace-01-mail-offline-revoke.json`)

The complete byte-level trace (signed JCS objects, BIP-340 signatures, `OP_RETURN` hex, `result_sha256`, journal hash chain, and exact refusal codes) is published in `vectors/trace-01-mail-offline-revoke.json`:

1. `id/alice` binds `id/mail-host-a` (by full `NamePin`) for `("mail", "work")` in her `seallink-manifest/1`.
2. `id/alice` signs a unilateral `seallink-grant/1` to `id/alice-acct-agent` using `executor_ref: {"provider_of":"id/alice","service_type":"mail","label":"work"}` (valid because `mail/read` has `external_mutation = false`, `quota_consuming = false`, `allows_executor_ref = true`, and no `quotas`) with `where: {"folder": {"in": ["Invoices"]}}` and confirmed UTXO `seal` anchored by `0x01`.
3. `id/alice` takes all her devices offline.
4. `id/alice-acct-agent` sends a signed `seallink-invocation/1` (`folder = "Invoices"`, `message_id = "msg-2026-001"`) + inline grant + inline manifest to `id/mail-host-a`.
5. `id/mail-host-a` runs `SPEC-06 §4` on its own Namecoin node -> **Admits**, returns `MailReadResult` + raw MIME bytes + signed `seallink-receipt/1` (`outcome = "executed"`, `result_sha256 = SHA256(JCS(MailReadResult))`).
6. A second invocation requesting `folder = "Personal"` fails Step 11d -> **Refuses** `INVOKE_CONSTRAINT_FAILED` (non-closing).
7. Later, `id/alice` spends `seal` from a secondary device. `id/mail-host-a` witnesses the spend in its mempool and durably writes a `closure(cause="SEAL_SPENT")` entry to its fenced journal (`c(0) -> c(1)`).
8. When `id/alice-acct-agent` sends a new `mail/read` invocation for `"Invoices"`, Step 6a of `SPEC-06 §4` hits the durable closure journal and returns the single deterministic refusal code **`GRANT_CLOSED`** with signed `seallink-receipt/1` (`outcome = "refused"`, `refusal_code = "GRANT_CLOSED"`).

---

## 7. Export Boundary (`SPEC-07 §2`)

A `mail` migration manifest (`seallink-migration/1`) exports RFC 5322 message blobs, folder assignments, message IDs, delivery receipts, and accounting evidence (settled `mail/send` counts + uncertain SMTP handoffs). It NEVER exports DKIM signing keys, SMTP relay credentials, TLS private keys, or active bearer tokens.
