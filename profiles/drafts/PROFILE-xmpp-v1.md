# PROFILE-xmpp-v1: Sovereign XMPP Hosting and Delegated Messaging

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — Reserved `open` standard service type (`registry/service-types.json`, `OPEN-QUESTIONS.md §3`); requires full SLIP + Draft 2020-12 schema + conformance vectors per `SPEC-07 §4.1` before promotion.
- **Service Type:** `xmpp`

---

## 1. Scope & Decoupled Hosting Model

Decouples a user's XMPP identity (`id/alice`) and OMEMO E2EE keys (`transport-binding` with `transport = "xmpp"`, `PROFILE-e2ee-messaging-v1`) from the XMPP server hosting their JID and MAM archive:
- Holder pins their active XMPP server via `manifest.providers[]` with `service_type = "xmpp"` and full `NamePin(provider)`.
- Supports both classic federated XMPP (`alice@xmpp.example`) and native `.bit` XMPP (`alice@alice.bit`) with pinned `https-tls-spki` / STARTTLS SPKI authentication.
- Provider switch uses the 4-step exclusive cut-over (`seallink-migration/1`, `SPEC-07 §2`) exporting MAM archives and roster metadata while excluding server S2S keys and session tokens.

---

## 2. Candidate Action Leaves & Orthogonal Flags (`SPEC-07 §4.1`)

| Action | `external_mutation` | `discloses_data` | `quota_consuming` | `allows_executor_ref` | `allows_bearer_session` | `requires_contract` | `require_seal` | Risk Class |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `xmpp/read-archive` | `false` | `true` | `false` | `true` | `true` | `false` | `false` | Class 2 (`5400s`) |
| `xmpp/send` | `true` | `false` | `true` | `false` | `true` | `false` | `true` | Class 1 (`3600s`) |
| `xmpp/muc-post` | `true` | `false` | `true` | `false` | `true` | `false` | `true` | Class 1 (`3600s`) |

- **Target grammar:** `^xmpp:id/[a-z0-9][a-z0-9._-]{0,63}:[a-z0-9._-]{1,64}$` (authorizing root issuer == holder `<owner>` pinned to executor in `manifest.providers[service_type="xmpp"]`).
- **Candidate `where` predicates:** `peer_jid` (`eq`/`in`/`suffix`), `muc_room` (`eq`/`in`), `max_bytes` (`range`).
- **Required quotas (`xmpp/send`, `xmpp/muc-post`):** `seallink/count` (`messages`, `resource == target`).
- **Mechanical `terms_text` ban:** All `xmpp/*` leaves refuse `terms_text` (`GRANT_TEXT_FORBIDDEN`).

---

## 3. Open SLIP Checklist Items (`SPEC-07 §4.1`)
1. Formal `schemas/profile-xmpp.schema.json` covering stanza arguments, MAM cursor snapshots, and canonical `result_sha256`.
2. SASL mechanism binding `seallink-auth-challenge/1` + depth-16 `AuthEntryProof` over XMPP C2S.
3. Conformance vectors (`ADMIT`, constraint refusals, provider switch, mempool revocation).
