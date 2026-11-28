# SealLink Exploratory Draft Extension Profiles (Non-Normative)

> **Non-Normative Status:** Every document in `profiles/drafts/` carries status **`exploratory-draft (non-normative)`**. These drafts demonstrate how domain protocols compose cleanly over the frozen SealLink v1.0 Core (`spec/SPEC-00`–`SPEC-07`) and serve as starting points for post-v1.0 Standard Profile SLIPs (`SPEC-07 §4`, `SLIP-TEMPLATE.md`). They are **NOT** part of v1.0 Core conformance requirements, are excluded from normative release bundles, and do not modify v1.0 wire schemas or refusal codes.

For normative v1.0 Standard Profiles (`decided`, schema-validated, vector-tested), see [`profiles/README.md`](../README.md).

## Exploratory Draft Catalog

| Draft Profile | Domain / `service_type` | Status | Summary |
| --- | --- | :-: | --- |
| [`PROFILE-ssh-v1.md`](PROFILE-ssh-v1.md) | `ssh` *(proposed)* | `exploratory-draft` | Zero-MITM OpenSSH host authentication (`KnownHostsCommand` + `transport-binding`), owner `config-section`/`policy-apply` & fleet depth-34 `sets.members` RBAC (`AuthorizedKeysCommand`), time-bounded contractor `seallink-grant/1` (`not_after_unix`), `ssh-ed25519` & FIDO2 `UP`/`UV` hardware tokens, and `0x11` break-glass. |
| [`PROFILE-sso-v1.md`](PROFILE-sso-v1.md) | `sso` | `exploratory-draft` | Decentralized Single Sign-On: OIDC Broker (Mode A1), Zero-Install Stateless Self-Sovereign WebAuthn Passkey Portal using `fido2-es256`/`fido2-eddsa` `UP`/`UV` (Mode A2), Native `.bit` / Secure Enclave direct auth (Mode B), and pairwise anonymous key-only login. |
| [`PROFILE-payment-v1.md`](PROFILE-payment-v1.md) | `org.seallink.payment/endpoints` | `exploratory-draft` | Universal public & private (`visibility="private"`, 32B `privacy_salt`, depth-20 `CertEntryProof`) payment endpoints: Silent Payments (CAIP-2), crypto/BOLT 12, traditional rails (`iban`, `sbp` with `bank_ids[]`, `paypal`, `upi`, `card`, `pix`, `mpesa`, `alipay` via `registry/payment-schemes.json`), anti-spam proof-of-payment, Web of Trust, and consensus-exact 2-step L1 PSBT handshake (`T_prep` -> `T_handshake`). |
| [`PROFILE-e2ee-messaging-v1.md`](PROFILE-e2ee-messaging-v1.md) | E2EE `transport-binding` | `exploratory-draft` | Independent E2EE key authentication without central CAs or manual Safety Numbers for `matrix`, `xmpp`, `signal`, `telegram`, `mls` (RFC 9420 multi-device), `openpgp` (RFC 9580 `sha256-fingerprint`), and `age` (`x25519`), with strict contour isolation and disposable UTXO `seal` revocation. |
| [`PROFILE-social-v1.md`](PROFILE-social-v1.md) | `SLSC` / Nostr | `exploratory-draft` | `SealLink Social` (`SLSC` `534c5343` prefix), sovereign multi-persona & professional profiles (`card/1` + `profile-section` + bilateral `identity-link`), Nostr relay as a SealLink organization (`https://` in `service.endpoint` vs `wss://` in `card.relays[]`, depth-34 `sets.members`), and `NIP-XX` / `NIP-YY`. |
| [`PROFILE-domain-binding-v1.md`](PROFILE-domain-binding-v1.md) | Channel 2 / `OQ-004` | `exploratory-draft` | Bi-directional domain binding between `id/<label>` and `.bit` (`d/<label>`), DNSSEC `_seallink.<domain>` TXT records, and HTTPS `.well-known/seallink/` with RFC 6890 SSRF hardening. |

## Reserved `open` Standard Service Type Skeletons (`registry/service-types.json`)

| Draft Skeleton | `service_type` | Status | Summary |
| --- | --- | :-: | --- |
| [`PROFILE-xmpp-v1.md`](PROFILE-xmpp-v1.md) | `xmpp` | `exploratory-draft` | Sovereign XMPP hosting (`manifest.providers[]`), OMEMO binding, MAM archive reads, and exclusive provider cut-over. |
| [`PROFILE-wallet-v1.md`](PROFILE-wallet-v1.md) | `wallet` | `exploratory-draft` | High-assurance financial spend & PSBT co-signing (`seallink/coins`, concrete `executor`, mandatory UTXO seal, no bearer sessions). |
| [`PROFILE-compute-v1.md`](PROFILE-compute-v1.md) | `compute` | `exploratory-draft` | Metered LLM & GPU compute proxy (`seallink/cost`, `seallink/tokens`, bearer sessions, optional root `window_only` micro-grants). |
| [`PROFILE-rental-v1.md`](PROFILE-rental-v1.md) | `rental` | `exploratory-draft` | Contract-bound physical/digital asset leases (`requires_contract = true`, `arbiter_or_both` seal, `contract-ruling` integration). |
| [`PROFILE-blob-v1.md`](PROFILE-blob-v1.md) | `blob` | `exploratory-draft` | Grant-aware content-addressed blob storage (Blossom `BUD-01/02/04`, `seallink/bytes`, replaceable mirrors). |
| [`PROFILE-names-v1.md`](PROFILE-names-v1.md) | `names` | `exploratory-draft` | Delegated update-only ledger name co-signing (`P2WSH` watchtowers respecting `SL-LDGR-006`) and sponsored fee funding. |
