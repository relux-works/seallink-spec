# PROFILE-e2ee-messaging-v1: Independent E2EE Messenger & Encryption Key Authentication (Zero Safety Numbers)

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — NOT part of the frozen v1.0 Core conformance bar; candidate for a post-v1.0 Standard Profile SLIP (`SPEC-07 §4`).
- **Core Primitives Used:** `SPEC-01` (`x25519` RFC 7748 non-low-order, `ed25519`, `p256`, `bip340`, `sha256-fingerprint` RFC 9580), `SPEC-03` (`seallink-statement/1` `statement_kind = "transport-binding"` in depth-20 `manifest.sets.certs` `CertEntryProof`, optional disposable `seal`).

---

## 1. Security Model & Contour Isolation

Messaging apps parse untrusted media (images, video, voice notes, archives) and therefore face elevated client-side 0-day risk. `PROFILE-e2ee-messaging-v1` enforces **strict contour isolation**:
1. **Messaging keys NEVER enter `sets.devices` or `link.*`:** An E2EE client generates its own local identity/encryption keypair (`X25519`, `Ed25519`, OpenPGP v6, `age`, or MLS signature key) inside the messenger sandbox without access to `name_owner` or `grant` private keys.
2. **Wallet-signed binding (`transport-binding`):** The messenger exports ONLY its public key to the user's SealLink wallet, which signs a `seallink-statement/1 (statement_kind = "transport-binding")` anchored in the user's depth-20 `manifest.sets.certs` (`CertEntryProof`) with an optional disposable UTXO `seal` (`tx_revoke` pre-signed with `P2A` CPFP).
3. **Zero Safety Numbers & Zero Trust in Messenger Servers:** When `id/alice` opens a chat with `id/bob`, Alice's client verifies `id/bob`'s `transport-binding` directly against Namecoin (`m.h -> sets.certs -> CertEntryProof -> statement`), mathematically defeating server-side MITM key injection without out-of-band Safety Number QR scanning or centralized Key Transparency servers!

---

## 2. Supported Transports & Key Bindings (`schemas/manifest.schema.json`)

Every transport below is already wire-valid in SealLink Core `v1.0.0-draft.15` (`TransportKind` & `transport-binding` in `schemas/manifest.schema.json`):

| `transport` | `key_alg` | `endpoint` Convention | Use Case |
| --- | --- | --- | --- |
| `matrix` | `ed25519` / `x25519` | `@alice:matrix.example` (or `matrix://...`) | Matrix Cross-Signing Master Key (MSK) or per-device Curve25519/Ed25519 verification |
| `xmpp` | `x25519` / `ed25519` | `alice@xmpp.example` | XMPP OMEMO identity key authentication |
| `signal` | `x25519` / `ed25519` | Signal ACI / handle | Eliminates manual Signal Safety Number verification |
| `telegram` | `ed25519` / `x25519` | `@alice` / E2EE overlay handle | Overlay E2EE verification on Telegram-compatible dual-mode clients |
| `mls` | `ed25519` / `p256` | `mls://<delivery-service>/id/alice` | **MLS (RFC 9420)** credential leaf `SignaturePublicKey` for multi-device E2EE group & 1:1 messaging over Nostr/relays |
| `openpgp` | `sha256-fingerprint` | `alice@example.org` | **RFC 9580 OpenPGP v6** 32-byte SHA-256 primary key fingerprint authentication |
| `age` | `x25519` | `age1...` / label | Modern file & backup encryption key (`age-encryption.org/v1`) |
| `nostr` | `bip340` | `wss://relay.example` | Nostr messaging / NIP-44 / relay endpoint binding |
| `email` | `sha256-fingerprint` / `ed25519` | `alice@example.org` | S/MIME / OpenPGP email encryption binding |

---

## 3. MLS (RFC 9420) Multi-Device Overlay & Fast Revocation

1. **Multi-device E2EE via MLS (`transport = "mls"`):** Each of `id/alice`'s messaging clients publishes an MLS `BasicCredential` referencing `NamePin(id/alice)` plus a `transport-binding` statement committing its MLS leaf `ed25519`/`p256` public key and an individual disposable UTXO `seal`. Adding a phone or laptop adds a new MLS leaf without sharing private keys between devices; removing a lost phone spends its `statement.seal` -> every MLS group peer detects `SEAL_SPENT` at mempool speed and immediately emits an MLS `Remove` proposal!
2. **Stale/revoked key behavior:** Clients verifying a peer's `transport-binding` MUST enforce `not_before <= now < not_after`, monotonic `seq`, `SL-IDEN-003` name history, and live `statement.seal` (`SEAL_SPENT` -> hard red warning & block outbound encryption!).
3. **Selective disclosure:** Private messaging bindings (e.g., an unlisted personal Matrix or Signal handle) omit public mirrors and are proven on-demand via depth-20 `CertEntryProof` directly inside the initial E2EE handshake!
