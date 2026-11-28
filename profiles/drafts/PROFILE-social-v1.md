# PROFILE-social-v1: SealLink Social (`SLSC`), Sovereign Profiles, Nostr Relays as Organizations, and L1 Anchoring

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — NOT part of the frozen v1.0 Core conformance bar; candidate for a post-v1.0 Standard Profile SLIP + companion Nostr NIPs (`NIP-XX`, `NIP-YY`).
- **Reserved Sibling `OP_RETURN` Prefix:** `SLSC` (`534c5343`, officially reserved in `registry/opreturn-actions.json` & ignored by `SLNK` Core verifiers per `SPEC-02 §5.2`)
- **Core Primitives Used:** `SPEC-03` (`seallink-card/1` avatars & links, depth-20 `sets.certs` `profile-section` & `identity-link`, depth-34 `sets.members` `MemberEntryProof`, top-level `nostr` field), `SPEC-05` (`seallink-credential/1` `log_tracked`, `seallink-release/1`).

---

## 1. Sovereign Social & Professional Profiles

SealLink already provides every cryptographic building block required for full-featured social, professional (LinkedIn-class), and private (e.g., dating / community) profiles without any central platform lock-in:

1. **Public Card (`seallink-card/1`, `manifest.sets.card`):** `display`, `role`, `contact`, `transports[]`, `relays[]` (`wss://`), primary `avatar` + up to 8 contextual `avatars` (`AvatarRef`, sandboxed raster-only), and up to 32 `links[]` (`LocatorUri`).
2. **Modular Profile Sections (`seallink-statement/1`, `statement_kind = "profile-section"` in depth-20 `sets.certs`):**
   - Arbitrary reverse-domain `section_kind` documents (`org.seallink.social/bio`, `org.seallink.career/resume`, `org.seallink.social/portfolio`, `org.seallink.social/dating`).
   - Supports `visibility = "public"` (with `locators[]`) AND `visibility = "private"` (forbidding `locators[]`, hidden inside depth-20 `sets.certs` and selectively revealed via `CertEntryProof`).
3. **Bilateral Identity & Organizational Verification (`identity-link` + depth-34 `sets.members` + `seallink-credential/1`):**
   - **Multi-persona proof (`same-controller`):** An actor can maintain separate `id/alice-dating` and `id/alice-pro` names, keeping them unlinkable publicly while proving common control selectively to one trusted peer via reciprocal `identity-link (relation = "same-controller")` + depth-20 `CertEntryProof`!
   - **Verified employment & membership (`member-of`):** Organization `id/acme` includes `NamePin(id/alice)` with `roles: ["staff-engineer"]` and disposable `seal` in depth-34 `sets.members` (`seallink-member-entry/1`), while `id/alice` publishes a reciprocal `identity-link (relation = "member-of", peer = NamePin(id/acme), roles = ["staff-engineer"])`. Relying parties treat the **intersection of mutually attested `roles[]`** as verified active membership.
   - **Work-history / diploma attestations (`seallink-credential/1`):** Universities and former employers issue `eternal` or `log_tracked` (`0x14`, `role = "cred"`) credentials; the holder references chosen credentials from their `career/resume` `profile-section`.

---

## 2. Nostr Relay as a SealLink Organization (`id/relay-relux`)

A Nostr relay operates as a standard sovereign SealLink actor (`id/relay-relux`) with **strict separation of HTTP management vs. WebSocket relay URIs** (matching `schemas/manifest.schema.json` & `schemas/card.schema.json`):

- **`manifest.service.endpoint` (`HttpsUri`, `https://` ONLY):** Points to the relay's NIP-11 / administrative HTTPS endpoint (e.g., `https://relay.relux.works`) with pinned `tls_spki_sha256` and `receipt_key`.
- **`card.relays[]` (`RelayUri`, `wss://`) and/or `transport-binding (transport = "nostr")`:** Publishes the actual WebSocket relay URL (`wss://relay.relux.works`) and pinned TLS/Nostr keys.
- **Anti-spam membership & instant ban (`sets.members` depth-34):** Paying or verified relay members receive a `seallink-member-entry/1` inside the relay's depth-34 sparse Merkle tree (supporting up to $2^{34}$ members with ~1.5 KiB proofs and zero member-list scraping). Banning a spammer spends their single disposable member `seal` (`SEAL_SPENT`)!
- **Zero lock-in:** Users can belong to 3–5 relays simultaneously and switch relays in minutes while keeping `id/<user>` and all followers intact.

---

## 3. Proposed Nostr Improvement Proposals (`NIP-XX` & `NIP-YY`)

1. **`NIP-XX` — Namecoin `id/` Sovereign Identity & Key Rotation:**
   - Reuses SealLink's existing optional top-level `nostr` field in Namecoin's 520-byte `name-value` (`SPEC-03 §1.1`, direct 64-hex or NIP-05 `names._`) plus `transport-binding (transport = "nostr")` for zero-duplication key discovery and verifiable Nostr key rotation surviving compromise of an old Nostr `nsec`.
   - Clients display verified SealLink handles (`id/alice`) alongside optional `origin_class` badges (`person` / `organization` / `agent`) checked locally against user-configured `trusted_origin_issuer_pins`.
2. **`NIP-YY` — L1 Merkle Anchoring for Nostr Relays & Authors (`SLSC` `OP_RETURN`):**
   - Relays or authors periodically commit Merkle roots of Nostr event IDs into standalone Namecoin `OP_RETURN` transactions using the reserved **`SLSC` (`534c5343`)** prefix (kept strictly separate from `SLNK` transactions so Namecoin's 1-`OP_RETURN` standard relay policy is never violated!).
   - Archived event bundles distributed over Blossom (`loc_type = 0x01`), BitTorrent v2 (`0x02`/`0x04`), or IPFS (`0x03`) are verified by set-union over `event.id` against confirmed `SLSC` Merkle anchors — allowing complete, censorship-resistant reconstruction of social history even if every original Nostr relay vanishes.
