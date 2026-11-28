# PROFILE-sso-v1: Decentralized Single Sign-On, OIDC Brokering, and Zero-Install WebAuthn Passkey Portals

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — NOT part of the frozen v1.0 Core conformance bar; candidate for a post-v1.0 Standard Profile SLIP (`SPEC-07 §4`).
- **Service Type:** `sso` (`registry/service-types.json`, `manifest.service.actions = []` per `SPEC-03 §3.1`)
- **Core Primitives Used:** `SPEC-01` (`fido2-es256`, `fido2-eddsa`, `p256`, `ed25519`, `bip340`, `ssh-ed25519`, `presence_attestation` `UP`/`UV`), `SPEC-03 §5` (`seallink-auth-challenge/1`, `seallink-auth-upgrade/1`, depth-16 `AuthEntryProof`, depth-34 `MemberEntryProof`, RFC 9266 `channel_binding`).

---

## 1. Architecture & Core Invariant

Authentication is **NOT** authorization (`SPEC-03 §5` item 5). A SealLink SSO session proves identity `(name, registration)` (or pairwise ephemeral key) and optional group membership (`sets.members` `roles[]`) to a relying party (RP) — it confers **zero** authority to issue grants, sign contracts, or execute privileged effects.

`PROFILE-sso-v1` defines three interoperable deployment profiles over the identical Core `seallink-auth-challenge/1` wire object:

| Mode | Target Ecosystem | Relying Party Requirements | Client Requirements |
| --- | --- | --- | --- |
| **Mode A1 — OIDC Broker** | Existing Web apps (Grafana, GitLab, Forgejo, Outline, Nextcloud) | Standard OpenID Connect / OAuth 2.0 client (zero Namecoin knowledge) | Any SealLink wallet, browser extension, or Passkey |
| **Mode A2 — Stateless Self-Sovereign Passkey Portal** | Web apps verifying SealLink directly (zero trusted IdP!) | Verifies `seallink-auth-challenge/1` + depth-16 `AuthEntryProof` against Namecoin | Stock mobile/desktop browser with WebAuthn Passkey (`fido2-es256`/`fido2-eddsa`) — zero browser extensions! |
| **Mode B — Native `.bit` / Direct Challenge** | Native SealLink apps, `.bit` sites, CLI tools | Issues & verifies `seallink-auth-challenge/1` directly (pinned `https-tls-spki`) | Native wallet, Secure Enclave / StrongBox, YubiKey, or QR + 4-digit SAS / NIP-46 remote signer |

---

## 2. Mode A1 — Team & Organizational OIDC Broker (`service_type = "sso"`)

An organization (e.g., `id/acme`) or self-hosted team runs one OIDC Broker (`id/auth-acme`, declaring `manifest.service.service_type = "sso"`, `actions = []`, `endpoint = "https://auth.acme.example"`) backed by one read-only Namecoin Core `nc28.0` node (`rpcwhitelist`) + `>= 1` comparison peer:

1. **OIDC Authorization Request:** Downstream app (`client_id`) redirects user to `https://auth.acme.example/authorize`.
2. **SealLink Challenge Issuance:** Broker generates 32B CSPRNG `nonce`, stores `(nonce, service_id="auth.acme.example", audience=client_id, channel_binding=tls_exporter_sha256, issued_at, expires_at <= issued_at + 120)` durably, and presents the challenge to the user's signer.
3. **Challenge Verification (`SPEC-03 §5`):** User returns signed `seallink-auth-challenge/1` + depth-16 `AuthEntryProof` (+ optional depth-34 `MemberEntryProof` from `id/acme` `manifest.sets.members`). Broker verifies:
   - Full `SPEC-03 §5` pipeline (origin/rebind/end gate, depth-16 `AuthEntryProof`, unspent `entry.seal`, `presence_attestation`, durable `nonce` consumption in `FencedJournal`);
   - Optional `MemberEntryProof` (`seallink-member-entry/1` + unspent member `seal` + optional reciprocal `identity-link`) to populate OIDC `groups` claims.
4. **Canonical OIDC Claims (`id_token`):**
   - `sub`: **MUST** bind immutable registration continuity (`seallink:<network>:<name>:<registration.txid>:<registration.vout>` or `seallink:origin:<origin_id>` when origin-certified) — NEVER a bare mutable name string alone, preventing account takeover if a name expires and is re-registered!
   - `preferred_username`: `<name>` (e.g., `id/alice`)
   - `seallink_origin_class`: `"person" | "agent" | "organization" | "unverified"`
   - `groups`: verified intersection of `seallink-member-entry/1.roles[]` (and reciprocal `identity-link.roles[]` when required)
   - `amr`: `["hwk", "up"]` / `["hwk", "uv"]` when verified via FIDO2 `presence_attestation`.

---

## 3. Mode A2 — Zero-Install Stateless Self-Sovereign Passkey Portal

WebAuthn binds browser Passkeys strictly to the origin's `rpId` (e.g., `auth.alice.me`). Mode A2 solves cross-site Passkey login with **zero browser extensions and zero backend trust**:

1. **User setup (one-time):** User hosts a ~40-line static HTML/JS portal (`https://auth.alice.me/index.html`, zero database, zero backend secrets, SRI-pinned hash) and enrolls their browser Passkey (`alg: "fido2-es256"` or `"fido2-eddsa"`, `rp_id: "auth.alice.me"`, `presence_attestation: "uv"`) inside `id/alice`'s depth-16 `manifest.sets.auth`, optionally listing the portal in `manifest.providers[service_type="sso"]`.
2. **Login to any Relying Party (`shop.example`):**
   - `shop.example` generates a fresh challenge (`service_id = "shop.example"`, `nonce`, `issued_at`, `expires_at <= issued_at + 120`) and opens `https://auth.alice.me/#challenge=<base64url(payload)>`.
   - The static portal displays **`Sign in to: shop.example`** prominently to the user, computes `digest = H_tag("seallink-auth-challenge/1", canonical_JCS(payload))`, and calls `navigator.credentials.get({ publicKey: { challenge: digest, rpId: "auth.alice.me", userVerification: "required" } })`.
   - The browser returns raw `(authenticatorData, clientDataJSON, signature)` to `shop.example` together with `id/alice`'s depth-16 `AuthEntryProof`.
3. **Trustless verification by `shop.example`:**
   - `shop.example` verifies `seallink-auth-challenge/1` directly against Namecoin (`expected_rp_id = "auth.alice.me"` matched against `entry.rp_id` and `id/alice`'s declared SSO portal), verifies `authenticatorData` `rpIdHash`, `UP`/`UV` flags, `clientDataJSON.challenge == base64url_nopad(digest)`, and unspent `entry.seal`!
   - **Honest trust boundary:** `shop.example` does NOT trust `auth.alice.me` for authentication soundness (cryptography + Namecoin prove possession of the Passkey); the *user* trusts their chosen static portal's JS solely to display the honest target `service_id` before prompting Touch ID / Face ID / YubiKey.

---

## 4. Mode B — Native Direct Auth, Pairwise Anonymity & Provisional Upgrade

- **Native `.bit` & Direct Auth:** Relying parties authenticate over pinned `https-tls-spki` (`SPEC-07 §1`), binding RFC 9266 `tls-exporter` into `channel_binding` to defeat MitM/relay phishing cryptographically. Mobile hardware signers connect via QR code + 4-digit SAS confirmation over direct HTTPS callback or Nostr NIP-46 remote signing.
- **Pairwise Anonymous Login (`name` omitted):** Clients derive a deterministic domain-scoped keypair `K(seed, service_id)` and omit `name` in `seallink-auth-challenge/1` (`SPEC-03 §5` item 3). Colluding sites cannot correlate accounts.
- **Sponsored Provisional Upgrade (`seallink-auth-upgrade/1`):** A user starting in a provisional key-only cell later registers `id/alice`, enrolls that same provisional key in `manifest.sets.auth`, and submits `seallink-auth-upgrade/1` + depth-16 `AuthEntryProof` to atomically bind the confirmed registration to the existing account without losing session history (`SPEC-03 §5` item 4).
