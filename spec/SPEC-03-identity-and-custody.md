# SPEC-03: Identity, Name Value, Manifest, Key Taxonomy, Authentication, and Owner Control

- **Version:** `1.0.0-draft.14`
- **Status:** `draft` (normative rules `decided`; domain-binding verification and FIDO2/SSH device extensions tracked `open` in `OPEN-QUESTIONS.md`)
- **Evidence / Maturity:** `vectors` (`vectors/trace-01-mail-offline-revoke.json`, `vectors/refusal-coverage-matrix.json`)
- **Registries:** `registry/object-types.json`, `registry/key-roles.json`, `registry/service-types.json`, `registry/locator-schemes.json`, `registry/refusal-codes.json`
- **Schemas:** `schemas/name-value.schema.json`, `schemas/manifest.schema.json`, `schemas/card.schema.json`, `schemas/invocation.schema.json`

---

## 1. Name Value Format (520-Byte Protocol Budget)

An actor's ledger name (conventionally `id/<label>`, which MAY be a human-readable handle or an opaque pseudonymous identifier such as `id/u-8f3a91c4e2`) carries a compact Restricted JCS JSON object (`SPEC-01`, `schemas/name-value.schema.json`) of **at most `520` bytes** (`SL-IDEN-001`, `decided`).

### 1.1 Top-Level Members (`SL-IDEN-002`, `decided`)

A SealLink reader MUST match top-level keys `link`, `m`, and `nostr` strictly — refusing duplicate keys and all 71 Unicode simple case-fold aliases of `link`, `m`, and `nostr` (explicitly enumerated in `schemas/name-value.schema.json`) with `WIRE_DUPLICATE` (other malformed name values refuse with `NAME_VALUE_INVALID`) — and MUST ignore unknown owner-defined top-level members.

| Top-Level Key | Optional | Structure & Purpose | Closes Grants on Edit? |
| --- | :-: | --- | :-: |
| `link` | Yes | Authority & origin root object: closed subset of `{cred, grant, notary, release, origin}`. Each of `cred`, `grant`, `notary`, `release` is either a single `xonly_64hex` key or an on-chain threshold pin `{"p":"<sha256_of_JCS(ThresholdPolicy)>"}`. | **Per-role only (`SL-IDEN-003`)** |
| `m` | Yes | Single manifest head: `{"h":"<64hex>","s":<PositiveUint53>}` pinning `seallink-manifest/1` (JCS sorted keys `h`, `s`). Zero URLs or `loc` allowed. | **Never** |
| `nostr` | Yes | Optional transport messaging key: `"<64hex>"` OR NIP-05 object `{"names":{"_":"<64hex>"},"relays":{...}}`. Only `"_"` is read. Zero authority. | **Never** |

### 1.2 Multi-Role Keys, On-Chain Role Policies, and Uniform `origin` Pin (`SL-IDEN-003`, `decided`)

One `id/` name MAY publish distinct, strictly isolated role keys or threshold role-policy pins simultaneously inside `link`:

```json
{"link":{"cred":"<64hex>","grant":{"p":"<64hex>"},"notary":"<64hex>","origin":"<64hex>"},"m":{"h":"<64hex>","s":1}}
```

- **On-chain role threshold integrity:** Every role policy (`1-of-1` direct key OR `m-of-n` `ThresholdPolicy` pinned as `{"p":"<sha256>"}`) is anchored **directly inside `link.<role>` on the ledger** — never governed solely by an off-chain manifest update.
  - When `link.<role>` is a 64-hex string `k`, the resolved role policy is `{"m":1,"pks":[k]}`.
  - When `link.<role>` is `{"p":h}`, the presenter supplies the full `ThresholdPolicy` (inside the signed object's `issuer.role_policy` and/or `manifest.role_policies.<role>`), and the verifier MUST confirm `SHA256(canonical_JCS(role_policy)) == h` (`WIRE_SIGNATURE` on mismatch). *(For ward-represented `seallink-grant/1` objects using `guardian_approvals[]`, `issuer.role_policy` is omitted on the ward's `issuer` pin and signing authority is resolved from each approving guardian's `link.grant` policy per `SPEC-04`.)*
  - Rotating any key or threshold inside a role policy changes `link.<role>` via an owner-authored (`SIGHASH_ALL`) ledger update, triggering the exact per-role closure rule below.
- **Byte budget:** With all four threshold role pins (`cred`, `grant`, `notary`, `release`) + `origin` + `m` (at `uint53` max), canonical Restricted JCS occupies at most **510 bytes** — strictly within the 520-byte protocol limit. Actors that publish all four authority roles alongside `origin` and `m` SHOULD publish Nostr transport keys via `seallink-card/1` or `seallink-statement/1` (`transport-binding`) rather than inside the 520-byte name value.
- **Per-role history isolation:** Rotating or removing `link.notary`, `link.cred`, or `link.release` MUST NOT close live grants bound to `link.grant`. Rotating or removing `link.grant` closes active grants (`NAME_ROLE_CHANGED`), while leaving eternal credentials, release records, and notary acts intact unless closed by `0x0b` (`h_c`) or log fraud (`NOTARY_LOG_COMPROMISED`).
- **Privacy-preserving `origin` pin:** Every origin-certified actor (child, adult, organization, or materialized agent) writes the identical field name `link.origin = "<origin_id_64hex>"`. Public chain observers cannot distinguish subject class or capacity from the name value alone (`SL-ARCH-012`).
- **Role key & policy-pin disjointness:** Within one name, every public key x-coordinate appearing in the name's on-chain `owner_policy`, `link.grant`, `link.cred`, `link.notary`, `link.release` (whether direct `xonly_64hex` or expanded via `{"p":...}` `role_policies` or `issuer.role_policy`), `nostr` (direct 64-hex string OR NIP-05 `names._`), and any disclosed `bip340` entry inside salted `sets.auth` or `sets.devices` MUST be pairwise disjoint, AND no two distinct roles in `{link.grant, link.cred, link.notary, link.release}` MAY share the same on-chain policy-hash pin `{"p": ...}`, NOR may any `{"p": H}` equal `SHA256(JCS({"m":1,"pks":[k]}))` for any known owner/role/nostr/disclosed `bip340` key `k` (`NAME_VALUE_INVALID` on any collision). **Selective-disclosure boundary:** wallets MUST enforce full pairwise disjointness across ALL generated keys (`owner_policy`, `link.*`, `nostr`, every `sets.auth` entry, and every `sets.devices` entry), while verifiers deterministically enforce disjointness across every key observable on-chain (`owner_policy`, `link.*`, `nostr`) and every key disclosed in the current verification context (`manifest.role_policies`, `issuer.role_policy`, disclosed `AuthEntry`/`DeviceEntry`).
- **Name history walk (`SL-IDEN-004`, `decided`):** To verify an issuer's `grant` role policy for an active grant, the verifier resolves the name (refusing `NAME_NOT_FOUND` if absent on the active chain) and walks the name's confirmed update chain back to `issuer.registration`: `owner_policy` and `link.grant` MUST remain unchanged across every step from the grant's `recent_block` through the tip (detecting even `K1 -> K2 -> K1` rotations for grants issued before the rotation; renewals, `m` updates, `nostr` updates, and unrelated role changes close nothing). Every historical update MUST parse cleanly under the exact Namecoin prefix grammar and 520-byte JCS rules (unparseable historical updates fail closed with `CHAIN_SCRIPT_UNSUPPORTED` / `NAME_VALUE_INVALID`, never silently skipped) and MUST pass writer verification against the pinned `owner_policy` (`SL-LDGR-007`). An owner-signed (`SIGHASH_ALL`) change or removal of `link.grant` (in mempool or block — ALWAYS inspecting `mempool_updates[]` regardless of whether `recent_block_height` was supplied) writes a durable cause- and epoch-scoped `NAME_ROLE_CHANGED` closure pinned by `retired_before_height` (the height of the update removing that policy, or `tip_height + 1` for a mempool update) — so grants with `recent_block < retired_before_height` remain closed permanently, while for confirmed `A -> B -> A` returns both stateful and freshly started verifiers yield identical verdicts for new grants whose `recent_block >= retired_before_height` (if a mempool update is later evicted without confirming, a witness that already observed that mempool rotation keeps grants with `recent_block <= tip_height` closed permanently until a fresh `recent_block >= tip_height + 1` is minted). An unparseable or unfetchable mempool update (`unparseable: true`) fails closed with retryable **`NAME_HISTORY_UNAVAILABLE`** without writing a permanent role closure (separating missing observation from proven rotation).

---

## 2. Key Taxonomy and Cold Custody Rules

All 25 key roles, curves, derivation accounts, and permitted signing domains are authoritatively fixed in `registry/key-roles.json` (`SL-IDEN-005`, `decided`):

1. **Cold isolation:** `name_owner` (separate cold seed `m/84'/7'/0'`) and `emergency_fee_reserve` (cold seed `m/84'/7'/3'`, strictly isolated from all hot signers so a hot compromise cannot drain emergency update/CPFP fees) MUST NEVER reside on an agent host or ordinary hot wallet.
2. **Authority separation:** `grant`, `cred`, `notary`, and `release` keys sign ONLY their registered BIP-340 domains (`registry/object-types.json`) and NEVER sign ledger transactions or spend seals. `log_seal` (secp256k1 ECDSA) controls `0x14` log-checkpoint continuation UTXOs and MUST remain strictly isolated from ordinary `funding` UTXOs.
3. **Auth vs Device vs Messaging:**
   - `auth` keys (enrolled in salted Merkle `sets.auth` with `alg ∈ {bip340, p256, ed25519}`) authenticate to foreign services ONLY (`seallink-auth-challenge/1`, `seallink-auth-upgrade/1`) and confer zero grant, contract assent, or effect authority.
   - `device` keys (enrolled in salted Merkle `sets.devices` with `alg ∈ {bip340, p256, ed25519}`) control the owner's own executors and agent key holders ONLY (`seallink-owner-command/1`, `seallink-statement/1`) and MUST NEVER sign foreign login challenges, assents, or grants (`DEVICE_UNAUTHORIZED`).
   - `messaging_or_request` keys carry messages and invoke grants only where explicitly named as recipient; they NEVER issue grants or child grants.
4. **Dynamic seal/row/stop pool (`>= 10'`):** Per-seal keys (`grant_seal`, `child_seal`, `row_coin`, `stop_coin`, `contract_seal`, `guardian_seal`) live in independent hardened accounts `>= 10'` with operator-secret xpubs.
5. **Disposable fast-revocation seals:** Per-entry `sets.auth` seals, per-entry `sets.devices` seals, member-entry seals, and optional statement seals MUST be generated from a CSPRNG (NEVER BIP-39), pre-signed with a `P2A` CPFP anchor output (`SL-LDGR-013`), and destroyed immediately after recording `tx_revoke`.

*(Concrete custody deployments — hardware enclaves, HSMs, Keyholder daemons — are informative and documented in `guides/GUIDE-01-custody-and-signers.md`.)*

---

## 3. Unified Manifest (`seallink-manifest/1`) and Off-Chain Sets

The single `m` pin in the name value authenticates one canonical JCS `seallink-manifest/1` object (`<= 65536` bytes, `schemas/manifest.schema.json`) (`SL-IDEN-006`, `decided`).

### 3.1 Manifest Members

1. **`sets`** *(optional)*: Hash + monotonic `seq` pins (`SetPin`) for up to five off-chain JCS sets:
   - `auth` (`seallink-auth-set-head/1` + salted leaves `seallink-auth-entry/1`, `AuthEntryProof`): Cryptographically **size-hiding** salted Merkle tree committing `1..256` foreign-service login keys (`salt, label, alg ∈ {bip340, p256, ed25519}, key, seal`) without revealing sibling keys or enrolled count to any relying party. Wallets **MUST** generate a fresh, independent 32-byte CSPRNG `salt` for every entry (and SHOULD fund distinct per-entry revocation seals from unlinkable UTXOs rather than a single batched transaction when hiding total device count from on-chain observers). Each real leaf digest is domain-separated using BIP-340 double-tag hashing `H_tag("seallink-auth-entry/1", canonical_JCS(entry))` (wrapped as `H_tag("seallink-merkle-leaf/1", leaf_digest)`). Before computing `merkle_root`, the builder **MUST pad the sorted real leaves to a fixed width of `256` leaves** using independent CSPRNG dummy leaves `H_tag("seallink-set-dummy/1", csprng_32B)`, so every `SetEntryMerkleProof.steps` array has **exact fixed length `8`** (`minItems: 8, maxItems: 8`) regardless of whether `1` or `256` keys are enrolled.
   - `devices` (`seallink-device-set-head/1` + salted leaves `seallink-device-entry/1`, `DeviceEntryProof`): Symmetric cryptographically **size-hiding** salted Merkle tree committing `1..256` owner control-plane devices (`salt, label, alg ∈ {bip340, p256, ed25519}, key, presence, ceiling ∈ {0,1,2}, seal`), using the identical 32-byte CSPRNG `salt` requirement, BIP-340 double-tag leaf digest `H_tag("seallink-device-entry/1", canonical_JCS(entry))` (making cross-set replay between `sets.auth` and `sets.devices` cryptographically impossible), and fixed **256-leaf dummy padding** (`SetEntryMerkleProof.steps` ALWAYS exact length `8`) anchored by `seallink-device-set-head/1.merkle_root`.
   - `card` (`seallink-card/1`): Public entity metadata card (`person | agent | organization | service`, display name, transports, relays, role, contact), plus optional content-addressed **`avatar`** (`AvatarRef`: `{sha256, mime ∈ {"image/png", "image/jpeg", "image/webp", "image/avif"}, bytes <= 10485760, locators: LocatorUri[1..8]}` — vector/active formats like `image/svg+xml` are strictly forbidden), optional contextual **`avatars`** map (`1..8` named `AvatarRef` entries), and optional **`links[]`** (`<= 32` `{label, url: LocatorUri}`). **Client avatar hardening:** rendering clients MUST verify `SHA256(bytes) == avatar.sha256` and exact byte length BEFORE decoding, MUST decode strictly in a memory-bounded sandboxed raster decoder rejecting mismatched MIME magic bytes and excessive pixel dimensions (decompression-bomb guard), and MUST strip embedded metadata (EXIF/XMP/ICC). Self-declared `kind` carries zero authority; if an `origin/1` is verified, `card.kind` MUST match `origin_class` and `card.name` MUST match the verified name.
   - `members` (`seallink-members-list/1`, `<= 1048576` bytes): Up to 1,024 managed/member actor pins `(name, registration, owner_policy, seal)` with optional **`roles[]`** (`1..16` unique `RoleTag` strings matching `^[a-z0-9][a-z0-9._-]{0,63}$`, `uniqueItems: true`). In Core v1.0, `roles[]` is strictly informational metadata (it confers zero protocol authorization without an explicit grant or contract). Organizations managing wards SHOULD NOT publicly list private ward pins in a public `members-list/1` (`SL-ARCH-012`). Pinning `registration` prevents an expired member name string from being hijacked upon re-registration. Verifiers MUST pass the fenced journal when evaluating each member `seal` (durable `SEAL_SPENT` closure) and MUST bound per-issuer journaled entries to prevent unbounded state growth.
   - `certs` (`seallink-certset-head/1`): Head committing to an actor's active self-signed (or, for ward `identity-link`, guardian-quorum-approved) `seallink-statement/1` records. `verify_certset_head` MUST verify that `head.network == owner_manifest.network`, `head.issuer_name == owner_manifest.owner`, `content_addr(head) == owner_manifest.sets.certs.sha256`, `head.seq == owner_manifest.sets.certs.seq`, every statement's `(network, issuer.name)` matches the head, and `set_sha256 == SHA256(canonical_JCS(sorted_content_addrs))` with `count == len(sorted_content_addrs)`. Every `seallink-statement/1` payload carries closed members `(type, network, genesis, issuer: NamePin, statement_kind, subject, seq, not_before, not_after)` where `not_before` and `not_after` are **Unix timestamps in seconds** (`not_before <= now < not_after`, refusing `INVOKE_TIME_INVALID` otherwise) and `seq` is a positive monotonic statement sequence number per `(issuer, statement_kind)` (consumers tracking latest statements reject rollbacks). Every live `seallink-statement/1` verification evaluates the issuer's active name history at tip (enforcing `0x0b` compromise breaks, universal `origin_bundle` / `0x0c` / `0x13` / `SUBJECT_ENDED` checks, and durable `SEAL_SPENT` closure at `>= operator_min_depth` when `seal` is present):
     - **`statement_kind` normative signer, ceiling, presence & foreign-verifier matrix:**

       | `statement_kind` | Permitted Signer(s) | Device Ceiling / Presence | Foreign Verifier? | Subject / Special Rules |
       | --- | --- | --- | :-: | --- |
       | `"config-section"` | `link.grant` OR `sets.devices` (`bip340`/`p256`/`ed25519`) | `ceiling >= 2`, `presence = true` | **NO** (`DEVICE_UNAUTHORIZED` on device signer) | `{host_id, section}` + `body_sha256`. |
       | `"transport-binding"` | `link.grant` OR `sets.devices` (`bip340`/`p256`/`ed25519`) | `ceiling >= 1` | Yes (`link.grant`); **NO** for device signer (`DEVICE_UNAUTHORIZED`) | `{transport, endpoint, key_alg ∈ {"sha256-spki","bip340","ed25519","x25519","p256"}, key_hex}` (valid curve/non-low-order key) + optional `seal`. |
       | `"identity-link"` | Autonomous: `link.grant` OR `sets.devices` (`bip340`/`p256`/`ed25519`); Ward: **`guardian_approvals[]` ONLY** | `ceiling >= 1` (autonomous device) | Yes (`link.grant` / `guardian_approvals`); **NO** for device signer | `{relation ∈ {"same-controller","member-of","contact"}, peer: NamePin, roles?: RoleTag[1..16]}` (`roles[]` ONLY when `relation == "member-of"`) + optional `seal`. **Unilateral assertion:** a single `identity-link` proves only `issuer`'s own claim; relying parties requiring mutual relationship confirmation MUST verify a reciprocal `identity-link` or `members-list/1` entry from `peer`. Wards MUST NOT sign autonomously (`WARD_AUTONOMOUS_FORBIDDEN`). |
       | `"profile-section"` | `link.grant` OR `sets.devices` (`bip340`/`p256`/`ed25519`) | `ceiling >= 1` | Yes (`link.grant`); **NO** for device signer | `{section_kind: "<reverse-domain>/<slug>", visibility?: "public"\|"private"}` + `body_sha256` + optional `locators: LocatorUri[1..8]` (**FORBIDDEN** when `visibility == "private"`, `WIRE_MEMBER`) + optional `seal`. |
       | `"root-rotate"` | **`link.grant` (`bip340` `SignatureSet`) ONLY** — NEVER device key | Forbidden (`DEVICE_UNAUTHORIZED`) | Own host only | `{host_id, new_role_policy: ThresholdPolicy}`. |
       | `"root-cancel"` | **`link.grant` (`bip340` `SignatureSet`) ONLY** — NEVER device key | Forbidden (`DEVICE_UNAUTHORIZED`) | Own host only | `{host_id, override_id: Hex64}`. |
       | `"migration-accept"` | **`link.grant` (`bip340` `SignatureSet`) ONLY** — NEVER device key | Forbidden (`DEVICE_UNAUTHORIZED`) | Yes (`service-migration` module) | `{migration_id, holder, source_executor, inventory_sha256}`. |
       | `"migration-fence"` | **Outgoing source `service.receipt_key` (`bip340` `SignatureSet`) ONLY** — NEVER device key | Forbidden (`DEVICE_UNAUTHORIZED`) | Yes (`service-migration` module) | `{migration_id, holder, dest_executor, source_journal_pos, source_journal_commitment, inventory_sha256, predecessor_grant_seals}` (`SPEC-07 §2`). |

2. **`service`** *(optional)*: Self-declaration when this actor operates a service (`service_type` — including `mail`, `agent-session`, `xmpp`, `blob`, `wallet`, `names`, `compute`, `rental`, `sso`, or reverse-domain — `actions` (`minItems: 0`, allowing `actions: []` cleanly for authentication-only services such as `"sso"`, which operate via `seallink-auth-challenge/1` rather than delegated grant actions), `receipt_key`, `endpoint: HttpsUri`, optional `tls_spki_sha256` pin). Discovery only; never substitutes for a pinned grant executor key.
3. **`providers`** *(optional, `SL-IDEN-007`, `decided`)*: Labeled bindings declaring which external service actors host this actor's resources. Each entry binds `(service_type, label)` to a full **`provider: NamePin`** (`{name, registration, owner_policy}`) plus optional `transport_key`:
   ```json
   "providers": [
     {
       "label": "work",
       "provider": {
         "name": "id/mail-host-a",
         "owner_policy": {"kind": "key", "pk": "02..."},
         "registration": {"txid": "...", "vout": 0}
       },
       "service_type": "mail"
     }
   ]
   ```
   - Each `(service_type, label)` pair MUST be unique within `providers`.
   - **Provider continuity:** Because `provider` pins `(name, registration, owner_policy)`, an attacker who re-registers an expired provider name string cannot hijack dynamic `executor_ref` delegations (`SERVICE_PROVIDER_UNBOUND` if holder's manifest lacks a matching `(service_type, label, provider)` entry; `NAME_OWNER_MISMATCH` if the pinned provider name's confirmed ledger output does not match `provider.owner_policy`). Switching providers requires an explicit owner-authored manifest update.
4. **`role_policies`** *(optional availability hint ONLY)*: Carries full `ThresholdPolicy` preimages for on-chain `link.<role>.p` pins (`grant`, `cred`, `notary`, `release`). A `role_policies` entry has ZERO authority unless `SHA256(canonical_JCS(policy))` equals the confirmed on-chain `link.<role>.p` hash (`SL-IDEN-003`).
5. **`notary` / `release`** *(optional operational declarations, `schemas/manifest.schema.json`)*: Operational discovery blocks strictly matching `schemas/manifest.schema.json`:
   - `notary`: REQUIRED `log: LogBindingSpec`, optional `policy_sha256`, `supported_claim_ids[]`, `supported_schemes[]`, and `mirror_endpoints[]`;
   - `release`: REQUIRED `allowed_product_prefixes[]`, optional `log: LogBindingSpec`, `supported_schemes[]`, and `mirror_endpoints[]`;
   - `LogBindingSpec`: REQUIRED `{log_id: Hex64, genesis_seal: Seal, heartbeat_max_blocks: PositiveUint53}` and optional `predecessor_logs: Hex64[]` (`maxItems: 16`, `uniqueItems: true`, ordered historical predecessor `log_id` digests).
   Availability & discovery hints only; authentic log heads, `O(1)` handovers, and revocations are verified strictly from on-chain `0x14` checkpoints and signatures (`SPEC-05 §6`).
   - **v1.0 `link` 520-byte freeze note:** The 4 authority roles (`cred`, `grant`, `notary`, `release`) + `origin` + `m` occupy up to `510 / 520` bytes under Namecoin's UI limit, so `link`'s key set is fixed for v1.0.

### 3.2 Monotonicity, Removal, and Reorg Rules (`SL-IDEN-008`, `decided`)

Verifiers journal `(seq, manifest_sha256, anchoring_txid)` for the manifest and `(seq, sha256)` plus removal marks for each set, keyed by `(name, registration)`:
- On confirmed updates while `anchoring_txid` remains on the active chain: `manifest.seq` MUST strictly increase (`new > old`), and every retained set's `seq` MUST NOT decrease (`new >= old`; equal `seq` with different `sha256` refuses `MANIFEST_ROLLBACK`).
- Omitting a previously present set in a valid newer manifest records a durable removal mark at its highest seen `seq`; reintroducing the set requires a strictly higher `seq`.
- If `anchoring_txid` is orphaned by a chain reorg, the verifier adopts the highest confirmed manifest on the new active chain while retaining all recorded removal marks and seal closures.
- **Revocation independence:** Validated seal spends MUST be processed and journaled even if `seallink-manifest/1` is unavailable.

---

## 4. Non-Exclusive Four-Channel Distribution Cascade

Verifiers resolve `seallink-manifest/1` and pinned off-chain sets using a strictly non-exclusive cascade (`SL-IDEN-009`, `decided` cascade / `open` domain-binding verification profile in `OPEN-QUESTIONS.md`):

| Priority | Channel | Availability & Policy |
| :-: | --- | --- |
| **0** | **Inline** | Supplied directly by the presenter/peer alongside the request. Always works, including for opaque names with zero domain and zero Nostr key. |
| **1** | **Local Cache / Configured Stores** | Verifier's local hash cache or operator-configured Blossom (`GET /<sha256>`) / HTTP mirrors. |
| **2** | **HTTPS `.well-known`** | Optional; used ONLY if the name explicitly declares a verified domain -> `https://<domain>/.well-known/seallink/<object>/<sha256>`, under strict SSRF and same-scheme redirect (`<= 3` hops, re-validating resolved IP on every hop) policy. |
| **3** | **Nostr Relay (`kind 30079`)** | Optional; used ONLY if the name publishes a `nostr` pubkey -> query verifier-configured `wss://` relays for addressable event `kind 30079` authored by that key with tag `["d", "seallink-manifest"]` (or `seallink-card`, etc.). |

Bytes from ANY channel are accepted **if and only if** `SHA256(bytes)` equals the confirmed ledger/manifest pin and full JCS/schema validation passes (`MANIFEST_MISMATCH` otherwise). Missing bytes refuse `MANIFEST_UNAVAILABLE` without silent unconfigured outbound fetches.

**Safe-by-design locator URI allowlist & SSRF protection (`registry/locator-schemes.json`):** Every off-chain `LocatorUri` (used in `card.avatar`, `card.avatars`, `card.links`, `statement(profile-section).locators`) MUST satisfy printable-ASCII RFC 3986 syntax (no whitespace, control characters, `\`, or embedded `user:pass@` authority credentials) AND Step 8b runtime enforcement against `registry/locator-schemes.json` (schemes in `forbidden_schemes` refuse `WIRE_MEMBER`; schemes in `allowed_schemes` — `https`, `blossom` (TLS-only port 443 / `<host>/<64hex>`), `ipfs`, `magnet` (`xt=urn:(btmh|btih):...` only, rejecting `tr=`/`ws=` SSRF tracker URLs), `nostr`, `sftp`, `seallink` — must satisfy strict per-scheme syntax; unknown non-forbidden schemes added by a future `Registry Update` are wire-valid but MUST NEVER be auto-fetched). `MirrorEndpoint.url` and `service.endpoint` MUST be `HttpsUri`, and `RelayUri` MUST use `wss://`. Any client or verifier performing automatic off-chain fetches MUST resolve DNS, unmap IPv4-mapped IPv6 (`::ffff:0:0/96`), block ALL non-global RFC 6890 addresses (loopback, RFC 1918, CGNAT, link-local, ULA, NAT64 `64:ff9b::/96`, 6to4, Teredo, multicast, broadcast, benchmark, unspecified), pin the validated socket IP against DNS rebinding, allow at most `3` strictly same-scheme `https://` redirects (re-validating DNS and IP on every hop), bound response bytes, and verify SHA-256 content addressing before parsing.

> **Ecosystem note — External Manifest Archivers & Monitors:** Independent public archivers or transparency monitors MAY index confirmed on-chain `m.h` pins and mirror public `seallink-manifest/1`, `seallink-card/1`, and public `profile-section` objects as additional availability caches (Channel 1) without holding any protocol privilege or trust (`SL-ARCH-007`), since every byte is verified against the ledger's `m.h` hash.

---

## 5. Provisional Onboarding and Foreign-Service Authentication

A foreign replaceable service authenticates actors using `seallink-auth-challenge/1` and `seallink-auth-upgrade/1` (`SL-IDEN-010`, `decided`):

1. **Challenge lifecycle, channel derivation, and durable nonce consumption:** Service generates a 32-byte CSPRNG `nonce`, records `(nonce, service_id, issued_at, expires_at)` (plus optional OIDC/SSO `audience` and optional RFC 9266 TLS `channel_binding` 32-byte SHA-256 digest) durably with `issued_at < expires_at <= issued_at + 120`. To prevent relay phishing, clients **MUST derive `service_id` directly from the authenticated transport channel** (the verified HTTPS origin host or verified provider `NamePin` identity, NEVER blindly echoing a caller-supplied string) and SHOULD populate `channel_binding` when authenticating over TLS (`tls-exporter`, [RFC9266]). Client constructs `seallink-auth-challenge/1` binding `(network, genesis, service_id, optional audience, optional channel_binding, optional name, nonce, issued_at, expires_at, auth_alg ∈ {bip340, p256, ed25519}, auth_pubkey)` and signs with that `auth` key (`DeviceSignatureSet`, never `device`, `grant`, or `name_owner`). Service verifies `SPEC-01 §7`, checks fenced journal continuity (`journal.check_continuity()`), confirms `network`/`genesis` (`CHAIN_MISMATCH`), confirms exact equality of `(service_id, nonce, issued_at, expires_at)`, expected `audience`, and expected `channel_binding` against its own stored challenge record (`AUTH_CHALLENGE_INVALID` on any mismatch or unknown/reused nonce), verifies `issued_at <= now < expires_at` (`AUTH_CHALLENGE_EXPIRED`), verifies the signature under `(auth_alg, auth_pubkey)`, and **durably appends a `nonce` entry (`scope: "auth"`) to the fenced journal** before creating any session (preventing replay across service restarts).
2. **Named mode (selective-disclosure salted Merkle `sets.auth` & origin gate):** Service resolves `name`, walks owner history, runs the universal origin/rebind/end gate (enforcing active `effective_binding` and `SUBJECT_ENDED` when origin-bound), verifies `manifest/1`, and verifies the presented `AuthEntryProof` (`{head: seallink-auth-set-head/1, entry: seallink-auth-entry/1, proof: SetEntryMerkleProof}`): `head` MUST match confirmed `manifest.sets.auth` (`sha256`, `seq`, `network`, `owner`), `entry` MUST match `(network, owner, auth_alg, auth_pubkey)`, `proof` MUST have exact length `8` steps and verify inclusion of domain-separated `H_tag("seallink-auth-entry/1", JCS(entry))` in `head.merkle_root` (`AUTH_KEY_UNPINNED` on mismatch), any disclosed `bip340` key MUST be disjoint from `owner_policy`/`link.*`/`nostr` (`NAME_VALUE_INVALID`), and `entry.seal` MUST be unspent at `>= operator_min_depth` evaluated with the fenced journal (`SEAL_SPENT` with durable closure if spent, `SEAL_UNAVAILABLE` if unconfirmed or inconclusive). Service returns the verified `(name, registration)` tuple; existing service accounts MUST retain their original `(name, registration, owner_policy)` binding so a re-registered name string MUST NOT take over an old account.
3. **Provisional key-only onboarding:** A service MAY admit a challenge without `name` into a strictly rate- and storage-capped local cell (zero effect, PII-release, or federation rights).
4. **Sponsored client-owned registration & atomic upgrade:** A sponsor MAY fund UTXOs controlled exclusively by the client so the client broadcasts `OP_NAME_NEW` and (`>= 12` blocks later) `OP_NAME_FIRSTUPDATE` (sponsor never owns the name). Once `OP_NAME_FIRSTUPDATE` confirms at `>= operator_min_depth` (`CHAIN_DEPTH_INSUFFICIENT` otherwise), client signs `seallink-auth-upgrade/1` (binding `network`, `genesis`, `service_id`, optional `audience`, optional `channel_binding`, `account_id`, `name`, `auth_alg`, `auth_pubkey`, `firstupdate_txid`, `nonce`, `issued_at`, `expires_at`) under the same provisional `(auth_alg, auth_pubkey)` and presents its `AuthEntryProof` against confirmed `manifest.sets.auth` (seal depth `>= operator_min_depth`, `TTL <= 120` refusing `AUTH_CHALLENGE_EXPIRED`, `account_id` matching the provisional cell, durable `nonce` consumption in the fenced journal) to atomically bind the confirmed registration to the provisional cell.
5. **Authentication is NOT authorization:** A successful login session confers zero authority to spend funds, disclose data to third parties, or bypass grant checks.

---

## 6. Owner Control Plane (Own Executors and Trust-Root Pin)

For commanding an actor's **own** hosts, executors, and managed agent key holders (`SL-IDEN-011`, `decided`):

1. **Device levels, mandatory on-chain manifest binding, and closed command set:** `seallink-owner-command/1` carries a closed command enum (`agent-dispatch`, `session-terminate`, `policy-apply`, `keyholder-halt`, `approve-pii-disclosure`) with typed `arguments` schemas (`schemas/invocation.schema.json`). Every `seallink-owner-command/1` MUST check fenced journal continuity (`journal.check_continuity()`), verify `target_executor` matches the local executor's own identity (`DEVICE_UNAUTHORIZED` on mismatch), reject replayed `nonce` values (`INVOKE_REPLAY`) and durably persist a `nonce` entry (`scope: "owner-command"`) in the fenced journal (except read-only sub-validations inside `verify_federation_disclosure` where the parent flow commits replay protection). Every `seallink-owner-command/1` AND every device-signed `seallink-statement/1` MUST resolve `owner` (`issuer`) on the active chain (passing the universal origin/rebind/end gate), verify `owner_manifest` (`seallink-manifest/1`) against the confirmed on-chain `m.h` manifest pin (`MANIFEST_MISMATCH` if missing or mismatched), verify the presented `DeviceEntryProof` (`{head: seallink-device-set-head/1, entry: seallink-device-entry/1, proof: SetEntryMerkleProof}` with exact length `8` steps) against `manifest.sets.devices` (`sha256`, `seq`, domain-separated leaf digest `H_tag("seallink-device-entry/1", JCS(entry))`, and `SL-IDEN-003` BIP-340 disjointness), and match an active entry whose `seal` is unspent at `>= operator_min_depth` evaluated with the fenced journal (durable `SEAL_SPENT` closure) and whose `(alg, key)` matches the command's signing key (`DEVICE_UNAUTHORIZED` otherwise), with `entry.ceiling >= command.level` and, for **EVERY** command with `command.level == 2`, `entry.presence == true`:
   - **L0:** Cognitive work / read-only dispatch (`agent-dispatch` with `level = 0`); zero effects.
   - **L1:** Policy-bounded operational control (`agent-dispatch`, `session-terminate` within local executor caps).
   - **L2:** High-assurance presence-verified device (`presence = true`, `ceiling = 2`): may issue `policy-apply` (paired with an L2-signed `seallink-statement/1`), `keyholder-halt`, `approve-pii-disclosure` (Contour A targeted PII release, `SPEC-07 §3`, strictly `route_mode = "direct"`), and fast device revocation (`tx_revoke`).
   - **Level inheritance:** Any agent run launched by an `seallink-owner-command/1` inherits its `level` ceiling; the run's key holder MUST NOT sign effects above that level.
2. **Foreign boundary:** Device keys MUST NEVER be accepted by foreign services (`DEVICE_UNAUTHORIZED`).
3. **Host Trust-Root Pin and Delayed Admin Override (`SL-IDEN-012`, `decided`):** An isolated host/runtime pins `(network, genesis, root_name, registration, owner_policy, pinned_grant_policy)` in admin-owned read-only storage outside agent write reach. Routine rotation uses a `root-rotate` statement signed by the old `pinned_grant_policy`. Unassisted administrator overwrite enters a mandatory pending delay `D` (default `1008` blocks) with out-of-band owner alerts on every load; the old `pinned_grant_policy` (via a signed `seallink-statement/1` with `kind = "root-cancel"`) OR the name's cold `owner_policy` (via an owner-authored `SIGHASH_ALL` `OP_NAME_UPDATE`) MAY cancel before `effective_height`.

---

## 7. Security Considerations

- **No silent downgrade of manifest:** Once a verifier observes a confirmed manifest for `(name, registration)`, missing or malformed manifests refuse without falling back to stale caches.
- **Bidi spoofing in Entity Cards:** Clients rendering `card.display` or `card.role` SHOULD isolate untrusted text and flag Unicode bidirectional controls (`U+202A..202E`, `U+2066..2069`).
- **Key compromise blast radius:** Separating `auth`, `grant`, `cred`, `notary`, `device`, and `name_owner` ensures a leaked mobile login key cannot forge contracts, grants, origin certificates, or hijack the ledger name.

---

## 8. References

- **Normative:** [RFC8785], [BIP-340], [RFC8032], [SEC1], [JSON-SCHEMA-2020-12].
- **Informative:** [NC28].
