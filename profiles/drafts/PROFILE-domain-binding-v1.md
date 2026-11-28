# PROFILE-domain-binding-v1: Channel 2 HTTPS `.well-known`, `.bit` (`d/`), and DNSSEC Domain Binding

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — NOT part of the frozen v1.0 Core conformance bar; candidate profile to close **`OQ-004`** (`OPEN-QUESTIONS.md`, `SPEC-03 §4` `SL-IDEN-009`).
- **Core Primitives Used:** `SPEC-03 §4` (4-channel non-exclusive cascade, `registry/locator-schemes.json` SSRF protection), `SPEC-03 §3.1` (`transport-binding` `https-tls-spki`, `seallink-card/1`), `SPEC-02` (Namecoin `d/` namespace).

---

## 1. Purpose & Non-Exclusive Availability Invariant

Channel 2 (`https://<domain>/.well-known/seallink/<object>/<sha256>`) is strictly an **optional availability hint** (`SL-ARCH-007`, `SL-IDEN-009`):
- Authenticity ALWAYS comes from exact `SHA256(bytes) == m.h` (or confirmed manifest pin) — NEVER from HTTPS CA trust alone.
- Channel 0 (inline presentation) and Channel 1 (local cache / Blossom / mirrors) ALWAYS work unconditionally, even for opaque names (`id/u-8f3a91c4e2`) with zero domain.

`PROFILE-domain-binding-v1` specifies how an actor `id/<label>` explicitly and bi-directionally binds an Internet DNS domain (`example.org`) or Namecoin `.bit` domain (`d/<label>`) for Channel 2 discovery and human-facing display without enabling spoofed domain hijacking.

---

## 2. Three Bi-Directional Domain Binding Mechanisms

A verifier MUST treat a domain binding as **verified** ONLY when BOTH directions match (`id/` -> domain AND domain -> `id/`):

### 2.1 Namecoin Native `.bit` Binding (`id/<label>` <-> `d/<label>`)
1. **Forward claim (`id/` -> `d/`):** `id/<label>` publishes a signed `seallink-statement/1 (statement_kind = "transport-binding", transport = "https-tls-spki", endpoint = "https://<label>.bit")` inside `sets.certs` (or `manifest.service.endpoint = "https://<label>.bit"` + `tls_spki_sha256`).
2. **Reverse claim (`d/` -> `id/`):** Namecoin `d/<label>`'s confirmed `OP_NAME_UPDATE` JSON carries `"seallink": {"name": "id/<label>", "registration": "<txid>:<vout>"}` (or identical `owner_policy` confirmed on chain).
3. **Zero-CA TLS:** Clients connect to `<label>.bit` authenticating TLS strictly against the verified `tls_spki_sha256` / `https-tls-spki` pin (never relying on WebPKI CAs!).

### 2.2 Classic DNS / DNSSEC Binding (`_seallink.<domain>`)
1. **Forward claim:** `id/<label>` publishes `seallink-statement/1 (statement_kind = "transport-binding", transport = "https-tls-spki", endpoint = "https://<domain>")` or `card.links[]` entry.
2. **Reverse claim (DNSSEC-validated TXT record):**
   ```text
   _seallink.example.org. IN TXT "v=seallink1; name=id/alice; reg=<txid>:<vout>; net=main"
   ```
   Verifiers validating DNSSEC MUST require `AD` (Authenticated Data) from a local validating resolver and confirm exact `(name, registration)` equality.

### 2.3 HTTPS `.well-known` Mutual Discovery & Blob Layout
When DNSSEC is unavailable, HTTPS `.well-known/seallink/identity.json` provides WebPKI-level reverse correlation alongside content-addressed Channel 2 blob serving:
- **`/.well-known/seallink/identity.json`:**
  ```json
  {
    "genesis": "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770",
    "name": "id/alice",
    "network": "main",
    "registration": { "txid": "<64hex>", "vout": 0 }
  }
  ```
- **Content-addressed immutable object endpoints (`Cache-Control: public, max-age=31536000, immutable`, `Access-Control-Allow-Origin: *`):**
  - `/.well-known/seallink/manifest/<sha256>`
  - `/.well-known/seallink/blobs/<sha256>` (cards, set heads, proofs, public profile sections, tickets)
- **Mandatory SSRF & redirect hardening (`SPEC-03 §4`, `registry/locator-schemes.json`):** Clients fetching Channel 2 URLs MUST unmap IPv4-mapped IPv6 (`::ffff:0:0/96`), block ALL non-global RFC 6890 / NAT64 / 6to4 / Teredo addresses, pin resolved socket IPs against DNS rebinding, allow `<= 3` strictly same-scheme `https://` redirects (re-validating DNS + IP on every hop), enforce `max_bytes` (`<= 1 MiB`), and verify `SHA256(bytes) == expected_sha256` before JSON parsing!
