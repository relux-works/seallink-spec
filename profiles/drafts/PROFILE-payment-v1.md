# PROFILE-payment-v1: Universal Payment Endpoints, Anti-Spam Proof-of-Payment, and L1 PSBT Handshakes

- **Version:** `0.1.0-draft` (targeting SealLink Core `1.0.0-draft.15`)
- **Status:** `exploratory-draft (non-normative)` — NOT part of the frozen v1.0 Core conformance bar; candidate for a post-v1.0 Standard Profile SLIP (`SPEC-07 §4`).
- **Profile Section Kind:** `org.seallink.payment/endpoints` (carried via `seallink-statement/1`, `statement_kind = "profile-section"` in depth-20 `manifest.sets.certs`)
- **Companion Registry:** `registry/payment-schemes.json` *(updated via lightweight `Registry Update`, `SPEC-00 §5.1`)*
- **Core Primitives Used:** `SPEC-01` (JCS, `uint64_str`), `SPEC-03` (`sets.certs` depth-20 `CertEntryProof`, `profile-section` with `visibility = "public" | "private"`, `identity-link`, `sets.members` depth-34), `SPEC-05` (`seallink-contract/1`, `0x07`).

---

## 1. Design Goals & Public vs. Private Visibility

Actors need to publish verifiable payment coordinates (Bitcoin/Namecoin Silent Payments, crypto addresses, Lightning BOLT 12, and traditional fiat rails like IBAN, SBP, PayPal, UPI, Pix, M-Pesa, card) bound directly to their sovereign `id/` identity — without leaking private banking details onto public relays or ledgers.

`PROFILE-payment-v1` anchors payment payloads strictly via **`seallink-statement/1 (statement_kind = "profile-section", subject.section_kind = "org.seallink.payment/endpoints")`** inside the actor's **depth-20 salted sparse Merkle tree `manifest.sets.certs`** (`CertEntryProof`, `SPEC-03 §3.1`):

1. **Public Payment Endpoints (`visibility = "public"`):**
   - Intended for open donations, NGO/grant transparency, merchant checkouts, and public invoicing.
   - `locators[]` MAY be populated on the `profile-section` statement (Blossom, IPFS, HTTPS `.well-known`, Nostr).
   - **Honest UI warning:** Clients MUST warn users before publishing `visibility = "public"` payment details that external archivers may cache the published document indefinitely.
2. **Private Payment Endpoints (`visibility = "private"`):**
   - Intended for personal bank accounts, card numbers, SBP phone numbers, and private crypto addresses shared solely with trusted friends, family, or business counterparties.
   - Per `SPEC-03 §3.1`, `locators[]` is **STRICTLY FORBIDDEN** (`WIRE_MEMBER`) when `visibility = "private"`.
   - The payload **MUST** include a fresh 32-byte CSPRNG **`privacy_salt`** (`64` lowercase hex) so an observer holding `body_sha256` cannot offline-brute-force short phone numbers, IBANs, or card numbers.
   - Because `sets.certs` is a depth-20 salted sparse Merkle tree (`seallink-cert-set-head/1` + `seallink-cert-entry/1`), the very existence of a private payment section remains invisible to outsiders until the holder selectively delivers `(payload_json, statement, CertEntryProof)` over E2EE transport (e.g., auto-responding to verified contacts or requiring manual 1-tap approval).
   - **Honest UI disclaimer:** Clients MUST inform holders that once a recipient receives the signed `CertEntryProof` + payload, the recipient possesses cryptographic proof linking that payload to `id/<owner>` if they choose to leak it.

---

## 2. Canonical `seallink-payment-endpoints/1` Payload

All monetary thresholds use canonical `uint64_str` (`SPEC-01 §2`, never IEEE 754 floats). Blockchain networks are identified strictly by **CAIP-2 `chain_id`** (without a redundant `symbol` field). Optional `seal` enables mempool-speed revocation (`SEAL_SPENT`) of compromised payment details without touching cold `name_owner`:

```json
{
  "crypto_addresses": [
    { "address": "nc1q...", "antispam_min_atomic": "1000000", "chain_id": "bip122:000000000062b72c5e2ceb45fbc8587e" },
    { "address": "0x...", "antispam_min_atomic": "1000000000000000", "chain_id": "eip155:1" },
    { "address": "...", "antispam_min_atomic": "5000000", "chain_id": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" },
    { "antispam_min_atomic": "1000", "offer": "lno1...", "protocol": "bolt12" }
  ],
  "network": "main",
  "owner": "id/alice",
  "privacy_salt": "<64hex_csprng_required_for_private>",
  "seal": {
    "script_policy": { "kind": "key", "pk": "02<64hex_disposable_csprng_pk>" },
    "txid": "<64hex>",
    "vout": 0
  },
  "seq": 3,
  "silent_payments": {
    "chains": [
      { "antispam_min_atomic": "1000000", "chain_id": "bip122:000000000062b72c5e2ceb45fbc8587e", "script_kind": "p2wpkh" },
      { "antispam_min_atomic": "1000", "chain_id": "bip122:000000000019d6689c085ae165831e93", "script_kind": "p2tr" }
    ],
    "scan_pk": "02<64hex_compressed>",
    "spend_pk": "03<64hex_compressed>"
  },
  "traditional": [
    { "currencies": ["EUR"], "details": { "account_holder": "Alice Example", "bic": "COBADEFFXXX", "iban": "DE89..." }, "scheme": "iban" },
    { "currencies": ["RUB"], "details": { "bank_ids": ["bank100000000004", "bank100000000111"], "phone": "+79990000000", "recipient_hint": "Alice E." }, "scheme": "sbp" },
    { "currencies": ["USD", "EUR"], "details": { "handle": "alice@example.org" }, "scheme": "paypal" },
    { "currencies": ["INR"], "details": { "payee_name": "Alice Example", "vpa": "alice@okhdfcbank" }, "scheme": "upi" },
    { "currencies": ["USD"], "details": { "cardholder_name": "ALICE EXAMPLE", "pan": "4242..." }, "scheme": "card" }
  ],
  "type": "seallink-payment-endpoints/1"
}
```

- **UTXO privacy choice:** Holders MAY expose Silent Payments (`scan_pk`, `spend_pk`) for unlinkable stealth outputs AND/OR hashed explicit addresses (`nc1q...` P2WPKH, hiding raw pubkeys until spend) in `crypto_addresses`.
- **Extensible fiat rails (`registry/payment-schemes.json`):** New national payment schemes (SEPA Instant, FedNow, FPS, Pix, M-Pesa, Alipay) are registered via lightweight `Registry Update` without changing frozen Core v1.0 schemas.

---

## 3. Anti-Spam Proof-of-Payment & Contact Policy

To defeat unsolicited spam from unknown senders across Email, XMPP, Matrix, or Nostr without centralized gatekeepers:
1. A recipient declares `antispam_min_atomic` (in chain base units: satoshis / wei / lamports / msats) on their chosen `silent_payments` or `crypto_addresses` entry.
2. An unknown sender (`id/bob`) derives a fresh Silent Payment output `P = spend_pk + H(a_bob * scan_pk) * G`, pays `>= antispam_min_atomic`, and attaches `{chain_id, txid, vout, msg_hash_sig}` (signed by the input private key `a_bob` over the incoming message digest) inside the E2EE message envelope.
3. The recipient's client verifies: (a) output ownership via `b_scan`, (b) amount `>= antispam_min_atomic`, (c) input signature over `msg_hash`, and (d) single-use consumption of `(chain_id, txid, vout)` in its local anti-replay table — promoting the message to Priority Inbox while keeping the payment unlinkable on chain!
4. **Zero-fee exemptions:** Mutual contacts (`identity-link`), verified colleagues sharing a common organization (`MemberEntryProof` in `sets.members`), and parallel reciprocal messages bypass the anti-spam fee automatically; unpaid messages from strangers route quietly to a "Requests" folder.

---

## 4. Public Web of Trust & Consensus-Exact 2-Step L1 PSBT Handshake

### 4.1 Scalable Web of Trust (`identity-link`)
Everyday professional and social trust graphs (co-workers, endorsements, verified contacts) are built off-chain from reciprocal `seallink-statement/1 (statement_kind = "identity-link")` anchored through `m.h` — scaling to hundreds of relationships per single `OP_NAME_UPDATE` with zero L1 bloat.

### 4.2 Ceremonial 2-Step L1 PSBT Handshake (`T_prep` -> `T_handshake`)
For high-assurance public milestones (co-founder attestations, formal corporate partnerships, public Web-of-Trust vouching, or bilateral `seallink-contract/1` anchoring `0x07`), two parties `id/alice` (`owner_policy(A)`) and `id/bob` (`owner_policy(B)`) execute a **two-step BIP-174 PSBT ceremony** fully compliant with Namecoin Core `nc28.0` consensus (`CheckNameTransaction`: max 1 name input and max 1 name output per tx) and `SPEC-05 §2.3` (confirmed `contract_seal` required before signing `seallink-assent/1`):

1. **Step 1 — Preparation Transaction(s) (`T_prep`):**
   - Creates the confirmed `contract_seal` (e.g., `both_of_2(A, B)` or `arbiter_or_both`, required before signing `seallink-assent/1` per `SPEC-05 §2.3`) AND either:
     - one shared non-name `assent_output` locked to `both_of_2(owner_policy(A), owner_policy(B))`, **OR**
     - two ordinary **non-name** native SegWit UTXOs locked to `compile(owner_policy(A))` and `compile(owner_policy(B))` respectively (NEVER name UTXOs, since Namecoin forbids two name inputs in one tx!).
   - Once `T_prep` confirms, both parties sign their `seallink-assent/1` envelopes referencing the confirmed `contract_seal`.
2. **Step 2 — Atomic Co-Signed Anchor (`T_handshake`):**
   - **Inputs:** Spends the shared `assent_output` (co-signed by `A` and `B` with `SIGHASH_ALL 0x01`), OR spends Party A's non-name `owner_policy(A)` UTXO (`Input 0`) AND Party B's non-name `owner_policy(B)` UTXO (`Input 1`) with `SIGHASH_ALL (0x01)`.
   - **Output 0 (`0 sat`):** `OP_RETURN SLNK 0x07 <contract_id>` (`42B`/`74B`) for a bilateral contract, OR `OP_RETURN SLSC <statement_sha256>` (`PROFILE-social-v1`) for a public partnership / vouching ceremony.
   - **Output 1+:** Fee change outputs.
   - **Atomicity & permanence:** Neither party can unilaterally broadcast `T_handshake` without the other's `SIGHASH_ALL` signature; once mined, the block height provides an eternal, censorship-resistant proof surviving future name rotations or expiry.
