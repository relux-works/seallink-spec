# SPEC-01: Wire Format, Cryptography, Thresholds, and Constraint Algebra

- **Version:** `1.0.0-draft.3`
- **Status:** `draft` (normative rules `decided`; see `OPEN-QUESTIONS.md` for deferred algorithm extensions)
- **Evidence / Maturity:** `vectors` (`vectors/wire-jcs-and-hashes.json`, `vectors/constraints-and-schemas.json`, `vectors/refusal-coverage-matrix.json`)
- **Registries:** `registry/object-types.json`, `registry/refusal-codes.json`, `registry/constraints.json`
- **Schemas:** `schemas/common.schema.json`

---

## 1. Canonical Serialization (Restricted RFC 8785 JCS)

Every canonical SealLink document — signed or unsigned, including manifests, cards, lists, contracts, origins, credentials, grants, invocations, receipts, and journal entries — **MUST** use exactly one wire encoding: **Restricted RFC 8785 JSON Canonicalization Scheme (JCS)** ([RFC8785], [RFC8259]).

| Rule ID | State | Requirement | Refusal |
| --- | --- | --- | --- |
| `SL-WIRE-001` | `decided` | Document octets MUST NOT exceed `max_bytes` registered for its `type` in `registry/object-types.json`. JSON object/array nesting depth MUST NOT exceed `16` (the root object is depth `1`). | `WIRE_SIZE` |
| `SL-WIRE-002` | `decided` | Input MUST be valid UTF-8 with no BOM and no leading or trailing bytes, parsing as exactly one RFC 8259 JSON object. | `WIRE_JSON` |
| `SL-WIRE-003` | `decided` | No JSON object at any nesting level MAY contain duplicate member names (compared after escape decoding). | `WIRE_DUPLICATE` |
| `SL-WIRE-004` | `decided` | Allowed JSON values are objects, arrays, strings, number-form integers (`SL-WIRE-007`), and booleans (`true`, `false`). The literal `null` is FORBIDDEN everywhere: optional fields MUST be omitted rather than set to `null`. | `WIRE_VALUE` |
| `SL-WIRE-005` | `decided` | Every string (including member names) MUST consist solely of Unicode scalar values `>= U+0020`, excluding `U+007F` (DEL), the C1 control block `U+0080..U+009F`, and unpaired surrogates. **Multiline prose exception:** `U+000A` (LF, encoded as `\n` under RFC 8785) is permitted ONLY in designated multiline prose fields (`terms_text`, contract clause `text`, `termination.reason`, `card.role`); CR (`U+000D`), TAB (`U+0009`), and all other `< U+0020` code points remain FORBIDDEN everywhere. No Unicode normalization is performed; string equality is exact code-point equality. | `WIRE_STRING` |
| `SL-WIRE-006` | `decided` | The verifier MUST re-serialize the parsed value under RFC 8785 (no insignificant whitespace; object keys sorted by UTF-16 code units; literal UTF-8 strings with ONLY `\"`, `\\`, and `\n` where permitted; canonical decimal integers) and MUST refuse unless the re-serialized octets are byte-for-byte identical to the input. A reader MUST NEVER repair non-canonical input. | `WIRE_NOT_CANONICAL` |

> **Implementation note:** Standard library JSON serializers that HTML-escape `<`, `>`, `&`, or `U+2028`, or parse numbers via IEEE 754 `float64`, violate `SL-WIRE-006` and `SL-WIRE-007`. Verifiers MUST implement a dedicated strict JCS parser and serializer.

---

## 2. Exact Integer Forms

No numeric value in SealLink may pass through IEEE 754 binary64 floating-point arithmetic.

| Rule ID | State | Requirement | Refusal |
| --- | --- | --- | --- |
| `SL-WIRE-007` | `decided` | **Number form (`uint53`):** JSON integer token `0` or `[1-9][0-9]*` with no sign, fraction, exponent, or leading zero, value `<= 9007199254740991` (`2^53 - 1`), and within the schema's field bound. Used for heights, `vout`, sequence numbers, thresholds, and Unix seconds. | `WIRE_NUMBER` (malformed token or > `2^53 - 1`), `WIRE_INTEGER` (out of schema bound) |
| `SL-WIRE-008` | `decided` | **String form (`uint64_str`):** JSON string matching `^(0|[1-9][0-9]{0,19})$` with unsigned integer value `<= 18446744073709551615` (`2^64 - 1`). Used for monetary amounts, costs, token counts, byte sizes, quota ceilings, and range bounds. | `WIRE_INTEGER` |
| `SL-WIRE-009` | `decided` | Schema form is strictly enforced: a `uint53` where `uint64_str` is required (or vice versa) MUST refuse without coercion (`WIRE_MEMBER`). All arithmetic (sums, products, quota debits) MUST use exact integer or exact rational arithmetic without wrap; arithmetic overflow refuses before any reservation or effect (`WIRE_INTEGER` during parse/attenuation; `QUOTA_EXCEEDED` during debit reservation). | `WIRE_MEMBER`, `WIRE_INTEGER`, `QUOTA_EXCEEDED` |

---

## 3. Object Types, Three Hashes, and Domain Separation

Every registered SealLink object type in `registry/object-types.json` carries its exact string identifier in `type` (top-level for unsigned pinned objects, or `payload.type` for signed envelopes).

| Rule ID | State | Requirement | Refusal |
| --- | --- | --- | --- |
| `SL-WIRE-010` | `decided` | **Closed schemas.** Every object type has a closed member set (`additionalProperties: false`) defined in `schemas/` (plus action profile schemas for `Invocation.arguments`). Unknown, missing, or unregistered `type` values MUST refuse immediately. | `WIRE_TYPE` (unknown type), `WIRE_MEMBER` (schema error) |
| `SL-WIRE-011` | `decided` | **Three distinct hashes.** For any object with canonical `payload_bytes` (the JCS bytes of `payload` for signed objects, or the full document for unsigned objects) and `signed_bytes` (full JCS bytes of the complete signed envelope, either `{"payload":...,"signatures":...}` or `{"guardian_approvals":...,"payload":...}`):<br>1. **Object Identifier (`id`):** `SHA256(payload_bytes)` — excludes signatures and guardian approvals; immune to signature randomness.<br>2. **Typed Signing Digest (`digest`):** BIP-340 tagged hash `H_tag(payload.type, payload_bytes)` where `H_tag(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)` and `tag` is the exact ASCII bytes of `payload.type` (e.g. `"seallink-grant/1"`).<br>3. **Content Address (`content_addr`):** `SHA256(signed_bytes)` — covers the entire signed envelope; used for retrieval pins and signed-form anchoring (`0x04`, `0x09`, `0x0d`, `0x0f`, `0x11`, `0x12`). | — |

---

## 4. Keys, Signatures, and Unified `SignatureSet`

SealLink defines one off-chain multi-signature and threshold envelope used uniformly across single-key actors, multi-key organizations, joint recipient groups, guardian quorums, and notary colleges.

### 4.1 Key Encodings (`SL-WIRE-012`, `decided`)

SealLink v1.0 specifies three exact off-chain signature algorithms plus one on-chain ledger key encoding:

| Algorithm / Role | Public Key Hex Encoding | Signature Hex Encoding | Normative Spec |
| --- | --- | --- | --- |
| `bip340` (default for all protocol objects) | 64 lowercase hex (`xonly_64hex`): valid secp256k1 x-coordinate (even Y). | 128 lowercase hex (64B BIP-340 Schnorr over `digest`). | [BIP-340] |
| `p256` (device keys ONLY) | 66 lowercase hex (`02`/`03` + 32B X): valid compressed SEC 1 point on NIST P-256. | 128 lowercase hex (64B raw `r \|\| s`, strict low-S `s <= n/2`, over pre-hashed `e = big_endian_uint256(digest)` without double-hashing). | [SEC1] |
| `ed25519` (device keys ONLY) | 64 lowercase hex: valid compressed Ed25519 point. | 128 lowercase hex (64B RFC 8032 PureEdDSA signature with message `M = digest`). | [RFC8032] |
| Ledger `ScriptPolicy` keys (`SPEC-02`) | 66 lowercase hex (`compressed_66hex`, `02`/`03` + 32B X): valid secp256k1 point. | DER ECDSA + `0x01` (`SIGHASH_ALL`) inside SegWit v0 witness. | [BIP-141], [BIP-143] |

Invalid curve points, non-lowercase hex, wrong byte lengths, or high-S `p256` signatures MUST refuse with `WIRE_KEY` (key defect) or `WIRE_SIGNATURE` (signature defect).

### 4.2 Signed Envelope, `SignatureSet`, `guardian_approvals`, and Authoritative Policy Binding (`SL-WIRE-013`, `decided`)

Every signed SealLink object has one of two exact top-level shapes:

1. **Ordinary signed envelope** (all signed objects without `payload.guardian_context`):
```json
{"payload":{...},"signatures":{"policy":{"m":1,"pks":["..."]},"sigs":[{"pk":"...","sig":"..."}]}}
```
2. **Ward guardian-quorum envelope** (permitted ONLY on `seallink-grant/1` and `seallink-assent/1` when `payload.guardian_context` is present):
```json
{"guardian_approvals":[{"guardian_name":"id/guardian-a","revision":1,"signatures":{"policy":{"m":1,"pks":["..."]},"sigs":[{"pk":"...","sig":"..."}]},"slot":1}],"payload":{...}}
```

Verification rules over `digest = H_tag(payload.type, canonical_JCS(payload))`:

1. **Structural validity (`SignatureSet`):** `policy.m` MUST satisfy `1 <= m <= len(policy.pks) <= 32`. `policy.pks` MUST be strictly sorted in ascending lexicographical hex order with no duplicates. Each entry in `sigs` carries strictly `{"pk","sig"}`.
2. **Algorithm restriction:** `policy.alg` defaults to `"bip340"` when omitted. Non-`bip340` algorithms (`p256`, `ed25519`) are permitted **ONLY** on `seallink-owner-command/1` and `seallink-statement/1` when signed by a registered `device` key (`SPEC-03 §6`). All other signed objects (including every `guardian_approvals[i].signatures`) MUST use `"bip340"`.
3. **Cryptographic verification (`SignatureSet`):** Each entry in `sigs` MUST name a `pk` present in `policy.pks`, MUST appear at most once per `pk`, and MUST verify strictly against `digest` under `policy.alg`. Verified distinct entries in `sigs` MUST number `>= policy.m`.
4. **Universal authoritative policy binding (ALL object types without exception):** Because `signatures.policy` lies outside `payload`, `signatures.policy` is NEVER trusted on its own. Every verifier MUST independently derive the **expected signing policy** from authoritative state (e.g., on-chain `link.<role>` for `grant`/`cred`/`notary`, `contract.parties[i].signing_policy`, `grant.recipient`, `grant.delegate.key`, `service.receipt_key`, `manifest.auth_key`, `seallink-device-list/1`, or each active slot guardian's resolved `link.grant` policy for `guardian_approvals[i].signatures`) and MUST require exact equality between `signatures.policy` and the derived expected policy. Any mismatch refuses with `WIRE_SIGNATURE`.
5. **Guardian quorum approvals (`guardian_approvals[]`, `SPEC-04`):** When `payload.guardian_context` is present (permitted ONLY on `seallink-grant/1` and `seallink-assent/1`), the payload cryptographically binds `(origin_id, ward_name, revision, event_class)` and the envelope MUST use `guardian_approvals[]` (and MUST NOT carry top-level `signatures`). Entries in `guardian_approvals[]` (`1..32` items) MUST be ordered by strictly ascending `slot` (`1..32`, no duplicate slots; `WIRE_SIGNATURE` otherwise), and every entry's `revision` MUST equal `payload.guardian_context.revision` (`GUARDIAN_QUORUM_UNMET` otherwise). For each entry, the verifier resolves slot `slot` at the active roster revision: if the slot is not `active` or its active guardian's name does not equal `entry.guardian_name`, refuse `GUARDIAN_INACTIVE`; otherwise derive that guardian's current `link.grant` policy at tip and verify `entry.signatures` under rules 1–4 with exact policy equality (`WIRE_SIGNATURE` on policy or signature mismatch). Because each slot carries its own independent `SignatureSet`, multi-key guardians cannot pool keys across slots or double-count. All approving slots MUST resolve to distinct `(name, registration)` guardians (`GUARDIAN_INACTIVE` on conflict), and the count of distinct satisfied slots MUST satisfy `required(derived_event_class)` against `revision_size` (`GUARDIAN_QUORUM_UNMET` on shortfall).

---

## 5. Salted Selective Disclosure Commitments

Contracts (`SPEC-05`), origin certificates (`SPEC-04`), and privacy-sensitive credentials (`SPEC-05`) use salted per-clause / per-claim commitments so a holder can reveal one item without disclosing siblings or permitting offline dictionary guesses (`SL-WIRE-014`, `decided`).

- **Normative commitment formula:**
  ```text
  commit(salt_32B, obj) = H_tag("seallink-clause/1", salt_32B || canonical_JCS(obj))
                        = SHA256(SHA256("seallink-clause/1") || SHA256("seallink-clause/1") || salt_32B || canonical_JCS(obj))
  ```
  where `salt_32B` is an **independent 32-byte CSPRNG salt** (encoded on wire as 64 lowercase hex when transmitted). Issuers MUST generate a fresh, independent 32-byte CSPRNG salt for every committed clause, claim, `majority_commitment`, and `initial_guardian_commitment` — salts MUST NEVER be reused across items.
- **Reference byte vector (`vectors/wire-jcs-and-hashes.json`):**
  For `salt_32B = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` and `obj = {"text":"Room inspection"}` (JCS bytes `7b2274657874223a22526f6f6d20696e7370656374696f6e227d`):
  `commit(salt_32B, obj) = b030a8a82ef79e9d6829f08c2e0bfc74db8b6c259a3b052988027ecc50ffd368` *(verified in `vectors/wire-jcs-and-hashes.json`)*.
- **Disclosure proof:** Presenter supplies `(salt_hex, canonical_JCS(obj))` alongside the containing object. The verifier recomputes `commit(salt_32B, obj)` and requires exact byte equality with the committed digest.
- **Operational boundary:** Losing `salt_32B` permanently forfeits selective disclosure of that item. Salts provide hiding against offline guessing, not encryption of stored plaintext.

---

## 6. Structured Capability and Constraint Algebra

To guarantee decidable, mechanical attenuation (`child <= parent`) across all verifiers while remaining readable for human typed-display on signers, SealLink defines a closed 7-predicate lattice over action arguments (`SL-WIRE-015`, `decided`).

### 6.1 Capability Shape

Each entry in `capabilities[]` (max `64` entries) has:
- `action`: exact lowercase slash-separated leaf (`^[a-z0-9._-]+(/[a-z0-9._-]+)+$`). Exact string equality only; prefixes grant nothing.
- `target`: structured resource identifier (e.g., `mailbox:id/alice:work`). Exact match unless narrowed by profile target rules.
- `where` *(optional, max `32` keys)*: map of `arg_name -> ConstraintPredicate`. Keys combine by implicit logical `AND`.
- `quotas` *(optional, max `32` entries)*: array of additive stateful counters (`kind, resource, unit, max, window`), strictly separated from stateless `where` predicates.
- `extensions` *(reserved)*: MUST NOT be present in v1.0; any presence MUST refuse with `WIRE_CONSTRAINT`.

### 6.2 The Seven Predicates and Conservative Pairwise Attenuation (`SL-WIRE-016`, `decided`)

For an invocation argument value `v` (a missing constrained argument ALWAYS fails with `INVOKE_CONSTRAINT_FAILED`). Array operands of `in` and `not_in` MUST be non-empty, strictly sorted in ascending UTF-16 code-unit order, with no duplicates (`WIRE_CONSTRAINT` otherwise). For `range([min, max])`, `int(min) <= int(max)` MUST hold (`WIRE_CONSTRAINT` otherwise).

| Op | Operand Form | Invocation Match (`arg v`) | Conservative Attenuation (`child <= parent`) |
| --- | --- | --- | --- |
| `eq` | `string \| bool` | `v == op` | `child` is `eq(op)` |
| `in` | sorted unique nonempty array `<= 256` | `v in op` | `child` is `in(S')` with `S' ⊆ op`, OR `eq(x)` with `x in op` |
| `not_in` | sorted unique nonempty array `<= 256` | `v not in op` | `child` is `not_in(S')` with `op ⊆ S'`, OR `in(S')` with `S' ∩ op = ∅`, OR `eq(x)` with `x not in op` |
| `prefix` | nonempty `string` | `v.starts_with(op)` | `child` is `prefix(p')` with `p'.starts_with(op)`, OR `eq(x)` / `in(S')` where every element starts with `op` |
| `suffix` | nonempty `string` | `v.ends_with(op)` | `child` is `suffix(s')` with `s'.ends_with(op)`, OR `eq(x)` / `in(S')` where every element ends with `op` |
| `range` | `[uint64_str min, uint64_str max]`, `min <= max` | `min <= int(v) <= max` | `child` is `range([a,b])` with `min <= a <= b <= max`, OR `eq(x)` / `in(S')` where every integer lies in `[min, max]` |
| `hash_eq` | `hex64` | `v == op` or `SHA256(bytes(v)) == op` (per profile) | `child` is `hash_eq(op)` |

> **Conservative comparison semantics:** The table above is intentionally conservative and performs no syntactic rewriting. For example, a parent using `eq("Invoices")` rejects a child using singleton `in(["Invoices"])`; to narrow `eq(x)`, a child MUST emit `eq(x)`.

**Universal Capability Attenuation Rule (`SL-WIRE-017`, `decided`):**
A child capability `C` narrows a parent capability `P` iff:
1. `C.action == P.action` and `C.target == P.target`;
2. For every key `k` present in `P.where`, `k` MUST be present in `C.where` and `C.where[k] <= P.where[k]` per the table above (`C.where` MAY add additional keys not present in `P.where`);
3. For every quota `(kind, resource, unit, window)` present in `P.quotas`, `C.quotas` MUST contain a matching quota with `int(C.max) <= int(P.max)`, and `C.quotas` MUST NOT introduce a quota with an incompatible `window` counting mode.

**Complexity bound:** Pairwise predicate comparison runs in $O(|op|)$ time. Checking a child capability list of length $|C| \le 64$ against a parent template list of length $|P| \le 64$ with at most $|W| \le 32$ `where` keys runs in $O(|C| \cdot |P| \cdot |W| \cdot |op|)$ bounded deterministic time without scripts or external notaries.

---

## 7. Deterministic Wire Validation Pipeline

Every verifier parsing any SealLink object **MUST** execute checks in this exact order and return the **first** failure (`SL-WIRE-018`, `decided`):

1. Size (`<= max_bytes`) and nesting depth (`<= 16`) (`SL-WIRE-001`) -> `WIRE_SIZE`
2. UTF-8 / no BOM / trailing bytes / RFC 8259 JSON object (`SL-WIRE-002`) -> `WIRE_JSON`
3. Duplicate object member names (`SL-WIRE-003`) -> `WIRE_DUPLICATE`
4. Disallowed `null` values (`SL-WIRE-004`) -> `WIRE_VALUE`
5. Number token grammar (`SL-WIRE-007`) -> `WIRE_NUMBER`; string scalar ranges (`SL-WIRE-005`) -> `WIRE_STRING`
6. Restricted RFC 8785 byte-for-byte round-trip (`SL-WIRE-006`) -> `WIRE_NOT_CANONICAL`
7. Registered `type` check (`SL-WIRE-010`) -> `WIRE_TYPE`
8. Closed schema member check (`SL-WIRE-010`) -> `WIRE_MEMBER`; integer bounds (`SL-WIRE-007..009`) -> `WIRE_INTEGER`; Constraint Algebra sorting, range ordering, and `extensions` check (`SL-WIRE-015..016`) -> `WIRE_CONSTRAINT`
9. Public key syntax and curve-point validation (`SL-WIRE-012`) -> `WIRE_KEY`
10. Cryptographic signature verification, strictly ascending `guardian_approvals[]` slot order (where applicable), and `SignatureSet` threshold check (`SL-WIRE-013`) -> `WIRE_SIGNATURE`

---

## 8. Security Considerations

- **No blind digest signing:** Signing services MUST parse the canonical object, validate `type`, display human-readable fields (for presence-gated keys), and compute the tagged digest internally — never sign an opaque caller-supplied 32-byte digest.
- **No signature malleability as replay:** `id = SHA256(payload_bytes)` excludes `signatures`, ensuring re-signing the same payload with fresh randomness or a different valid subset of an `m-of-n` `SignatureSet` never produces a new grant ID, contract ID, or invocation deduplication key.
- **No `null` ambiguity:** Banning `null` eliminates parser divergence between absent optional fields and `null`-valued fields.
- **Fail-closed extensions:** Any unrecognized `type`, predicate operator, or populated `extensions` field refuses unconditionally.
- **Policy binding:** Because `signatures.policy` sits outside `payload_bytes`, verifiers MUST always compare `signatures.policy` against an independently derived expected policy (`SL-WIRE-013` item 4).

---

## 9. References

- **Normative:** [RFC2119], [RFC8174], [RFC8259], [RFC8785], [RFC8032], [BIP-340], [SEC1], [JSON-SCHEMA-2020-12].
- **Informative:** [RFC8448].
