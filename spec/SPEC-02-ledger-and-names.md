# SPEC-02: Ledger Interface, Namecoin Binding, ScriptPolicy, Merkle Batching, and UTXO Seals

- **Version:** `1.0.0-draft.10`
- **Status:** `draft` (normative rules `decided` except provisional freshness constants and Tier 2 profile marked `open` in `OPEN-QUESTIONS.md`)
- **Evidence / Maturity:** `vectors` (`vectors/ledger-scripts-and-opreturn.json`, `vectors/refusal-coverage-matrix.json`; two-node P2A regtest proof in `conformance/p2a-regtest/`)
- **Registries:** `registry/opreturn-actions.json`, `registry/refusal-codes.json`
- **Schemas:** `schemas/common.schema.json`

---

## 1. Abstract Ledger Interface (`ChainView`)

Core SealLink semantics (`SPEC-03` through `SPEC-07`) depend solely on an abstract ledger interface (`ChainView`) satisfied by any public ledger providing eight primitives (`SL-LDGR-001`, `decided`):

1. **Globally unique names** owned by an authenticated script/policy.
2. **Totally ordered name updates** forming an auditable history chain from initial registration.
3. **Name liveness / expiry rules** deterministically evaluable at any block height.
4. **Compact name-attached value** sufficient for role keys/policy pins and one manifest SHA-256 head.
5. **Single-spend transaction outputs (UTXOs)** powering revocable seals, single-use seals, row coins, stop coins, status spines, and guardian slots.
6. **Compact arbitrary data commitments** (`OP_RETURN` or equivalent) anchored to block height.
7. **Script-agnostic output control** supporting single-key and `m-of-n` threshold policies without changing ledger consensus.
8. **Verifiable chain tip, block height, and median block time.**

### 1.1 Verifier Conformance Tiers (`SL-LDGR-002`, `decided` Tier 1 / `open` Tier 2)

| Tier | Architecture | Cryptographic Guarantees & Honest Boundaries | Permitted Use |
| --- | --- | --- | --- |
| **Tier 1 (Full-Node Verifier)** | Verifier reads its own locally controlled, read-only, tx-indexed full node (`txindex=1`, plus `namehistory=1` or equivalent historical registration archive), cross-checked against `>= 1` independent comparison node. | Full cryptographic verification of current and historical registration lineages (addressable independently by pinned `registration` outpoint even after expiry and re-registration of the same spelling), anchor inclusion, and **absence of spends or name updates in the active chain and its locally observed mempool**. Does not guarantee instant observation of unpropagated network transactions. | **Normative default; REQUIRED** for all effect executors (mail hosts, agent runtimes, wallets, locks, notaries). |
| **Tier 2 (Light / Proof-Bundle Verifier)** | PoW block header chain + Merkle transaction inclusion proofs + cross-query of `k >= 2` independent UTXO/name servers. | **Proves:** transaction inclusion, signatures, and already-observed spends. **Cannot cryptographically prove on Namecoin/Bitcoin** (no UTXO state root in block headers) that servers did not withhold a newer seal spend or name update, nor observe mempool spends. Security rests on at least 1 honest, non-eclipsed source among `k`. | `open` (deferred to a post-v1.0 profile; see `OPEN-QUESTIONS.md`). |

---

## 2. Namecoin Binding Profile v1

### 2.1 Chain Pins and Consensus Facts (`SL-LDGR-003`, `decided`)

- **Networks:**
  - `main`: genesis `000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770`, name expiry `D = 36000` blocks, SegWit ([BIP-141]) and CSV ([BIP-112]) activated at height `475000`, Taproot inactive.
  - `regtest`: verifier-configured genesis hash, name expiry `D = 30` blocks, SegWit active from genesis and CSV ([BIP-112]) active from height `1` (matching Namecoin Core `nc28.0` consensus parameters).
- No other network identifier is valid in SealLink v1.0 (`schemas/common.schema.json#/$defs/Network` closes `network` to `"main" | "regtest"`). A verifier MUST explicitly pin `network` and `genesis` in local configuration and refuse any node reporting a mismatch (`CHAIN_MISMATCH`).
- **Name value byte limit:** Namecoin consensus (`nc28.0` `MAX_VALUE_LENGTH`) allows `1023` bytes, while Namecoin Core wallet UI enforces `MAX_VALUE_LENGTH_UI = 520` bytes. SealLink fixes **`520` bytes** as its protocol limit (`SPEC-03`) for universal wallet compatibility.
- **Name registration:** Two-step flow (`OP_NAME_NEW` committing salted `HASH160(rand || name)`, followed `>= 12` blocks later by `OP_NAME_FIRSTUPDATE` revealing name and initial value, locking `0.01 NMC`). A name is live at tip height `H` iff its latest name operation confirmed at height `h` satisfies `H < h + D` (`NAME_EXPIRED` otherwise).
- **Read-only node route:** Verifier node credentials MUST NOT expose wallet or transaction-submission RPCs (e.g., restricted via `rpcwhitelist`).

### 2.2 Normative `ChainView` Snapshot Fields and Fail-Closed Defaults (`SL-LDGR-015`, `decided`)

To ensure deterministic cross-language verification between Rust, Go, and reference implementations, every chain adapter populating an immutable `ChainView` snapshot MUST supply the following exact fields and units (omitted or malformed fields fail closed as indicated):

| Field | Type & Unit | Fail-Closed Requirement |
| --- | --- | --- |
| `network`, `genesis` | `string` (`"main" \| "regtest"`), `hex64` | MUST match local verifier config AND the reading node's `getblockchaininfo()["chain"]` (`CHAIN_MISMATCH` / `CHAIN_UNHEALTHY`). |
| `tip_height`, `tip_hash`, `tip_header_time` | `uint53` blocks, `hex64`, `uint53` Unix seconds | Active tip block height, hash, and header timestamp. |
| `tip_median_time_past` | `uint53` Unix seconds (BIP-113 `mediantime`) | REQUIRED for evaluating any ward origin with `majority_commitment` (`GUARDIAN_TIME_BOUNDARY` if omitted). |
| `best_header_height`, `in_ibd`, `txindex`, `node_reachable` | `uint53`, `bool`, `bool`, `bool` | ALL four fields are REQUIRED (omitted or non-conforming type fails closed `CHAIN_UNHEALTHY`). MUST satisfy `node_reachable == true`, `in_ibd == false`, `txindex == true` (verified via `getindexinfo`), and `best_header_height - tip_height <= LAG` where `LAG` and future bound `S` are owned strictly by local verifier configuration (never overridden by untrusted snapshot fields). |
| `now`, `tip_first_sight`, `clock_watermark` | `uint53` Unix seconds | ALL three fields are REQUIRED (`CHAIN_CLOCK_ERROR` if omitted). `now < clock_watermark` refuses `CHAIN_CLOCK_ERROR`; `tip_header_time - now > S` refuses `CHAIN_CLOCK_ERROR`; `tip_first_sight` records durable first observation of `tip_hash`. |
| `observation_bracket` *(+ optional `rebracket_tip`)* | `{consistent: bool, start: {hash, height}, end: {hash, height}}` | REQUIRED by default (`require_observation_bracket = true`); checked BEFORE peer comparison and downstream stages. Missing bracket, `consistent != true`, `start != end`, or `start != (tip_hash, tip_height)` ALWAYS refuses `CHAIN_OBSERVATION_VOID` (even if `rebracket_tip` is present; when `rebracket_tip` is present it MUST additionally match `(tip_hash, tip_height)`). During `pre_effect_recheck`, `consistent` MUST remain `prev_consistent && (recheck_start == recheck_end)` (a voided bracket MUST NEVER be resurrected). |
| `comparison_peers` | array of `{id, healthy, height, hash_at_tip}` (`schemas/common.schema.json#/$defs/ChainViewComparisonPeer`) | REQUIRED (`CHAIN_UNHEALTHY` if omitted or empty). At least one peer with `healthy == true`, valid `uint53` `height`, and 64-hex `hash_at_tip` is required (`CHAIN_UNHEALTHY`); any healthy peer with `height > tip_height` or `hash_at_tip != tip_hash` vetoes (`CHAIN_NODE_DISAGREEMENT`). |
| `txs`, `blocks`, `block_times` | active-chain confirmed & mempool tx maps; `blocks` maps `block_hash -> height`; `block_times` maps `height_str -> uint53` BIP-113 `mediantime` | Every confirmed tx MUST verify `confirmations >= 1` and `blocks[block_hash] == confirmed_height`; `block_times` records strictly verified BIP-113 `mediantime` (adapters MUST NEVER substitute ordinary `header.time` when `mediantime` is unavailable, and MUST fetch `getblockhash(h_rec + delay_blocks)` -> `mediantime` inside the same observation bracket for every pending/promoted `0x0c` deadline `<= tip_height` so quiet maturity blocks remain verifiable on cold nodes). `gettxout` responses MUST be strictly `null` (absent) or a valid object with `scriptPubKey` and `confirmations` — transient `gettxout` RPC errors or malformed responses MUST fail closed `CHAIN_UNHEALTHY` with zero closures written (NEVER treated as `absent_from_utxo`). |
| `names`, `name_registrations` | confirmed registration lineages keyed by `name` -> `{registration, history_truncated, updates, mempool_updates?}` | Each lineage records ordered confirmed updates (`txid, vout, op, confirmed_height, block_time` [BIP-113 `mediantime`], `output_script_hex, owner_policy, prev_input, opreturn_hex / opreturns`) plus per-registration `history_truncated: bool` and optional `mempool_updates[]` (locally observed mempool `OP_NAME_UPDATE` spends of that registration; any unparseable or unfetchable mempool spend MUST set `unparseable: true`, failing closed with retryable `NAME_HISTORY_UNAVAILABLE` without writing a permanent role closure). Namecoin Core `nc28.0` RPC error codes `-1` / `-4` with missing-name message map to absent name (`NAME_NOT_FOUND`); any other `name_history` RPC error (including `-32601 Method not found` on nodes without `namehistory=1`) or unparseable history entry sets `history_truncated = true` and fails closed (`NAME_HISTORY_UNAVAILABLE` / `CHAIN_SCRIPT_UNSUPPORTED`). |

---

## 3. Unified `ScriptPolicy` (On-Chain Ownership and Seal Scripts)

SealLink uses one deterministic **`ScriptPolicy`** primitive covering **name ownership**, **contract termination seals**, **guardianship slots**, **status/roster spines**, and **single-use seals**.

### 3.1 Supported Templates, Canonical Pair Ordering, and `BranchKeySpec` (`SL-LDGR-004`, `decided`)

Every `ScriptPolicy` deterministically compiles to an exact native SegWit v0 trailing `scriptPubKey` (`P2WPKH` 22 bytes or `P2WSH` 34 bytes). All compressed secp256k1 keys MUST be valid points on the curve (`WIRE_KEY` otherwise).

- **Strict canonical input order & distinct x-coordinates:** Within `multisig.pks[]`, `BranchKeySpec.pks[]`, and ALL unordered key pairs `(a, b)` (`either_of_2`, `both_of_2`, and `(a, b)` in `arbiter_or_both`), inputs MUST be supplied in **strict ascending canonical order** (`a < b` as lowercase hex for single keys, or `canonical_JCS(a) < canonical_JCS(b)` when either side is a `BranchKeySpec` object). Furthermore, all compressed secp256k1 keys appearing across any distinct keys or roles within the same `ScriptPolicy` MUST have **pairwise distinct 32-byte x-coordinates** (rejecting duplicate keys and `02X`/`03X` negated-point pairs with `CHAIN_SCRIPT_UNSUPPORTED`).
- **On-chain vs. off-chain policy identity:**
  1. *On-chain UTXO matching* compares the compiled trailing `scriptPubKey` byte-for-byte against the ledger output script.
  2. *Off-chain policy equality* (e.g., `NamePin.owner_policy` equality, `ThresholdPolicy` equality, and `ScriptPolicy` comparisons across pins) verifies compilation and compares exact **canonical JCS bytes** (`SPEC-01 §1`). Because every supported `ScriptPolicy` template enforces a unique canonical input representation (`a < b`, sorted `pks[]`, no `1-of-1` object form), canonical JCS equality is unambiguous and unique per policy.
- **Relative locktime `<D>`:** Uses minimal Bitcoin Script `CScriptNum` encoding (`1 <= D <= 52560`, BIP-68 block-based relative locktime with bit 22 cleared: `1..16` MUST compile to single-byte `OP_1`..`OP_16` `0x51..0x60`; `D >= 17` uses minimal little-endian signed push).
- **Contract seal restriction:** `Contract.termination.seal.script_policy` MUST use `ContractSealScriptPolicy` (closed in `schemas/contract.schema.json` to `key`, `multisig`, `either_of_2`, `both_of_2`, or `arbiter_or_both`; `single_use_1_of_2` and `guardian_slot_pending` are forbidden on contract seals).

**Institutional `BranchKeySpec` (single key OR compact `m-of-n`):** To allow institutional roles (`disposer`, `arbiter`, `challenger`, and the `arbiter` branch of `arbiter_or_both`) to use either a single key / threshold-ECDSA MPC signer OR a native offline PSBT `m-of-n` multisig without inflating single-key scripts, those branch slots accept a **`BranchKeySpec`**:
- Either a single `CompressedPubkey66` string `pk` -> `clause(pk) = <pk> OP_CHECKSIG`, `clause_verify(pk) = <pk> OP_CHECKSIGVERIFY`;
- Or a compact native multisig object `{"m": k, "pks": [p_1, ..., p_n]}` with `2 <= n <= 5`, `1 <= k <= n`, strictly ascending `CompressedPubkey66` keys with distinct x-coordinates (`1-of-1` object form is FORBIDDEN to guarantee a single canonical encoding) -> `clause(spec) = OP_k <p_1> ... <p_n> OP_n OP_CHECKMULTISIG`, `clause_verify(spec) = OP_k <p_1> ... <p_n> OP_n OP_CHECKMULTISIGVERIFY`.

| `kind` / `template` | Compilation to Output `scriptPubKey` | Primary Use |
| --- | --- | --- |
| `{"kind":"key","pk":"<66hex>"}` | `P2WPKH` (22B): `OP_0 PUSH20 HASH160(pk)`. Spent with ECDSA. *(Namecoin `P2WPKH` validates strictly ECDSA, never BIP-340 Schnorr / FROST; any single-key threshold custody MUST use qualified threshold ECDSA.)* | Individual actor name, ordinary revocable grant seal, row coin, stop coin, disposable revoke seal. |
| `{"kind":"multisig","m":k,"pks":[...]}` | `P2WSH` (34B): `OP_0 PUSH32 SHA256(witnessScript)`, where `witnessScript = OP_k <pk_1> ... <pk_n> OP_n OP_CHECKMULTISIG`, `1 <= k <= n <= 15`. | Child name (`2-of-3`), organization name (`3-of-5`), multi-guardian agent name (`2-of-3`), signed via `namepsbt`. |
| `{"kind":"branch","template":"either_of_2","keys":{"a","b"}}` | `P2WSH` (34B), requiring `a < b` (single-key hex or `canonical_JCS`). If `a` and `b` are single keys: `OP_1 <a> <b> OP_2 OP_CHECKMULTISIG` (71B). If either is an `m-of-n` `BranchKeySpec`: `OP_IF <clause(a)> OP_ELSE <clause(b)> OP_ENDIF`. | Contract seal (`either_party`); active guardian slot (`guardian OR disposer`); `status_seal`. |
| `{"kind":"branch","template":"both_of_2","keys":{"a","b"}}` | `P2WSH` (34B), requiring `a < b` (single-key hex or `canonical_JCS`). If `a` and `b` are single keys: `OP_2 <a> <b> OP_2 OP_CHECKMULTISIG` (71B). If either is an `m-of-n` `BranchKeySpec`: `<clause_verify(a)> <clause(b)>`. | Contract seal (`both_together`); on-chain 2-party assent; vacant guardian slot (`disposer AND arbiter`); `roster_seal`; `recovery_seal`. |
| `{"kind":"branch","template":"arbiter_or_both","keys":{"a","b","arbiter"}}` | `P2WSH` (34B), requiring `a < b` (`a, b` single keys; `arbiter` is `BranchKeySpec`, all x-coords pairwise disjoint): `OP_IF OP_2 <a> <b> OP_2 OP_CHECKMULTISIG OP_ELSE <clause(arbiter)> OP_ENDIF`. | Contract seal (`arbiter` termination branch `0` or mutual termination branch `1`). |
| `{"kind":"branch","template":"single_use_1_of_2","keys":{"issuer","grantee"}}` | `P2WSH` (34B): `OP_IF <issuer> OP_CHECKSIG OP_ELSE <grantee> OP_CHECKSIG OP_ENDIF` (`issuer, grantee` single keys with distinct x-coordinates; witness selector evaluated via Bitcoin Script `CastToBool`: non-empty truthy `0x01` = issuer revoke; empty `""` = grantee use). | Single-use UTXO grant seal (unambiguous branch attribution). |
| `{"kind":"branch","template":"guardian_slot_pending","keys":{"disposer","challenger","guardian"},"delay_blocks":D}` | `P2WSH` (34B): `OP_IF <clause(disposer)> OP_ELSE OP_IF <clause(challenger)> OP_ELSE <D> OP_CHECKSEQUENCEVERIFY OP_DROP <guardian> OP_CHECKSIG OP_ENDIF OP_ENDIF` (`disposer, challenger` are `BranchKeySpec`; `guardian` is a single key; all x-coords pairwise disjoint; witness selectors evaluated via Bitcoin Script `CastToBool`). | Stage 1 pending guardian slot: disposer or challenger MAY veto during delay `D`; after `D` blocks, guardian spends to Stage 2 active `either_of_2(guardian, disposer)` (`SPEC-04 §3.3`), permanently terminating challenger veto. |

#### Normative Witness Stack Layouts (Bottom-to-Top, BIP-141)

For every `m-of-n` `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` clause (`multisig` or `m-of-n` `BranchKeySpec`), BIP-141 `NULLDUMMY` REQUIRES a leading empty byte vector `""` (`OP_0` dummy) immediately below the `m` DER+`SIGHASH_ALL` signatures (`sigs_of(spec)` denotes `[sig]` for a single key, or `["", sig_1, ..., sig_m]` for an `m-of-n` `BranchKeySpec`):

| Template & Branch | Exact Witness Stack (Bottom -> Top) | Sequence / Notes |
| --- | --- | --- |
| `key` (`P2WPKH`) | `[sig, pk]` | `sig` ends with `0x01` (`SIGHASH_ALL`) |
| `multisig` (`P2WSH`) | `["", sig_1, ..., sig_k, witnessScript]` | Signatures ordered matching ascending `pks[]` |
| `either_of_2` (single keys) | `["", sig, witnessScript]` | `OP_1 <a> <b> OP_2 OP_CHECKMULTISIG` |
| `either_of_2` (`BranchKeySpec`, branch `a` / `b`) | `[...sigs_of(a), "01", witnessScript]` / `[...sigs_of(b), "", witnessScript]` | Truthy `"01"` selects `a`; empty `""` selects `b` |
| `both_of_2` (single keys) | `["", sig_a, sig_b, witnessScript]` | `sig_a` before `sig_b` matching `a < b` |
| `both_of_2` (`BranchKeySpec`) | `[...sigs_of(b), ...sigs_of(a), witnessScript]` | `<clause_verify(a)>` consumes top first, then `<clause(b)>` |
| `arbiter_or_both` (both / arbiter) | `["", sig_a, sig_b, "01", witnessScript]` / `[...sigs_of(arbiter), "", witnessScript]` | Branch `1` = both parties; branch `0` = arbiter |
| `single_use_1_of_2` (issuer / grantee) | `[sig_issuer, "01", witnessScript]` / `[sig_grantee, "", witnessScript]` | Branch `1` = revoke; branch `0` = grantee use + `0x11` |
| `guardian_slot_pending` (disposer / challenger / CSV guardian) | `[...sigs_of(disposer), "01", witnessScript]` / `[...sigs_of(challenger), "01", "", witnessScript]` / `[sig_guardian, "", "", witnessScript]` | CSV guardian branch MUST have exact 4-item witness with `wit[-1] == witnessScript`, `CastToBool(wit[-2]) == false`, `CastToBool(wit[-3]) == false`, `sig_guardian` ending in `0x01`, AND BIP-68 input `sequence` with bit 31 & bit 22 cleared and `(sequence & 0xffff) >= delay_blocks` |

> **Namecoin Core `nc28.0` compatibility note:** In `src/script/solver.cpp:146-148`, Namecoin strips the `OP_NAME_*` prefix before evaluating `WITNESS_V0_SCRIPTHASH` (`IsWitnessProgram(true, ...)`), so native `P2WSH` name outputs pass standard relay policy up to 3,600-byte witness scripts and 100 stack items. Even a worst-case `guardian_slot_pending` with 5-of-5 `disposer` and 5-of-5 `challenger` compiles to under 400 bytes.

### 3.2 Name Output Prefix Grammars and Pre-Spend Verification (`SL-LDGR-005`, `decided`)

1. **Exact Namecoin name script grammars:** A Namecoin name output `scriptPubKey` MUST match one of the three exact prefix forms followed immediately by a trailing native SegWit `scriptPubKey` (`P2WPKH` 22 bytes or `P2WSH` 34 bytes; legacy `P2PKH` is NOT supported):

| Operation | Opcode | Exact Prefix Before Trailing `scriptPubKey` |
| --- | :-: | --- |
| `NAME_NEW` | `0x51` (`OP_NAME_NEW`) | `OP_NAME_NEW <20B_hash> OP_2DROP <scriptPubKey>` |
| `NAME_FIRSTUPDATE` | `0x52` (`OP_NAME_FIRSTUPDATE`) | `OP_NAME_FIRSTUPDATE <name> <rand> <value> OP_2DROP OP_2DROP <scriptPubKey>` |
| `NAME_UPDATE` | `0x53` (`OP_NAME_UPDATE`) | `OP_NAME_UPDATE <name> <value> OP_2DROP OP_DROP <scriptPubKey>` |

   - **Namecoin `nc28.0` data-push rule:** Inside Namecoin name prefixes (`src/script/names.cpp`), an empty value MUST be pushed as `OP_0` (`0x00`), any 1-byte argument (including `0x01..0x10` and `0x81`) MUST be pushed as a direct 1-byte data push (`0x01 <byte>`, NOT `OP_1..OP_16` / `OP_1NEGATE`), and multi-byte arguments MUST use minimal `0x02..0x4b`, `OP_PUSHDATA1` (`0x4c` for 76..255B), or `OP_PUSHDATA2` (`0x4d` for 256..520B).
   - **Fail-closed history parsing:** Any output violating these exact prefix and cleanup opcodes, or any unparseable/unfetched name operation encountered during history traversal, MUST refuse (`CHAIN_SCRIPT_UNSUPPORTED` or `NAME_HISTORY_UNAVAILABLE`). A verifier or chain adapter MUST NEVER silently drop an unparseable history transaction.
2. **Pre-spend verification:** Because an unspent `P2WSH` output exposes only `OP_0 PUSH32 SHA256(witnessScript)` on chain, any pin, contract, manifest, or origin naming an output MUST include its complete `ScriptPolicy`. The verifier compiles `ScriptPolicy` to the exact trailing `scriptPubKey` (`22` bytes for `key`, `34` bytes for `multisig` and `branch`) and requires byte-for-byte equality with the trailing `scriptPubKey` extracted from the on-chain output. Mismatch or unknown template MUST refuse with `CHAIN_SCRIPT_UNSUPPORTED` (non-closing; never inferred as a transfer).
3. **No covenant renewal-only branch (`SL-LDGR-006`, `decided`):** Unmodified Namecoin lacks output covenants (`OP_CTV`). Any spending branch in a name's `ScriptPolicy` can technically transfer the name to another script. Deployments MUST NOT add a low-threshold "renewal-only" branch to a name output; renewals MUST use the name's full `ScriptPolicy` threshold.

### 3.3 Author / Writer Verification and Mempool Name Updates (`SL-LDGR-007`, `decided`)

Receiving a name output proves neither authorship nor consent. To prove a name value or ownership transfer was **authored** by `owner_policy`:
1. The spent previous name input's trailing `scriptPubKey` MUST equal `compile(owner_policy)`, and the spending witness MUST satisfy `owner_policy` (verified via witness script hash and pubkeys for `P2WSH`, or pubkey hash for `P2WPKH`);
2. Every authorizing ECDSA signature in that input's witness MUST end with strict sighash byte **`0x01` (`SIGHASH_ALL`, without `ANYONECANPAY`)**, committing to every output (including the new name value, any transferred destination script, and any `OP_RETURN` break or cancel frame);
3. For a newly registered name whose `OP_NAME_FIRSTUPDATE` was signed by a funding wallet, the pinned `owner_policy` MUST sign one subsequent `OP_NAME_UPDATE` of its own before that value is treated as owner-authored (`NAME_WRITER_UNVERIFIED` otherwise);
4. **Mempool `OP_NAME_UPDATE` acceleration:** Tier 1 verifiers inspect locally observed mempool transactions spending the current active name output. A valid owner-authored (`SIGHASH_ALL`) mempool `OP_NAME_UPDATE` that changes or removes `link.grant` immediately accelerates revocation locally (`NAME_ROLE_CHANGED`), whereas new grants, manifest advances, and recoveries take effect only once confirmed on the active chain.

### 3.4 Normative Bitcoin / Namecoin Script Constants

| Constant | Hex / Value | Role |
| --- | --- | --- |
| `OP_0` / `OP_1..OP_16` | `0x00` / `0x51..0x60` | Empty push, multisig thresholds, minimal `CScriptNum` `1..16` |
| `OP_IF` / `OP_ELSE` / `OP_ENDIF` | `0x63` / `0x67` / `0x68` | Branch templates (`either_of_2` multisig, `arbiter_or_both`, `single_use_1_of_2`, `guardian_slot_pending`) |
| `OP_RETURN` | `0x6a` | Framed `SLNK` commitment output (single zero-value output per anchor tx) |
| `OP_2DROP` / `OP_DROP` | `0x6d` / `0x75` | Namecoin prefix cleanup & `OP_CHECKSEQUENCEVERIFY` stack cleanup |
| `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` | `0xac` / `0xad` | Single-key signature check (`clause` / `clause_verify`) |
| `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` | `0xae` / `0xaf` | `m-of-n` multisig check (`clause` / `clause_verify`) |
| `OP_CHECKSEQUENCEVERIFY` | `0xb2` | Relative block locktime (`BIP-112`, bit 22 cleared, `1 <= D <= 52560`, `nVersion >= 2`) |
| `OP_NAME_NEW` / `FIRSTUPDATE` / `UPDATE` | `0x51` / `0x52` / `0x53` | Namecoin name prefix opcodes (`src/script/names.cpp`) |
| `SIGHASH_ALL` | `0x01` | Required final byte of every authorizing ECDSA signature |
| `P2WPKH` / `P2WSH` / `P2A` | `00 14 <20B>` / `00 20 <32B>` / `51 02 4e73` | SegWit v0 outputs (22B, 34B) and TRUC v3 CPFP anchor output (4B, dust `240` base units) |

---

## 4. Observation, Multi-Node Freshness, and Risk Cutoffs

Every chain-dependent decision executes inside one **consistent observation** (`SL-LDGR-008`, `decided` algorithm & `K = 432` / `open` provisional constants `LAG`, `S` tracked in `OPEN-QUESTIONS.md`):

1. **Snapshot bracket (checked first):** Read tip `(hash_0, height_0)` on the reading node before all queries, and `(hash_1, height_1)` after. If `(hash_0, height_0) != (hash_1, height_1)`, discard the observation with `CHAIN_OBSERVATION_VOID` **before** evaluating comparison peers or downstream admission steps (no closure written, except any validated seal spend already witnessed).
2. **Active-chain authenticity & multi-node health:** Reading node MUST be synced (`!IBD`, real `txindex=1` verified via `getindexinfo` or equivalent, `best_header - tip <= LAG`, provisional `LAG = 1`; else `CHAIN_UNHEALTHY`). Every confirmed transaction and block hash (`recent_block`, anchor tx, seal tx, name history tx) MUST be verified on the active chain (`confirmations >= 1` AND `getblockhash(block_height) == block_hash`); unverified presenter hints MUST NEVER be treated as confirmed spends or chain facts. Verifier MUST cross-check `(hash_0, height_0)` against `>= 1` independent healthy comparison node (distinct operator source, querying `getblockhash(height_0)` on each healthy peer); if zero healthy comparison nodes are configured or reachable, refuse `CHAIN_UNHEALTHY`. If *any* healthy comparison node reports a different hash at `height_0` or a higher height than `height_0`, refuse `CHAIN_NODE_DISAGREEMENT` (a single disagreeing healthy peer vetoes).
3. **Dual tip-age freshness:** Verifier maintains a durable monotonic UTC clock watermark (clock regression -> `CHAIN_CLOCK_ERROR`; on `network = "main"`, operational wall-clock mode is MANDATORY and deterministic test-clock overrides are FORBIDDEN) and rejects headers with `header_time - now > S` (provisional `S = 600s`). Verifier durably records `first_sight_time` on first observation of each block hash using atomic transactional read-modify-write merging (`min(first_sight_time)`, `max(clock_watermark)`):
   ```text
   tip_age = max(now - header_time, now - first_sight_time)
   ```
   Risk cutoffs:
   - **Class 1 (money, irreversible effects, custody/guardian transitions, issuance):** `tip_age <= 3600s` (60 min; default if unstated).
   - **Class 2 (other privileged/read-only actions):** `tip_age <= 5400s` (90 min).
   Exceeding cutoff refuses `CHAIN_TIP_STALE`.
4. **Recency & confirmation depth:** Grant `recent_block` `R` MUST lie on the active chain (`getblockhash(R.height) == R.hash`); anchor height `A` MUST satisfy `R < A <= R + K` (`K = 432` blocks, ~72h on Namecoin; else `CHAIN_RECENCY_INVALID`). Confirmation depth is `H - h + 1`, requiring `>= max(signed_min_depth, operator_floor)` where `signed_min_depth` is `grant.min_depth` (default `1` if omitted) (`CHAIN_DEPTH_INSUFFICIENT`).
5. **Pre-effect recheck:** Immediately before reserving or executing an irreversible effect, the executor MUST execute a bounded `pre_effect_recheck` that:
   - preserves the initial observation snapshot for auditability;
   - advances to one unified decision clock `now_recheck >= now_initial` applied consistently to BOTH invocation expiry (`expires_at`) and refreshed `tip_age`;
   - re-verifies node sync/lag (`!IBD`, `best_header - tip <= LAG`), comparison peers, all relevant name outputs (including mempool `OP_NAME_UPDATE`), and all active seals (including mempool spends);
   - closes the recheck bracket with a second tip read AFTER all refreshed queries and preserves `consistent = prev_consistent && (recheck_open == recheck_close)` (so a previously voided snapshot is NEVER resurrected, and any tip move mid-recheck refuses `CHAIN_OBSERVATION_VOID`); and
   - persists updated operational watermark / `first_sight` records via atomic transactional read-modify-write merge.

---

## 5. Witness Profile (`W`), `SLNK` `OP_RETURN` Framing, and Merkle Batching (`0x02`)

### 5.1 Witness Construction Profile (`W`) (`SL-LDGR-009`, `decided`)

- **Every input** of a seal-creation transaction `T` and an anchoring transaction `A` MUST be non-empty and native SegWit v0 (`P2WPKH` or `P2WSH`) with empty `scriptSig` and strict `SIGHASH_ALL` (`0x01`) on all signatures (`CHAIN_TX_CONSTRUCTION`).
- **Exact linkage output:**
  - For **every** individual grant anchor (`0x01`) — both root grants AND depth-2 child grants — when `A` anchors a grant whose seal was created in `T` at `seal_vout`, `T` MUST create a native SegWit linkage output at `vout = seal_vout + 1`, and `A` MUST spend exact prevout `(seal_txid, seal_vout + 1)` (never spending the seal). For a depth-2 child grant, `A` therefore spends **both** the parent's delegation `row_coin` AND the child's own `(child_seal_txid, child_seal_vout + 1)` linkage output.
  - For a Merkle batch anchor (`0x02`), **root grants ONLY** are permitted (depth-2 child grants spending a delegation row coin MUST use individual `0x01` anchors so row-coin linkage is unambiguous; `CHAIN_FRAME_INVALID` otherwise). Every root grant leaf `i` in a `0x02` batch MUST have its seal-creation tx `T_i` create linkage output `(seal_txid_i, seal_vout_i + 1)` spent directly by an input of `A`.
  - Only the linkage output(s) (and for a depth-2 child grant, the parent's confirmed `row_coin`) may be spent together with `T`; all other funding inputs of `A` MUST be confirmed at a block height strictly `< anchor_height` (`CHAIN_TX_CONSTRUCTION`). `T` and `A` MAY confirm in the same block.
- **Legacy profile (`L`):** Reserved solely for future non-SegWit UTXO chains; refused on Namecoin (`CHAIN_TX_CONSTRUCTION`).

### 5.2 Framed `OP_RETURN` Format (`SLNK`) (`SL-LDGR-010`, `decided`)

Every SealLink on-chain commitment uses **exactly one** zero-value (`value == 0`) `SLNK` `OP_RETURN` output per anchoring transaction (`CHAIN_FRAME_INVALID` if missing, duplicated, non-zero value, reserved `0x06`, malformed, or carrying a `loc_type` outside the action's normative `allowed_locators` in `registry/opreturn-actions.json`):

```text
OP_RETURN (0x6a)  PUSH5 (0x05)  "SLNK" (53 4c 4e 4b)  <action:1B>  <PUSH_N>  <payload:N bytes>
```

Standard payload (`N = 34` for `loc_type = 0x00`, total script **42 bytes**; `N = 66` for `loc_type = 0x01 | 0x02 | 0x05`, total script **74 bytes** — strictly below the 83-byte standard relay limit):

```text
<version:1B = 0x01> || <commitment:32B> || <loc_type:1B> || [pointer:0B|32B]
```

Exception — Action `0x0b` (`KEY_COMPROMISE_BREAK`, total script **50 bytes**, `N = 42`):

```text
<version:1B = 0x01> || <typed_digest:32B> || <h_c_le64:8B> || <loc_type:1B = 0x00>
```

Example hex (`action = 0x01`, `loc_type = 0x00`, 42 bytes):
```text
6a 05 534c4e4b 01 22 01 <commitment:32B> 00
```

All action codes (`0x01`–`0x12`, with `0x06` reserved) and locator types (`0x00`, `0x01`, `0x02`, `0x05`) are registered in `registry/opreturn-actions.json`. Locators are strictly non-exclusive hints: an unavailable locator NEVER invalidates a document whose exact bytes match `commitment` when supplied inline or via any other channel.

**Name-history `SLNK` criticality & deterministic decoding precedence (200-year forward-compatibility):** When walking confirmed `OP_NAME_UPDATE` history (`resolve_name`), EVERY confirmed update carrying an `SLNK` `OP_RETURN` output (regardless of sighash flags) MUST be validated in strict outer-before-semantic precedence (semantic `0x0b` / `0x10` effects still additionally require owner-authored `SIGHASH_ALL` per `SL-LDGR-007`):
1. **Outer envelope check (always FIRST -> `CHAIN_FRAME_INVALID`):** At most ONE `SLNK` `OP_RETURN` output per transaction, strictly `value_sat == 0`, total script `8 <= len <= 83` bytes starting with `6a 05 534c4e4b <action:1B>`, followed by exactly one valid Bitcoin Script data push with non-empty payload reaching end-of-script. Any violation refuses **`CHAIN_FRAME_INVALID`** before consulting action-range criticality.
2. **Known v1.0 actions (`0x01`–`0x05`, `0x07`–`0x12`):** Strict body decode (`version == 0x01`, exact length 42B/74B or 50B for `0x0b`, allowed `loc_type`, and `h_c <= confirmed_height` for `0x0b`); any violation refuses **`CHAIN_FRAME_INVALID`**.
3. **Critical forward-only reserved range (`0x13`–`0x1a`, incl. `0x13` voluntary rebind & `0x14` log checkpoint):** Reserved for future state transitions that act strictly forward from `confirmed_height` without retroactively altering earlier blocks. An older v1.0 verifier MUST NOT attempt to parse future payload internals: on live evaluation (`at_height == None`) or historical evaluation with `at_height >= confirmed_height`, fail closed **`ORIGIN_STATUS_INCOMPLETE`**; on historical evaluation strictly prior to the frame (`at_height < confirmed_height`), the future forward-only frame does NOT invalidate the earlier historical fact.
4. **Critical retroactive reserved range (`0x1b`–`0x1f`):** Reserved for future emergency/retroactive actions (e.g., future post-quantum compromise breaks). An older v1.0 verifier MUST fail closed **`ORIGIN_STATUS_INCOMPLETE`** on EVERY evaluation (live AND historical at any `at_height`) without attempting to parse future payload internals.
5. **Advisory ignorable range (`0x20`–`0x2f`):** Reserved for non-critical soft-fork annotations. A v1.0 verifier verifies standard 42B/74B `SLNK` v1 framing (`CHAIN_FRAME_INVALID` if malformed) and then safely ignores well-formed frames at all heights.
6. **Reserved `0x06` or any unknown action outside `0x13`–`0x2f`:** MUST fail closed **`CHAIN_FRAME_INVALID`**.

### 5.3 Merkle Batch Anchor Construction (`0x02`) (`SL-LDGR-014`, `decided`)

Action `0x02` (`BATCH_ANCHOR`, permitted for **root grants ONLY** — never depth-2 child grants) commits to a non-empty set of `1 <= N <= 65536` distinct 32-byte item commitments (`item_digest_32B`) in a single `OP_RETURN` frame:

1. **Ordering:** Deduplicate all `item_digest_32B` entries and sort them in strictly ascending unsigned byte order (`d_0 < d_1 < ... < d_{N-1}`).
2. **Tagged leaf hash:** `L_i = H_tag("seallink-merkle-leaf/1", d_i)`.
3. **Tagged internal node hash:** `node(left, right) = H_tag("seallink-merkle-node/1", left || right)`.
4. **Odd-node promotion (no duplication):** At each level of length `k > 1`, pair `(level[0], level[1])`, `(level[2], level[3])`, ...; if `k` is odd, promote `level[k - 1]` unchanged to the next level. *(Promoting rather than duplicating prevents tree-duplication second-preimage malleability.)* If `N == 1`, `root = L_0`.
5. **Proof verification (`MerkleProof`):** Starting with `cur = H_tag("seallink-merkle-leaf/1", leaf_digest)`, for each step `{side, hash}` in `steps[]` (`len <= 16`):
   - If `side == "L"`, `cur = node(hash, cur)`.
   - If `side == "R"`, `cur = node(cur, hash)`.
   Verify `cur == proof.root` and `proof.root == op_return.commitment` (`CHAIN_FRAME_INVALID` on mismatch). Reference 5-leaf odd-promotion vector is published in `vectors/ledger-scripts-and-opreturn.json`.

---

## 6. UTXO Seal State Machine and Fast-Revocation Fee Bumping

### 6.1 Unified Three-Valued Seal State (`SL-LDGR-011`, `decided`)

Every standard revocable seal (grant seal, contract seal, credential seal, active guardian slot seal, device seal, member seal, auth seal, row stop coin) follows this deterministic state table:

| Observed Ledger Condition | Seal State | Verifier Action | Refusal Code |
| --- | --- | --- | --- |
| Creation tx confirmed at `>= required_depth`, trailing script matches compiled `ScriptPolicy`, UTXO unspent at tip and no valid spend in mempool. | **`unspent`** | Continue verification. | — |
| Creation tx confirmed with matching `ScriptPolicy`, AND either (a) a valid spend is witnessed in mempool or confirmed block, OR (b) confirmed output is absent from node's UTXO set (`gettxout == null` -> adapter MUST report `absent_from_utxo = true`, NEVER silent `unspent`). | **`revoked`** | Durably write permanent `closure` entry to fenced journal (`SPEC-06 §6`) BEFORE returning refusal. Reorgs or mempool eviction MUST NOT reopen a closed seal. | `SEAL_SPENT` |
| Creation tx unknown, unconfirmed, script mismatches `ScriptPolicy`, or node read inconclusive. | **`unavailable`** | Refuse WITHOUT writing permanent closure. | `SEAL_UNAVAILABLE` |

### 6.2 Single-Use Attribution (`SL-LDGR-012`, `decided`)

For `single_use_1_of_2` grant seals, a spend has **two distinct branches** and MUST NOT be folded blindly into `SEAL_SPENT`:

| Observed Seal Condition | Single-Use State | Verifier Action | Refusal / Outcome |
| --- | --- | --- | --- |
| Seal unspent (no grantee spend observed). | `awaiting_spend` | Refuse without closure (grantee must spend branch `0` first). | `SEAL_UNAVAILABLE` |
| Spent via branch `1` (`issuer`), OR spent without valid `0x11` frame, OR absent from UTXO with unknown branch. | `revoked` | Write permanent `closure(cause="SEAL_SPENT")` to journal. | `SEAL_SPENT` |
| Spent via branch `0` (`grantee`) with a valid `0x11` frame whose `txid` or committed `content_addr` belongs to a *different* invocation (foreign/mismatched `0x11` presentation). | `revoked` (non-closing) | Refuse **WITHOUT** writing a permanent `grant` closure (anti-DoS: a mismatched invocation presentation MUST NOT poison the legitimate `0x11` spend). | `SEAL_SPENT` |
| Spent via branch `0` (`grantee`, `SIGHASH_ALL`) with `OP_RETURN 0x11` committing `content_addr(invocation/1)`, depth `< required_depth` (mempool or shallow block). | `pending_confirm` | Refuse without closure; retryable once depth reaches `required_depth`. | `CHAIN_DEPTH_INSUFFICIENT` |
| Spent via branch `0` with matching `0x11`, confirmed `>= required_depth`, NOT yet in journal `single-use-consumed`. | `ready_once` | Execute at most once; commit completion atomically in ONE `settlement` journal entry (`single_use_consumed: true`, `use_txid`, `closes_grant_id`, `SPEC-06 §6`) updating derived single-use and grant closure state with `+1` witness advance. Across an `uncertain -> executed/refused` reconciliation, `single_use_consumed: true` MUST be recorded **at most once** (on the first settlement entry for that `invocation_id`, never duplicated on reconciliation). | **Admit** (`executed`) |
| Spent via branch `0`, already recorded in journal `single-use-consumed`. | `consumed` | Identical `invocation_id`: perform zero second effect and return cached receipt (or `INVOKE_REPLAY` if profile forbids cached return). Different `invocation_id`: refuse. | Cached receipt or `INVOKE_REPLAY` |

Block and mempool scanners projecting seal candidates MUST index tracked outpoints first and parse only transactions spending tracked seals.

### 6.3 Pre-Signed Disposable Seals and TRUC/P2A CPFP Anchor Output (`SL-LDGR-013`, `decided` format / `open` production propagation qualification)

Fast-revocation seals for devices, auth keys, and member entries use a **CSPRNG-only private key** (never BIP-39 derived) whose private key is **destroyed immediately** after pre-signing and replicating `tx_revoke`:
- A zero-fee pre-signed `tx_revoke` **MUST** use `nVersion = 3` (TRUC topology rules, [BIP-431]) signed with `SIGHASH_ALL` spending the seal UTXO and creating **one standard Pay-to-Anchor (`P2A`) output** ([BIP-433]): 4-byte witness v1 scriptPubKey `OP_1 PUSH2 0x4e73` (`51024e73`, classified as standard type `"anchor"` in Namecoin Core `nc28.0`) alongside its burn/return output. *(An `nVersion = 2` `tx_revoke` is permitted ONLY if pre-funded with a standalone fee `>= minrelaytxfee`, because Namecoin Core `nc28.0` rejects zero-fee v2 parents even inside 1p1c packages.)* The `P2A` output value MUST meet or exceed Namecoin Core `nc28.0`'s `P2A` dust floor of **`240` base units**. Bare `OP_TRUE` (`nonstandard` in `nc28.0`) MUST NOT be used.
- **Namecoin minimum relay fee note:** Namecoin Core `nc28.0` sets default `minrelaytxfee = 0.001 NMC / 1000 vB` (`100,000` base units per 1000 vB — 100× Bitcoin's default). A zero-fee pre-signed `tx_revoke` parent is therefore rejected standalone (`min relay fee not met`) and is relayed as a 1-parent-1-child (`1p1c`) v3 package with a dynamically signed CPFP child spending the `P2A` output and funding the combined package fee (`>= minrelaytxfee` and current mempool feerate), without ever needing the destroyed seal private key.
- A reproducible two-node Namecoin Core `nc28.0` regtest positive control proving standalone parent rejection, `submitpackage` acceptance, P2P propagation before mining, and block confirmation is preserved in `conformance/p2a-regtest/` (production propagation and fee-competition qualification remain tracked under `OQ-006`).

---

## 7. Security Considerations

- **Mempool visibility is observer-local:** Revocation operates at mempool speed at each witnessing verifier; network propagation latency remains a physical limit.
- **Cold emergency fee reserve:** A hot signer compromise MUST NOT allow an attacker to drain fee UTXOs required for emergency name updates or CPFP revocations; emergency fee UTXOs remain in cold custody (`SPEC-03 §2`).
- **History walk DoS protection:** Verifiers MUST enforce a configurable maximum step bound when walking a name's update chain; hitting the bound refuses `NAME_HISTORY_UNAVAILABLE` without closure.

---

## 8. References

- **Normative:** [BIP-112], [BIP-141], [BIP-143], [BIP-174], [BIP-340].
- **Informative:** [BIP-431], [BIP-433], [NC28].
