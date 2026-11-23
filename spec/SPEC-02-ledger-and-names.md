# SPEC-02: Ledger Interface, Namecoin Binding, ScriptPolicy, Merkle Batching, and UTXO Seals

- **Version:** `1.0.0-draft.6`
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

---

## 3. Unified `ScriptPolicy` (On-Chain Ownership and Seal Scripts)

SealLink uses one deterministic **`ScriptPolicy`** primitive covering **name ownership**, **contract termination seals**, **guardianship slots**, **status/roster spines**, and **single-use seals**.

### 3.1 Supported Templates (`SL-LDGR-004`, `decided`)

Every `ScriptPolicy` deterministically compiles to an exact native SegWit v0 trailing `scriptPubKey` (`P2WPKH` 22 bytes or `P2WSH` 34 bytes). Keys in `multisig` and unordered pairs `(a, b)` MUST be strictly sorted in ascending lexicographical hex order (`min(a,b) < max(a,b)`). Relative locktime `<D>` uses minimal Bitcoin Script `CScriptNum` encoding (`1 <= D <= 52560`, BIP-68 block-based relative locktime with bit 22 cleared).

| `kind` / `template` | Compilation to Output `scriptPubKey` | Primary Use |
| --- | --- | --- |
| `{"kind":"key","pk":"<66hex>"}` | `P2WPKH` (22B): `OP_0 PUSH20 HASH160(pk)`. Spent with ECDSA. *(Namecoin `P2WPKH` validates strictly ECDSA, never BIP-340 Schnorr / FROST; any single-key threshold custody MUST use qualified threshold ECDSA.)* | Individual actor name, ordinary revocable grant seal, row coin, stop coin, disposable revoke seal. |
| `{"kind":"multisig","m":k,"pks":[...]}` | `P2WSH` (34B): `OP_0 PUSH32 SHA256(witnessScript)`, where `witnessScript = OP_k <pk_1> ... <pk_n> OP_n OP_CHECKMULTISIG`, `1 <= k <= n <= 15`. | Child name (`2-of-3`), organization name (`3-of-5`), multi-guardian agent name (`2-of-3`), signed via `namepsbt`. |
| `{"kind":"branch","template":"either_of_2","keys":{"a","b"}}` | `P2WSH` (34B): `OP_1 <min(a,b)> <max(a,b)> OP_2 OP_CHECKMULTISIG` | Contract seal (`either_party`); active guardian slot (`guardian OR disposer`); `status_seal`. |
| `{"kind":"branch","template":"both_of_2","keys":{"a","b"}}` | `P2WSH` (34B): `OP_2 <min(a,b)> <max(a,b)> OP_2 OP_CHECKMULTISIG` | Contract seal (`both_together`); on-chain 2-party assent; vacant guardian slot (`disposer AND arbiter`); `roster_seal`; `recovery_seal`. |
| `{"kind":"branch","template":"arbiter_or_both","keys":{"a","b","arbiter"}}` | `P2WSH` (34B): `OP_IF OP_2 <min(a,b)> <max(a,b)> OP_2 OP_CHECKMULTISIG OP_ELSE <arbiter> OP_CHECKSIG OP_ENDIF` | Contract seal (`arbiter` termination branch `0` or mutual termination branch `1`). |
| `{"kind":"branch","template":"single_use_1_of_2","keys":{"issuer","grantee"}}` | `P2WSH` (34B): `OP_IF <issuer> OP_CHECKSIG OP_ELSE <grantee> OP_CHECKSIG OP_ENDIF` (witness selector `0x01` = issuer revoke; empty `""` = grantee use). | Single-use UTXO grant seal (unambiguous branch attribution). |
| `{"kind":"branch","template":"guardian_slot_pending","keys":{"disposer","challenger","guardian"},"delay_blocks":D}` | `P2WSH` (34B): `OP_IF <disposer> OP_CHECKSIG OP_ELSE OP_IF <challenger> OP_CHECKSIG OP_ELSE <D> OP_CHECKSEQUENCEVERIFY OP_DROP <guardian> OP_CHECKSIG OP_ENDIF OP_ENDIF` | Stage 1 pending guardian slot: disposer or challenger MAY veto during delay `D`; after `D` blocks, guardian spends to Stage 2 active `either_of_2(guardian, disposer)` (`SPEC-04 §3.3`), permanently terminating challenger veto. |

> **Namecoin Core `nc28.0` compatibility note:** In `src/script/solver.cpp:146-148`, Namecoin strips the `OP_NAME_*` prefix before evaluating `WITNESS_V0_SCRIPTHASH` (`IsWitnessProgram(true, ...)`), so native `P2WSH` name outputs pass standard relay policy up to 3,600-byte witness scripts and 100 stack items.

### 3.2 Name Output Prefix Grammars and Pre-Spend Verification (`SL-LDGR-005`, `decided`)

1. **Exact Namecoin name script grammars:** A Namecoin name output `scriptPubKey` MUST match one of the three exact minimal-push (`MINIMALDATA`) prefix forms followed immediately by a trailing native SegWit `scriptPubKey` (`P2WPKH` 22 bytes or `P2WSH` 34 bytes; legacy `P2PKH` is NOT supported):

| Operation | Opcode | Exact Prefix Before Trailing `scriptPubKey` |
| --- | :-: | --- |
| `NAME_NEW` | `0x51` (`OP_NAME_NEW`) | `OP_NAME_NEW <20B_hash> OP_2DROP <scriptPubKey>` |
| `NAME_FIRSTUPDATE` | `0x52` (`OP_NAME_FIRSTUPDATE`) | `OP_NAME_FIRSTUPDATE <name> <rand> <value> OP_2DROP OP_2DROP <scriptPubKey>` |
| `NAME_UPDATE` | `0x53` (`OP_NAME_UPDATE`) | `OP_NAME_UPDATE <name> <value> OP_2DROP OP_DROP <scriptPubKey>` |

   Any output violating these exact prefix and cleanup opcodes MUST refuse with `CHAIN_SCRIPT_UNSUPPORTED`.
2. **Pre-spend verification:** Because an unspent `P2WSH` output exposes only `OP_0 PUSH32 SHA256(witnessScript)` on chain, any pin, contract, manifest, or origin naming an output MUST include its complete `ScriptPolicy`. The verifier compiles `ScriptPolicy` to the exact trailing `scriptPubKey` (`22` bytes for `key`, `34` bytes for `multisig` and `branch`) and requires byte-for-byte equality with the trailing `scriptPubKey` extracted from the on-chain output. Mismatch or unknown template MUST refuse with `CHAIN_SCRIPT_UNSUPPORTED` (non-closing; never inferred as a transfer).
3. **No covenant renewal-only branch (`SL-LDGR-006`, `decided`):** Unmodified Namecoin lacks output covenants (`OP_CTV`). Any spending branch in a name's `ScriptPolicy` can technically transfer the name to another script. Deployments MUST NOT add a low-threshold "renewal-only" branch to a name output; renewals MUST use the name's full `ScriptPolicy` threshold.

### 3.3 Author / Writer Verification (`SL-LDGR-007`, `decided`)

Receiving a name output proves neither authorship nor consent. To prove a name value was **authored** by `owner_policy`:
1. The spent previous name input MUST satisfy `owner_policy` (verified via witness script hash and pubkeys for `P2WSH`, or pubkey hash for `P2WPKH`);
2. Every authorizing ECDSA signature in that input's witness MUST end with strict sighash byte **`0x01` (`SIGHASH_ALL`, without `ANYONECANPAY`)**, committing to every output (including the new name value and any `OP_RETURN` break or cancel frame);
3. For a newly registered name whose `OP_NAME_FIRSTUPDATE` was signed by a funding wallet, the pinned `owner_policy` MUST sign one subsequent `OP_NAME_UPDATE` of its own before that value is treated as owner-authored (`NAME_WRITER_UNVERIFIED` otherwise).

---

## 4. Observation, Multi-Node Freshness, and Risk Cutoffs

Every chain-dependent decision executes inside one **consistent observation** (`SL-LDGR-008`, `decided` algorithm / `open` provisional constants `LAG`, `S`, `K` tracked in `OPEN-QUESTIONS.md`):

1. **Snapshot bracket:** Read tip `(hash_0, height_0)` on the reading node before all queries, and `(hash_1, height_1)` after. If `(hash_0, height_0) != (hash_1, height_1)`, discard the observation with `CHAIN_OBSERVATION_VOID` (no closure written, except any validated seal spend already witnessed).
2. **Multi-node health & single-node veto:** Reading node MUST be synced (`!IBD`, `txindex=1`, `best_header - tip <= LAG`, provisional `LAG = 1`; else `CHAIN_UNHEALTHY`). Verifier MUST cross-check against `>= 1` independent healthy comparison node (distinct operator source); if zero healthy comparison nodes are configured or reachable, refuse `CHAIN_UNHEALTHY`. If *any* healthy comparison node reports a different hash at `height_0` or a higher height than `height_0`, refuse `CHAIN_NODE_DISAGREEMENT` (a single disagreeing healthy peer vetoes).
3. **Dual tip-age freshness:** Verifier maintains a durable monotonic UTC clock watermark (clock regression -> `CHAIN_CLOCK_ERROR`) and rejects headers with `header_time - now > S` (provisional `S = 600s`). Verifier durably records `first_sight_time` on first observation of each block hash:
   ```text
   tip_age = max(now - header_time, now - first_sight_time)
   ```
   Risk cutoffs:
   - **Class 1 (money, irreversible effects, custody/guardian transitions, issuance):** `tip_age <= 3600s` (60 min; default if unstated).
   - **Class 2 (other privileged/read-only actions):** `tip_age <= 5400s` (90 min).
   Exceeding cutoff refuses `CHAIN_TIP_STALE`.
4. **Recency & confirmation depth:** Grant `recent_block` `R` MUST lie on the active chain; anchor height `A` MUST satisfy `R < A <= R + K` (provisional `K = 432` blocks; else `CHAIN_RECENCY_INVALID`). Confirmation depth is `H - h + 1`, requiring `>= max(signed_min_depth, operator_floor)` where `signed_min_depth` is `grant.min_depth` (default `1` if omitted) (`CHAIN_DEPTH_INSUFFICIENT`).
5. **Pre-effect recheck:** Immediately before reserving or executing an irreversible effect, the executor MUST re-verify tip freshness, wall-clock window, and live seal status (including mempool).

---

## 5. Witness Profile (`W`), `SLNK` `OP_RETURN` Framing, and Merkle Batching (`0x02`)

### 5.1 Witness Construction Profile (`W`) (`SL-LDGR-009`, `decided`)

- **Every input** of a seal-creation transaction `T` and an anchoring transaction `A` MUST be native SegWit v0 (`P2WPKH` or `P2WSH`) with empty `scriptSig` and strict `SIGHASH_ALL` (`0x01`) on all signatures (`CHAIN_TX_CONSTRUCTION`).
- **Linkage output:** When `A` anchors a grant whose seal was created in `T`, `T` creates a linkage output at `vout = seal_vout + 1` (native SegWit), and `A` MUST spend that linkage output (never spending the seal). Only the linkage output may be unconfirmed when `A` is broadcast; all other funding inputs MUST be confirmed strictly below the spending transaction's block. `T` and `A` MAY confirm in the same block.
- **Legacy profile (`L`):** Reserved solely for future non-SegWit UTXO chains; refused on Namecoin (`CHAIN_TX_CONSTRUCTION`).

### 5.2 Framed `OP_RETURN` Format (`SLNK`) (`SL-LDGR-010`, `decided`)

Every SealLink on-chain commitment uses a single zero-value `OP_RETURN` output per anchoring transaction (`CHAIN_FRAME_INVALID` if missing, duplicate, reserved `0x06`, or malformed):

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

### 5.3 Merkle Batch Anchor Construction (`0x02`) (`SL-LDGR-014`, `decided`)

Action `0x02` (`BATCH_ANCHOR`) commits to a non-empty set of `1 <= N <= 65536` distinct 32-byte item commitments (`item_digest_32B`) in a single `OP_RETURN` frame:

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
| Creation tx confirmed with matching `ScriptPolicy`, AND either (a) a valid spend is witnessed in mempool or confirmed block, OR (b) confirmed output is absent from node's UTXO set. | **`revoked`** | Durably write permanent `closure` entry to fenced journal (`SPEC-06 §6`) BEFORE returning refusal. Reorgs or mempool eviction MUST NOT reopen a closed seal. | `SEAL_SPENT` |
| Creation tx unknown, unconfirmed, script mismatches `ScriptPolicy`, or node read inconclusive. | **`unavailable`** | Refuse WITHOUT writing permanent closure. | `SEAL_UNAVAILABLE` |

### 6.2 Single-Use Attribution (`SL-LDGR-012`, `decided`)

For `single_use_1_of_2` grant seals, a spend has **two distinct branches** and MUST NOT be folded blindly into `SEAL_SPENT`:

| Observed Seal Condition | Single-Use State | Verifier Action | Refusal / Outcome |
| --- | --- | --- | --- |
| Seal unspent (no grantee spend observed). | `awaiting_spend` | Refuse without closure (grantee must spend branch `0` first). | `SEAL_UNAVAILABLE` |
| Spent via branch `1` (`issuer`), OR spent without valid `0x11` frame, OR absent from UTXO with unknown branch. | `revoked` | Write permanent `closure(cause="SEAL_SPENT")` to journal. | `SEAL_SPENT` |
| Spent via branch `0` (`grantee`, `SIGHASH_ALL`) with `OP_RETURN 0x11` committing `content_addr(invocation/1)`, depth `< required_depth` (mempool or shallow block). | `pending_confirm` | Refuse without closure; retryable once depth reaches `required_depth`. | `CHAIN_DEPTH_INSUFFICIENT` |
| Spent via branch `0` with matching `0x11`, confirmed `>= required_depth`, NOT yet in journal `single-use-consumed`. | `ready_once` | Execute at most once; durably write `single-use-consumed` + `closure(cause="SINGLE_USE_CONSUMED")` to journal. | **Admit** (`executed`) |
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
